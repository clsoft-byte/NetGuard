package com.clsoft.netguard.features.traffic.monitor.service


import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession
import java.util.LinkedHashMap
import java.util.UUID

internal class TrafficSessionAggregator(
    private val flushWindowMillis: Long = DEFAULT_FLUSH_WINDOW,
    private val minBytesBeforeFlush: Long = DEFAULT_MIN_BYTES,
    private val riskEvaluator: NativeRiskEvaluator = NativeRiskEvaluator
) {

    private val sessions = LinkedHashMap<String, MutableAggregate>()

    suspend fun register(
        packet: ParsedPacket,
        rawPacket: ByteArray,
        resolvedPackage: String?,
        emit: suspend (TrafficSession) -> Unit
    ) {
        val now = System.currentTimeMillis()
        val key = buildKey(packet)
        val aggregate = sessions.getOrPut(key) {
            MutableAggregate(
                id = UUID.randomUUID().toString(),
                sourceIp = packet.sourceIp,
                destinationIp = packet.destinationIp,
                sourcePort = packet.sourcePort,
                destinationPort = packet.destinationPort,
                protocol = packet.protocol,
                firstSeen = now,
                appPackage = resolvedPackage ?: UNKNOWN_APP
            )
        }

        aggregate.lastUpdated = now
        if (packet.direction == PacketDirection.OUTGOING) {
            aggregate.bytesSent += packet.totalBytes
        } else {
            aggregate.bytesReceived += packet.totalBytes
        }
        resolvedPackage?.let { aggregate.appPackage = it }
        aggregate.packets += rawPacket

        if (aggregate.shouldFlush(now, flushWindowMillis, minBytesBeforeFlush)) {
            val summary = riskEvaluator.evaluate(aggregate.normalizedPackage(), aggregate.packets)
            emit(aggregate.toTrafficSession(summary))
            sessions.remove(key)
        }
    }

    suspend fun flushAll(emit: suspend (TrafficSession) -> Unit) {
        val iterator = sessions.values.iterator()
        while (iterator.hasNext()) {
            val aggregate = iterator.next()
            val summary = riskEvaluator.evaluate(aggregate.normalizedPackage(), aggregate.packets)
            emit(aggregate.toTrafficSession(summary))
            iterator.remove()
        }
    }

    private fun buildKey(packet: ParsedPacket): String = buildString {
        append(packet.sourceIp)
        append(':')
        append(packet.sourcePort ?: -1)
        append("->")
        append(packet.destinationIp)
        append(':')
        append(packet.destinationPort ?: -1)
        append('|')
        append(packet.protocol)
        append('|')
        append(packet.direction.name)
    }

    private data class MutableAggregate(
        val id: String,
        val sourceIp: String,
        val destinationIp: String,
        val sourcePort: Int,
        val destinationPort: Int,
        val protocol: String,
        val firstSeen: Long,
        var lastUpdated: Long = firstSeen,
        var bytesSent: Long = 0,
        var bytesReceived: Long = 0,
        var appPackage: String = UNKNOWN_APP,
        val packets: MutableList<ByteArray> = mutableListOf()
    ) {
        fun shouldFlush(now: Long, window: Long, minBytes: Long): Boolean {
            val totalBytes = bytesSent + bytesReceived
            return totalBytes >= minBytes || (now - firstSeen) >= window
        }

        fun toTrafficSession(risk: NativeRiskEvaluator.RiskSummary): TrafficSession  {
            val (label, score) = if (risk.label.isNullOrBlank() || risk.score <= 0f) {
                when (destinationPort) {
                    22, 23, 445, 3389 -> "High" to 0.90f
                    80, 443           -> "Medium" to 0.50f
                    else              -> "Low" to 0.20f
                }
            } else {
                risk.label to risk.score
            }

            return TrafficSession(
                id = id,
                appPackage = appPackage,
                sourceIp = sourceIp,
                destinationIp = destinationIp,
                destinationPort = destinationPort,
                sourcePort = sourcePort,
                protocol = protocol,
                bytesSent = bytesSent,
                bytesReceived = bytesReceived,
                timestamp = lastUpdated,
                blocked = risk.blocked,
                riskScore = score,
                riskLabel = label
            )
        }
        fun normalizedPackage(): String? = appPackage.takeIf { it.isNotBlank() && it != UNKNOWN_APP }
    }

    companion object {
        private const val DEFAULT_FLUSH_WINDOW = 600L
        private const val DEFAULT_MIN_BYTES = 64L
        private const val UNKNOWN_APP = "unknown"
    }
}