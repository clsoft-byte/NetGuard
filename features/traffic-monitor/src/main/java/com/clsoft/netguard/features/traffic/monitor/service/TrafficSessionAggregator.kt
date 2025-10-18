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
            val summary = riskEvaluator.evaluate(aggregate.packets)
            emit(aggregate.toTrafficSession(summary))
            sessions.remove(key)
        }
    }

    suspend fun flushAll(emit: suspend (TrafficSession) -> Unit) {
        val iterator = sessions.values.iterator()
        while (iterator.hasNext()) {
            val aggregate = iterator.next()
            val summary = riskEvaluator.evaluate(aggregate.packets)
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

        fun toTrafficSession(risk: NativeRiskEvaluator.RiskSummary): TrafficSession = TrafficSession(
            id = id,
            appPackage = appPackage,
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = protocol,
            bytesSent = bytesSent,
            bytesReceived = bytesReceived,
            timestamp = lastUpdated,
            blocked = risk.blocked,
            riskScore = risk.score,
            riskLabel = risk.label
        )
    }

    companion object {
        private const val DEFAULT_FLUSH_WINDOW = 1_500L
        private const val DEFAULT_MIN_BYTES = 1_024L
        private const val UNKNOWN_APP = "unknown"
    }
}