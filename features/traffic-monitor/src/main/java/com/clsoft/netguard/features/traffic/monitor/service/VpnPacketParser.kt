package com.clsoft.netguard.features.traffic.monitor.service

import java.nio.ByteBuffer
import java.nio.ByteOrder
internal object VpnPacketParser {

    private const val IPV4_VERSION = 4
    private const val TCP_PROTOCOL = 6
    private const val UDP_PROTOCOL = 17
    private const val ICMP_PROTOCOL = 1

    fun parsePacket(
        packet: ByteArray,
        length: Int,
        localAddress: String
    ): ParsedPacket? {
        if (length <= 0 || packet.isEmpty()) return null

        val version = (packet[0].toInt() shr 4) and 0xF
        if (version != IPV4_VERSION) {
            return null
        }

        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < 20 || headerLength > length) {
            return null
        }

        val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        if (totalLength <= 0) {
            return null
        }

        val protocolNumber = packet[9].toInt() and 0xFF
        val protocol = when (protocolNumber) {
            TCP_PROTOCOL -> "TCP"
            UDP_PROTOCOL -> "UDP"
            ICMP_PROTOCOL -> "ICMP"
            else -> "IP-$protocolNumber"
        }

        val sourceIp = buildString {
            for (i in 12 until 16) {
                append(packet[i].toInt() and 0xFF)
                if (i < 15) append('.')
            }
        }
        val destinationIp = buildString {
            for (i in 16 until 20) {
                append(packet[i].toInt() and 0xFF)
                if (i < 19) append('.')
            }
        }

        val direction = if (sourceIp == localAddress) {
            PacketDirection.OUTGOING
        } else {
            PacketDirection.INCOMING
        }

        var sourcePort: Int? = null
        var destinationPort: Int? = null
        if (protocolNumber == TCP_PROTOCOL || protocolNumber == UDP_PROTOCOL) {
            if (length >= headerLength + 4) {
                val portsBuffer = ByteBuffer.wrap(packet, headerLength, 4)
                portsBuffer.order(ByteOrder.BIG_ENDIAN)
                sourcePort = portsBuffer.short.toInt() and 0xFFFF
                destinationPort = portsBuffer.short.toInt() and 0xFFFF
            }
        }

        return ParsedPacket(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = protocol,
            protocolNumber = protocolNumber,
            direction = direction,
            totalBytes = totalLength.coerceAtMost(length).toLong(),
            sourcePort = sourcePort,
            destinationPort = destinationPort
        )
    }
}

enum class PacketDirection { OUTGOING, INCOMING }

data class ParsedPacket(
    val sourceIp: String,
    val destinationIp: String,
    val protocol: String,
    val protocolNumber: Int,
    val direction: PacketDirection,
    val totalBytes: Long,
    val sourcePort: Int?,
    val destinationPort: Int?
)