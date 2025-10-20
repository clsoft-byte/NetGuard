package com.clsoft.netguard.features.traffic.monitor.service

import java.nio.ByteBuffer
import java.nio.ByteOrder
internal object VpnPacketParser {


    private const val IPV4_VERSION = 4
    private const val IPV6_VERSION = 6
    private const val TCP_PROTOCOL = 6
    private const val UDP_PROTOCOL = 17
    private const val ICMP_PROTOCOL = 1

    fun parsePacket(
        packet: ByteArray,
        length: Int,
        localV4: String?,         // e.g. "10.0.0.2"
        localV6: String?          // e.g. "fd00:1:fd00::2"
    ): ParsedPacket? {
        if (length <= 0 || packet.isEmpty()) return null

        val version = (packet[0].toInt() shr 4) and 0xF
        return when (version) {
            IPV4_VERSION -> parseIPv4(packet, length, localV4)
            IPV6_VERSION -> parseIPv6(packet, length, localV6)
            else -> null
        }
    }

    private fun parseIPv4(packet: ByteArray, length: Int, localV4: String?): ParsedPacket? {
        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < 20 || headerLength > length) return null

        val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        if (totalLength <= 0) return null

        val protocolNumber = packet[9].toInt() and 0xFF
        val protocol = when (protocolNumber) {
            TCP_PROTOCOL -> "TCP"
            UDP_PROTOCOL -> "UDP"
            ICMP_PROTOCOL -> "ICMP"
            else -> "IP-$protocolNumber"
        }

        val sourceIp = buildString {
            for (i in 12 until 16) { append(packet[i].toInt() and 0xFF); if (i < 15) append('.') }
        }
        val destinationIp = buildString {
            for (i in 16 until 20) { append(packet[i].toInt() and 0xFF); if (i < 19) append('.') }
        }

        val direction = when {
            localV4 != null && sourceIp == localV4 -> PacketDirection.OUTGOING
            localV4 != null && destinationIp == localV4 -> PacketDirection.INCOMING
            else -> PacketDirection.OUTGOING
        }

        var srcPort = -1
        var dstPort = -1
        if (protocolNumber == TCP_PROTOCOL || protocolNumber == UDP_PROTOCOL) {
            if (length >= headerLength + 4) {
                val bb = java.nio.ByteBuffer.wrap(packet, headerLength, 4).order(java.nio.ByteOrder.BIG_ENDIAN)
                srcPort = bb.short.toInt() and 0xFFFF
                dstPort = bb.short.toInt() and 0xFFFF
            }
        }

        return ParsedPacket(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = protocol,
            protocolNumber = protocolNumber,
            direction = direction,
            totalBytes = totalLength.coerceAtMost(length).toLong(),
            sourcePort = srcPort,
            destinationPort = dstPort
        )
    }

    private fun parseIPv6(packet: ByteArray, length: Int, localV6: String?): ParsedPacket? {
        if (length < 40) return null // IPv6 fixed header
        val protocolNumber = packet[6].toInt() and 0xFF // Next Header (simplificado: sin recorrer extensiones)
        val protocol = when (protocolNumber) {
            TCP_PROTOCOL -> "TCP"
            UDP_PROTOCOL -> "UDP"
            else -> "IP6-$protocolNumber"
        }

        fun inet6At(offset: Int): String {
            val b = packet.copyOfRange(offset, offset + 16)
            val bb = java.nio.ByteBuffer.wrap(b)
            val sb = StringBuilder()
            for (i in 0 until 16 step 2) {
                val seg = ((bb[i].toInt() and 0xFF) shl 8) or (bb[i + 1].toInt() and 0xFF)
                sb.append(Integer.toHexString(seg))
                if (i < 14) sb.append(':')
            }
            // Nota: abreviado :: opcional; Inet6Address podría formatearlo más bonito si lo prefieres.
            return java.net.InetAddress.getByAddress(b).hostAddress
        }

        val sourceIp = inet6At(8)
        val destinationIp = inet6At(24)

        val direction = when {
            localV6 != null && sourceIp == localV6 -> PacketDirection.OUTGOING
            localV6 != null && destinationIp == localV6 -> PacketDirection.INCOMING
            else -> PacketDirection.OUTGOING
        }

        var headerLen = 40 // sin extensiones
        var srcPort = -1
        var dstPort = -1
        if ((protocolNumber == TCP_PROTOCOL || protocolNumber == UDP_PROTOCOL) && length >= headerLen + 4) {
            val bb = java.nio.ByteBuffer.wrap(packet, headerLen, 4).order(java.nio.ByteOrder.BIG_ENDIAN)
            srcPort = bb.short.toInt() and 0xFFFF
            dstPort = bb.short.toInt() and 0xFFFF
        }

        return ParsedPacket(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = protocol,
            protocolNumber = protocolNumber,
            direction = direction,
            totalBytes = length.toLong(), // IPv6: no hay totalLength en header fijo
            sourcePort = srcPort,
            destinationPort = dstPort
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
    val sourcePort: Int,
    val destinationPort: Int
)