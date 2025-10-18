package com.clsoft.netguard.features.traffic.monitor.service

import android.net.ConnectivityManager
import android.os.Build
import com.clsoft.netguard.core.utils.Logger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.LinkedHashMap

internal class ConnectionOwnerResolver(
    private val connectivityManager: ConnectivityManager,
    private val packageNameLookup: (Int) -> String?
) {

    private val cache = object : LinkedHashMap<String, String?>(CACHE_CAPACITY, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String?>?): Boolean {
            return size > CACHE_CAPACITY
        }
    }

    fun resolve(packet: ParsedPacket): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        val sourcePort = packet.sourcePort ?: return null
        val destinationPort = packet.destinationPort ?: return null

        val key = buildKey(packet, sourcePort, destinationPort)
        synchronized(cache) {
            if (cache.containsKey(key)) {
                return cache[key]
            }
        }

        val resolved = try {
            val (local, remote) = buildSocketAddresses(packet, sourcePort, destinationPort)
            val uid = connectivityManager.getConnectionOwnerUid(
                packet.protocolNumber,
                local,
                remote
            )
            if (uid <= 0) {
                null
            } else {
                packageNameLookup(uid)
            }
        } catch (se: SecurityException) {
            Logger.e(TAG, "Sin permisos para obtener owner de conexión", se)
            null
        } catch (iae: IllegalArgumentException) {
            Logger.e(TAG, "Parámetros inválidos al consultar owner", iae)
            null
        } catch (t: Throwable) {
            Logger.e(TAG, "Fallo al resolver owner de conexión", t)
            null
        }?.takeUnless { it.isBlank() }

        synchronized(cache) {
            cache[key] = resolved
        }
        return resolved
    }

    private fun buildSocketAddresses(
        packet: ParsedPacket,
        sourcePort: Int,
        destinationPort: Int
    ): Pair<InetSocketAddress, InetSocketAddress> {
        val localAddress: InetSocketAddress
        val remoteAddress: InetSocketAddress
        if (packet.direction == PacketDirection.OUTGOING) {
            localAddress = InetSocketAddress(parseAddress(packet.sourceIp), sourcePort)
            remoteAddress = InetSocketAddress(parseAddress(packet.destinationIp), destinationPort)
        } else {
            localAddress = InetSocketAddress(parseAddress(packet.destinationIp), destinationPort)
            remoteAddress = InetSocketAddress(parseAddress(packet.sourceIp), sourcePort)
        }
        return localAddress to remoteAddress
    }

    private fun parseAddress(address: String): InetAddress = InetAddress.getByName(address)

    private fun buildKey(packet: ParsedPacket, sourcePort: Int, destinationPort: Int): String =
        buildString {
            append(packet.protocolNumber)
            append(':')
            append(packet.sourceIp)
            append(':')
            append(sourcePort)
            append("->")
            append(packet.destinationIp)
            append(':')
            append(destinationPort)
            append('|')
            append(packet.direction.name)
        }

    companion object {
        private const val TAG = "ConnectionOwnerResolver"
        private const val CACHE_CAPACITY = 256
    }
}
