package com.clsoft.netguard.engine.detector.core

import java.net.InetAddress
import kotlin.math.ln

object FeatureExtractor {

    fun fromRaw(
        bytesUp: Long,
        bytesDown: Long,
        protocol: String,
        destIp: String,
        nowMillis: Long
    ): InputFeatures {
        val isTcp = if (protocol.equals("TCP", ignoreCase = true)) 1 else 0
        val hour = ((nowMillis / (1000*60*60)) % 24).toInt()
        val entropy = destEntropy(destIp)
        return InputFeatures(bytesUp, bytesDown, isTcp, hour, entropy)
    }

    // Heurística barata de “entropía” (conteo de octetos únicos de la IP /4)
    private fun destEntropy(ip: String): Float = try {
        val bytes = InetAddress.getByName(ip).address
        val unique = bytes.toSet().size
        // normaliza 1..4 → ~0.25..1.0
        (unique / 4.0f).coerceIn(0f, 1f)
    } catch (_: Exception) {
        0.5f
    }
}