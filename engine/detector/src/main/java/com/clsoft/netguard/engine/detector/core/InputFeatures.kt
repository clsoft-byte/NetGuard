package com.clsoft.netguard.engine.detector.core


data class InputFeatures(
    val bytesUp: Long,
    val bytesDown: Long,
    val isTcp: Int,            // 1 TCP, 0 UDP
    val hourOfDay: Int,        // 0..23
    val destEntropy: Float     // entropía del destino (heurística simple)
) {
    fun asFloatArray(): FloatArray = floatArrayOf(
        bytesUp.coerceAtLeast(0).toFloat(),
        bytesDown.coerceAtLeast(0).toFloat(),
        isTcp.toFloat(),
        hourOfDay.toFloat(),
        destEntropy
    )
}