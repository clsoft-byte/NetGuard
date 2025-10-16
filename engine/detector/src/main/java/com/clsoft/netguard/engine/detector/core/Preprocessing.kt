package com.clsoft.netguard.engine.detector.core

object Preprocessing {
    // Normalización sencilla para que el modelo no “explote” con MB/GB
    fun normalize(input: FloatArray): FloatArray {
        val up = input[0] / (1024f * 1024f)     // MB
        val down = input[1] / (1024f * 1024f)   // MB
        return floatArrayOf(
            up.coerceAtMost(1024f),             // clamp 1GB
            down.coerceAtMost(1024f),
            input[2],                           // isTcp
            input[3] / 23f,                     // hour 0..1
            input[4].coerceIn(0f, 1f)           // entropy 0..1
        )
    }
}