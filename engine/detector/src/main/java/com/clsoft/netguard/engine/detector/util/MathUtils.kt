package com.clsoft.netguard.engine.detector.util

object MathUtils {
    fun clamp01(v: Float) = v.coerceIn(0f, 1f)
}