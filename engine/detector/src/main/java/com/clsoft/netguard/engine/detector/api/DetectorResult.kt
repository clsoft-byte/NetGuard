package com.clsoft.netguard.engine.detector.api

data class DetectorResult(
    val score: Float,          // 0..1
    val label: RiskLabel
)

enum class RiskLabel { LOW, MEDIUM, HIGH }