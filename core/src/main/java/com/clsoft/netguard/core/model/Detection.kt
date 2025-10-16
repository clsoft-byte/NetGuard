package com.clsoft.netguard.core.model

data class Detection(
    val id: String,
    val appPackage: String,
    val riskLevel: RiskLevel,
    val description: String,
    val detectedAt: Long
)

enum class RiskLevel { LOW, MEDIUM, HIGH }