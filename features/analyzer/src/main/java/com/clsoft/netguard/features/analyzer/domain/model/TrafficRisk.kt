package com.clsoft.netguard.features.analyzer.domain.model

data class TrafficRisk(
    val id: String,
    val appPackage: String,
    val destinationIp: String,
    val riskLevel: RiskLevel,
    val description: String,
    val timestamp: Long
)