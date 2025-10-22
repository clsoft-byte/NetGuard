package com.clsoft.netguard.features.analyzer.domain.model

data class TrafficRisk(
    val id: String,
    val appPackage: String,
    val destinationIp: String,
    val riskLevel: RiskLevel,
    val riskScore: Float,
    val description: String,
    val timestamp: Long,
    val bytesSent: Long,
    val bytesReceived: Long,
    val protocol: String,
    val destinationPort: Int
)