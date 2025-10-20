package com.clsoft.netguard.features.traffic.monitor.domain.model

data class Traffic(
    val id: String,
    val appPackage: String,
    val sourceIp: String,
    val destinationIp: String,
    val sourcePort: Int,
    val destinationPort: Int,
    val protocol: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val blocked: Boolean = false,
    val riskScore: Float = 0f,
    val riskLabel: String? = null,
    val timestamp: Long
)