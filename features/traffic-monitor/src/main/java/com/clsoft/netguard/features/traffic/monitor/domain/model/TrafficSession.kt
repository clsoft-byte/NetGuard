package com.clsoft.netguard.features.traffic.monitor.domain.model

data class TrafficSession(
    val id: String,
    val appPackage: String,
    val sourceIp: String,
    val destinationIp: String,
    val protocol: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val timestamp: Long,
    val blocked: Boolean = false,
    val riskScore: Float = 0f,
    val riskLabel: String? = null
)

fun TrafficSession.toTraffic(): Traffic = Traffic(
    id = id,
    appPackage = appPackage,
    sourceIp = sourceIp,
    destinationIp = destinationIp,
    protocol = protocol,
    bytesSent = bytesSent,
    bytesReceived = bytesReceived,
    blocked = blocked,
    riskScore = riskScore,
    riskLabel = riskLabel,
    timestamp = timestamp
)