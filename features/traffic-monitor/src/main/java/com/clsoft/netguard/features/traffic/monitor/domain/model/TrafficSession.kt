package com.clsoft.netguard.features.traffic.monitor.domain.model

data class TrafficSession(
    val id: String,
    val appPackage: String,
    val sourceIp: String,
    val destinationIp: String,
    val protocol: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val timestamp: Long
)