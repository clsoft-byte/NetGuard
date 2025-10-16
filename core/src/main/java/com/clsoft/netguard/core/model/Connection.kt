package com.clsoft.netguard.core.model

data class Connection(
    val id: String,
    val appPackage: String,
    val sourceIp: String,
    val destinationIp: String,
    val protocol: String,
    val port: Int,
    val bytesSent: Long,
    val bytesReceived: Long,
    val timestamp: Long
)