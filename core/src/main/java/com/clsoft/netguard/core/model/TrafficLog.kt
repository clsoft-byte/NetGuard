package com.clsoft.netguard.core.model

data class TrafficLog(
    val id: String,
    val appPackage: String,
    val totalBytesSent: Long,
    val totalBytesReceived: Long,
    val date: Long
)