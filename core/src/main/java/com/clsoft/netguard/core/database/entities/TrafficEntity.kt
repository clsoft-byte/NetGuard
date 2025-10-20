package com.clsoft.netguard.core.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "traffic")
data class TrafficEntity(
    @PrimaryKey val id: String,
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

data class TrafficSummary(
    val totalSent: Long,
    val totalReceived: Long
)
