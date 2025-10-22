package com.clsoft.netguard.core.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "analysis_result")
data class AnalysisResultEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val appPackage: String,
    val destinationIp: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val protocol: String,
    val destinationPort: Int,
    val riskScore: Float,
    val riskLevel: String,
    val description: String,
    val timestamp: Long
)
