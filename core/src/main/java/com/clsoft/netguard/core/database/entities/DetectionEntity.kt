package com.clsoft.netguard.core.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "detection")
data class DetectionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val appName: String,
    val riskLevel: String,  // "Low", "Medium", "High"
    val riskType: String,   // "Spyware", "Anomalous", etc.
    val timestamp: Long
)