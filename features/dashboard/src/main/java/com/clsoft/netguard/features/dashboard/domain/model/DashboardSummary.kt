package com.clsoft.netguard.features.dashboard.domain.model


data class DashboardSummary(
    val firewallEnabled: Boolean,
    val totalSent: Long = 0,
    val totalReceived: Long = 0,
    val detections: List<Detection>,
    val lastSession: TrafficSession?
)

data class Detection(
    val appName: String,
    val riskLevel: String, // Low, Medium, High
    val riskType: String,  // Spyware, Anomalous, etc.
    val timestamp: Long
)

data class TrafficSession(
    val id: String,
    val appPackage: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val timestamp: Long
)