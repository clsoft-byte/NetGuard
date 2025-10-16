package com.clsoft.netguard.features.traffic.monitor.presentation.contract

import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession

data class TrafficMonitorState(
    val isMonitoring: Boolean = false,
    val sessions: List<TrafficSession> = emptyList()
)

sealed class TrafficMonitorEvent {
    object Start : TrafficMonitorEvent()
    object Stop : TrafficMonitorEvent()
}