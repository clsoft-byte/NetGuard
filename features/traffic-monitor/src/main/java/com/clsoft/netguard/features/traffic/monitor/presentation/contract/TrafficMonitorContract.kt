package com.clsoft.netguard.features.traffic.monitor.presentation.contract

import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic

data class TrafficMonitorState(
    val isMonitoring: Boolean = false,
    val sessions: List<Traffic> = emptyList()
)

sealed class TrafficMonitorEvent {
    data class onEditTrafficSession(val row: Traffic) : TrafficMonitorEvent()
}