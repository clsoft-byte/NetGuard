package com.clsoft.netguard.features.dashboard.presentation.contract

import com.clsoft.netguard.features.dashboard.domain.model.DashboardSummary


data class DashboardState(
    val isLoading: Boolean = true,
    val data: DashboardSummary = DashboardSummary(firewallEnabled = false, detections = emptyList(), lastSession = null, totalReceived = 0, totalSent = 0),
    val error: String? = null
)

sealed class DashboardEvent {
    object Refresh : DashboardEvent()
    data class ToggleFirewall(val enabled: Boolean) : DashboardEvent()
}