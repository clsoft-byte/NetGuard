package com.clsoft.netguard.features.dashboard.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.dashboard.domain.usecase.GetDashboardDataUseCase
import com.clsoft.netguard.features.dashboard.presentation.contract.DashboardEvent
import com.clsoft.netguard.features.dashboard.presentation.contract.DashboardState
import com.clsoft.netguard.features.traffic.monitor.service.NetGuardVpnService
import com.clsoft.netguard.framework.vpn.domain.usecase.SetFirewallEnabledUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val getDashboardDataUseCase: GetDashboardDataUseCase,
    private val setFirewallEnabledUseCase: SetFirewallEnabledUseCase,
    @ApplicationContext private val app: Context
) : ViewModel() {

    private val _state = MutableStateFlow(DashboardState())
    val state: StateFlow<DashboardState> = _state

    init {
        loadData()
    }

    fun onEvent(event: DashboardEvent) {
        when (event) {
            DashboardEvent.Refresh -> loadData()
            is DashboardEvent.ToggleFirewall -> onToggleFirewall(event.enabled)
        }
    }

    private fun loadData() {
        viewModelScope.launch {
            getDashboardDataUseCase()
                .catch { e -> _state.value = DashboardState(error = e.message) }
                .collect { summary ->
                    _state.value = DashboardState(isLoading = false, data = summary)
                    if (summary.firewallEnabled) NetGuardVpnService.start(app)
                }
        }
    }

    private fun onToggleFirewall(enabled: Boolean) {
        viewModelScope.launch {
            _state.value = _state.value.copy(data = _state.value.data.copy(firewallEnabled = enabled))
            setFirewallEnabledUseCase(enabled)
            if (enabled) NetGuardVpnService.start(app) else NetGuardVpnService.stop(app)
        }
    }
}