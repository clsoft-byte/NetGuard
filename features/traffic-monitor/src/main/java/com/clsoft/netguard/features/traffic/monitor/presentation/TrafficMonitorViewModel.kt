package com.clsoft.netguard.features.traffic.monitor.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.traffic.monitor.domain.usecase.StartMonitoringUseCase
import com.clsoft.netguard.features.traffic.monitor.domain.usecase.StopMonitoringUseCase
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorEvent
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorState
import com.clsoft.netguard.features.traffic.monitor.service.TrafficSessionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class TrafficMonitorViewModel @Inject constructor(
    private val startMonitoring: StartMonitoringUseCase,
    private val stopMonitoring: StopMonitoringUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(TrafficMonitorState())
    val state: StateFlow<TrafficMonitorState> = _state

    fun onEvent(event: TrafficMonitorEvent, context: Context) {
        when (event) {
            TrafficMonitorEvent.Start -> start(context)
            TrafficMonitorEvent.Stop -> stop(context)
        }
    }

    private fun start(context: Context) {
        viewModelScope.launch {
            startMonitoring(context)
            _state.value = _state.value.copy(isMonitoring = true)
        }
    }

    private fun stop(context: Context) {
        viewModelScope.launch {
            stopMonitoring(context)
            _state.value = _state.value.copy(isMonitoring = false)
        }
    }

    fun observeSessions() {
        viewModelScope.launch {
            TrafficSessionManager.sessionsFlow.collect { session ->
                _state.value = _state.value.copy(
                    sessions = _state.value.sessions + session
                )
            }
        }
    }
}