package com.clsoft.netguard.features.traffic.monitor.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.traffic.monitor.domain.usecase.GetTrafficUseCase
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorEvent
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorState
import com.clsoft.netguard.features.traffic.monitor.service.TrafficSessionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class TrafficMonitorViewModel @Inject constructor(
    private val getTrafficUseCase: GetTrafficUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(TrafficMonitorState())
    val state: StateFlow<TrafficMonitorState> = _state

    init {
        observeSessions()
    }

    fun onEvent(event: TrafficMonitorEvent) {
        when (event) {
            is TrafficMonitorEvent.onEditTrafficSession -> {

            }
        }
    }

    fun observeSessions() {
        viewModelScope.launch {
            getTrafficUseCase().collect { traffic ->
                _state.value = _state.value.copy(
                    sessions = traffic
                )
            }
        }
    }
}