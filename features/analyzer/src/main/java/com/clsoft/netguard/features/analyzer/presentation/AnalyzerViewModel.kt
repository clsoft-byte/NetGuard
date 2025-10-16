package com.clsoft.netguard.features.analyzer.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.analyzer.domain.usecase.AnalyzeTrafficUseCase
import com.clsoft.netguard.features.analyzer.domain.usecase.GetAnalysisHistoryUseCase
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerEvent
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AnalyzerViewModel @Inject constructor(
    private val analyzeUseCase: AnalyzeTrafficUseCase,
    private val getHistory: GetAnalysisHistoryUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(AnalyzerState())
    val state: StateFlow<AnalyzerState> = _state

    init {
        observeHistory()
    }

    fun onEvent(event: AnalyzerEvent) {
        when (event) {
            is AnalyzerEvent.Analyze -> analyze(event.appPackage, event.destinationIp)
        }
    }

    private fun analyze(app: String, ip: String) {
        viewModelScope.launch {
            analyzeUseCase(app, ip)
        }
    }

    private fun observeHistory() {
        viewModelScope.launch {
            getHistory().collectLatest { risks ->
                _state.value = AnalyzerState(risks)
            }
        }
    }
}