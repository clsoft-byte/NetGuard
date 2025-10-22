package com.clsoft.netguard.features.analyzer.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.analyzer.data.repository.MissingTrafficDataException
import com.clsoft.netguard.features.analyzer.domain.usecase.AnalyzeTrafficUseCase
import com.clsoft.netguard.features.analyzer.domain.usecase.GetAnalysisHistoryUseCase
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerEvent
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
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
            is AnalyzerEvent.AppPackageChanged -> _state.update {
                it.copy(appPackage = event.value, errorMessage = null)
            }
            is AnalyzerEvent.DestinationIpChanged -> _state.update {
                it.copy(destinationIp = event.value, errorMessage = null)
            }
            AnalyzerEvent.Analyze -> analyze()
            AnalyzerEvent.DismissError -> _state.update { it.copy(errorMessage = null) }
        }
    }

    private fun analyze() {
        val current = _state.value
        val app = current.appPackage.trim()
        val ip = current.destinationIp.trim()

        if (app.isEmpty() || ip.isEmpty()) {
            _state.update {
                it.copy(errorMessage = "Completa el paquete de la app y la IP destino para continuar")
            }
            return
        }

        viewModelScope.launch {
            _state.update { it.copy(isLoading = true, errorMessage = null) }
            try {
                val result = analyzeUseCase(app, ip)
                _state.update {
                    it.copy(
                        isLoading = false,
                        lastResult = result,
                        appPackage = "",
                        destinationIp = ""
                    )
                }
            } catch (missing: MissingTrafficDataException) {
                _state.update { it.copy(isLoading = false, errorMessage = missing.message) }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = "No se pudo completar el análisis. Intenta nuevamente."
                    )
                }
            }
        }
    }

    private fun observeHistory() {
        viewModelScope.launch {
            getHistory().collectLatest { risks ->
                _state.update { it.copy(risks = risks) }
            }
        }
    }
}