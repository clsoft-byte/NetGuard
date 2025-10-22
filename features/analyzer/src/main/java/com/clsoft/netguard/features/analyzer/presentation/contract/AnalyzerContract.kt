package com.clsoft.netguard.features.analyzer.presentation.contract

import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk

data class AnalyzerState(
    val isLoading: Boolean = false,
    val appPackage: String = "",
    val destinationIp: String = "",
    val lastResult: TrafficRisk? = null,
    val risks: List<TrafficRisk> = emptyList(),
    val errorMessage: String? = null
)

sealed class AnalyzerEvent {
    data class AppPackageChanged(val value: String) : AnalyzerEvent()
    data class DestinationIpChanged(val value: String) : AnalyzerEvent()
    data object Analyze : AnalyzerEvent()
    data object DismissError : AnalyzerEvent()
}