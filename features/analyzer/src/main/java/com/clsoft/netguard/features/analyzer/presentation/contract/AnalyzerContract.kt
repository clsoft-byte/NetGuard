package com.clsoft.netguard.features.analyzer.presentation.contract

import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk

data class AnalyzerState(
    val risks: List<TrafficRisk> = emptyList()
)

sealed class AnalyzerEvent {
    data class Analyze(val appPackage: String, val destinationIp: String) : AnalyzerEvent()
}