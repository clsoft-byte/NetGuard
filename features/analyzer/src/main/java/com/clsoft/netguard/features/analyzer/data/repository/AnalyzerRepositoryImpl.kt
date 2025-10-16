package com.clsoft.netguard.features.analyzer.data.repository

import com.clsoft.netguard.features.analyzer.domain.model.RiskLevel
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import com.clsoft.netguard.features.analyzer.domain.repository.AnalyzerRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

class AnalyzerRepositoryImpl: AnalyzerRepository {
    private val riskHistory = mutableListOf<TrafficRisk>()
    private val _risksFlow = MutableStateFlow<List<TrafficRisk>>(emptyList())
    val risksFlow: Flow<List<TrafficRisk>> = _risksFlow.asStateFlow()

    override fun analyze(appPackage: String, destinationIp: String): TrafficRisk {
        val risk = simulateRisk(appPackage, destinationIp)
        riskHistory.add(risk)
        _risksFlow.value = riskHistory.toList()
        return risk
    }

    override fun getHistory(): Flow<List<TrafficRisk>> = risksFlow

    private fun simulateRisk(app: String, ip: String): TrafficRisk {
        val random = listOf(RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH).random()
        val desc = when (random) {
            RiskLevel.LOW -> "Tráfico normal o cifrado"
            RiskLevel.MEDIUM -> "Comunicaciones no cifradas o frecuentes"
            RiskLevel.HIGH -> "Posible app espía o servidor sospechoso"
        }

        return TrafficRisk(
            id = UUID.randomUUID().toString(),
            appPackage = app,
            destinationIp = ip,
            riskLevel = random,
            description = desc,
            timestamp = System.currentTimeMillis()
        )
    }
}