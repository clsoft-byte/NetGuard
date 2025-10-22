package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import com.clsoft.netguard.features.analyzer.domain.repository.AnalyzerRepository
import javax.inject.Inject


class AnalyzeTrafficUseCase @Inject constructor(
    private val repository: AnalyzerRepository
) {
    suspend operator fun invoke(appPackage: String, destinationIp: String): TrafficRisk {
        return repository.analyze(appPackage, destinationIp)
    }
}