package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.features.analyzer.data.repository.AnalyzerRepositoryImpl
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import javax.inject.Inject


class AnalyzeTrafficUseCase @Inject constructor(
    private val repository: AnalyzerRepositoryImpl
) {
    operator fun invoke(appPackage: String, destinationIp: String): TrafficRisk {
        return repository.analyze(appPackage, destinationIp)
    }
}