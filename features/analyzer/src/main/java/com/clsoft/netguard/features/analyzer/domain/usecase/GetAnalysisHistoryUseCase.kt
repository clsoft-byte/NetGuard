package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.features.analyzer.domain.repository.AnalyzerRepository
import javax.inject.Inject

class GetAnalysisHistoryUseCase @Inject constructor(
    private val repository: AnalyzerRepository
) {
    operator fun invoke() = repository.getHistory()
}