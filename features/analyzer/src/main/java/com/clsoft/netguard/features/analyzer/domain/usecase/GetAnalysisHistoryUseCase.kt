package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.features.analyzer.data.repository.AnalyzerRepositoryImpl
import javax.inject.Inject

class GetAnalysisHistoryUseCase @Inject constructor(
    private val repository: AnalyzerRepositoryImpl
) {
    operator fun invoke() = repository.getHistory()
}