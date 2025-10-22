package com.clsoft.netguard.features.analyzer.di

import com.clsoft.netguard.core.database.dao.AnalyzerDao
import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.analyzer.data.repository.AnalyzerRepositoryImpl
import com.clsoft.netguard.features.analyzer.domain.repository.AnalyzerRepository
import com.clsoft.netguard.features.analyzer.domain.usecase.ClassifyRiskUseCase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AnalyzerModule {

    @Provides
    @Singleton
    fun provideAnalyzerRepository(
        trafficDao: TrafficDao,
        analyzerDao: AnalyzerDao,
        classifyRiskUseCase: ClassifyRiskUseCase
    ): AnalyzerRepository =
        AnalyzerRepositoryImpl(trafficDao, analyzerDao, classifyRiskUseCase)
}