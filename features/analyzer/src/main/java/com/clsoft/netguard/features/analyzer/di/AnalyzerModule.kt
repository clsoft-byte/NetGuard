package com.clsoft.netguard.features.analyzer.di

import com.clsoft.netguard.features.analyzer.data.repository.AnalyzerRepositoryImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AnalyzerModule {

    @Provides @Singleton
    fun provideAnalyzerRepository() = AnalyzerRepositoryImpl()
}