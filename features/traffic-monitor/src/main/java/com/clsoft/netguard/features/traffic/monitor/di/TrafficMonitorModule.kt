package com.clsoft.netguard.features.traffic.monitor.di

import com.clsoft.netguard.core.database.NetGuardDatabase
import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.traffic.monitor.domain.usecase.StartMonitoringUseCase
import com.clsoft.netguard.features.traffic.monitor.domain.usecase.StopMonitoringUseCase
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object TrafficMonitorModule {

    @Provides
    @Singleton
    fun provideStartMonitoringUseCase() = StartMonitoringUseCase()

    @Provides
    @Singleton
    fun provideStopMonitoringUseCase() = StopMonitoringUseCase()
}