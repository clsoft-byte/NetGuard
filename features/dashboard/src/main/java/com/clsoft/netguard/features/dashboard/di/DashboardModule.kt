package com.clsoft.netguard.features.dashboard.di

import com.clsoft.netguard.core.database.dao.DetectionDao
import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.dashboard.data.repository.DashboardRepositoryImpl
import com.clsoft.netguard.features.dashboard.domain.usecase.GetDashboardDataUseCase
import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DashboardModule {

    @Provides
    @Singleton
    fun provideDashboardRepository(
        trafficDao: TrafficDao,
        detectionDao: DetectionDao,
        firewallRepository: FirewallRepository
    ): DashboardRepositoryImpl = DashboardRepositoryImpl(
        trafficDao = trafficDao,
        detectionDao = detectionDao,
        firewallRepository = firewallRepository
    )

}