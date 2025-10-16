package com.clsoft.netguard.features.traffic.monitor.di

import com.clsoft.netguard.features.traffic.monitor.data.repository.TrafficRepositoryImpl
import com.clsoft.netguard.features.traffic.monitor.domain.repository.TrafficRepository
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    @Binds
    @Singleton
    abstract fun bindTrafficRepository(impl: TrafficRepositoryImpl): TrafficRepository
}