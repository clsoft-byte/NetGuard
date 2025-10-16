package com.clsoft.netguard.features.dashboard.di

import com.clsoft.netguard.features.dashboard.data.repository.DashboardRepositoryImpl
import com.clsoft.netguard.features.dashboard.domain.repository.DashboardRepository
import com.clsoft.netguard.framework.vpn.data.FirewallRepositoryImpl
import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
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
    abstract fun bindFirewallRepository(impl: FirewallRepositoryImpl): FirewallRepository

    @Binds
    @Singleton
    abstract fun bindDashboardRepository(impl: DashboardRepositoryImpl): DashboardRepository
}