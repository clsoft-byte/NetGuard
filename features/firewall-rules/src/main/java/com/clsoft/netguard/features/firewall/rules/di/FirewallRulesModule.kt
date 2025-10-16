package com.clsoft.netguard.features.firewall.rules.di

import com.clsoft.netguard.features.firewall.rules.data.repository.FirewallRulesRepositoryImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object FirewallRulesModule {

    @Provides @Singleton
    fun provideFirewallRulesRepository() = FirewallRulesRepositoryImpl()
}