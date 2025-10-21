package com.clsoft.netguard.features.firewall.rules.di

import com.clsoft.netguard.features.firewall.rules.data.repository.FirewallAppsRepositoryImpl
import com.clsoft.netguard.features.firewall.rules.data.repository.FirewallRulesRepositoryImpl
import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallAppsRepository
import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class FirewallRulesModule {

    @Binds
    @Singleton
    abstract fun bindFirewallRulesRepository(
        impl: FirewallRulesRepositoryImpl
    ): FirewallRulesRepository

    @Binds
    @Singleton
    abstract fun bindFirewallAppsRepository(
        impl: FirewallAppsRepositoryImpl
    ): FirewallAppsRepository
}
