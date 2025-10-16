package com.clsoft.netguard.framework.vpn.domain.repository

import kotlinx.coroutines.flow.Flow

interface FirewallRepository {
    suspend fun setFirewallEnabled(enabled: Boolean)
    fun isFirewallEnabled(): Flow<Boolean>
}