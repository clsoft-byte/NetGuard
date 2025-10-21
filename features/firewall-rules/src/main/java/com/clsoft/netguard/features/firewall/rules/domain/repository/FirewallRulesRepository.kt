package com.clsoft.netguard.features.firewall.rules.domain.repository

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule
import kotlinx.coroutines.flow.Flow

interface FirewallRulesRepository {
    fun getRules(): Flow<List<FirewallRule>>
    suspend fun addRule(appPackage: String, appName: String)
    suspend fun removeRule(ruleId: String)
    suspend fun toggleRule(ruleId: String)
}
