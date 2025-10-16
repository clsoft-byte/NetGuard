package com.clsoft.netguard.features.firewall.rules.domain.repository

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule
import kotlinx.coroutines.flow.Flow

interface FirewallRulesRepository {
    fun getRules(): Flow<List<FirewallRule>>
    fun addRule(appPackage: String, appName: String)
    fun removeRule(ruleId: String)
    fun toggleRule(ruleId: String)
}
