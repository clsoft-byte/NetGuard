package com.clsoft.netguard.features.firewall.rules.data.repository

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule
import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

class FirewallRulesRepositoryImpl: FirewallRulesRepository {
    private val rules = mutableListOf<FirewallRule>()
    private val _rulesFlow = MutableStateFlow<List<FirewallRule>>(emptyList())
    val rulesFlow: Flow<List<FirewallRule>> = _rulesFlow.asStateFlow()

    override fun getRules(): Flow<List<FirewallRule>> = rulesFlow

    override fun addRule(appPackage: String, appName: String) {
        val newRule = FirewallRule(UUID.randomUUID().toString(), appPackage, appName, isAllowed = false)
        rules.add(newRule)
        _rulesFlow.value = rules.toList()
    }

    override fun removeRule(ruleId: String) {
        rules.removeAll { it.id == ruleId }
        _rulesFlow.value = rules.toList()
    }

    override fun toggleRule(ruleId: String) {
        rules.replaceAll {
            if (it.id == ruleId) it.copy(isAllowed = !it.isAllowed) else it
        }
        _rulesFlow.value = rules.toList()
    }
}