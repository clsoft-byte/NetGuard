package com.clsoft.netguard.features.firewall.rules.presentation.contract

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule


data class FirewallRulesState(
    val rules: List<FirewallRule> = emptyList()
)
sealed class FirewallRulesEvent {
    data class AddRule(val appPackage: String, val appName: String) : FirewallRulesEvent()
    data class RemoveRule(val ruleId: String) : FirewallRulesEvent()
    data class ToggleRule(val ruleId: String) : FirewallRulesEvent()
}