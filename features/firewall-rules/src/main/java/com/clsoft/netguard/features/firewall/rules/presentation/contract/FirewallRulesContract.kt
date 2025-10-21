package com.clsoft.netguard.features.firewall.rules.presentation.contract

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallApp
import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule

data class FirewallRulesState(
    val isLoading: Boolean = false,
    val isAppsLoading: Boolean = false,
    val rules: List<FirewallRule> = emptyList(),
    val availableApps: List<FirewallApp> = emptyList(),
    val searchQuery: String = "",
    val isDialogVisible: Boolean = false,
    val snackbarMessage: UiMessage? = null,
    val isFirewallEnabled: Boolean = false
)

data class UiMessage(
    val message: String,
    val isError: Boolean = false
)

sealed class FirewallRulesEvent {
    data class AddRule(val appPackage: String, val appName: String) : FirewallRulesEvent()
    data class RemoveRule(val ruleId: String) : FirewallRulesEvent()
    data class ToggleRule(val ruleId: String) : FirewallRulesEvent()
    data class SearchQueryChanged(val query: String) : FirewallRulesEvent()
    data class SetDialogVisible(val visible: Boolean) : FirewallRulesEvent()
    object RefreshInstalledApps : FirewallRulesEvent()
    object ConsumeMessage : FirewallRulesEvent()
}