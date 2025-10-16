package com.clsoft.netguard.features.firewall.rules.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.firewall.rules.domain.usecase.AddFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.GetFirewallRulesUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.RemoveFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.ToggleFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesEvent
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class FirewallRulesViewModel @Inject constructor(
    private val getRules: GetFirewallRulesUseCase,
    private val addRule: AddFirewallRuleUseCase,
    private val removeRule: RemoveFirewallRuleUseCase,
    private val toggleRule: ToggleFirewallRuleUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(FirewallRulesState())
    val state: StateFlow<FirewallRulesState> = _state

    init {
        observeRules()
    }

    fun onEvent(event: FirewallRulesEvent) {
        when (event) {
            is FirewallRulesEvent.AddRule -> addRule(event.appPackage, event.appName)
            is FirewallRulesEvent.RemoveRule -> removeRule(event.ruleId)
            is FirewallRulesEvent.ToggleRule -> toggleRule(event.ruleId)
        }
    }

    private fun observeRules() {
        viewModelScope.launch {
            getRules().collectLatest { rules ->
                _state.value = FirewallRulesState(rules)
            }
        }
    }
}