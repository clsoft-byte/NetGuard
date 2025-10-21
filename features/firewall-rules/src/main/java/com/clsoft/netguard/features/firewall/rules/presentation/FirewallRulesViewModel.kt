package com.clsoft.netguard.features.firewall.rules.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features.firewall.rules.domain.error.DuplicateFirewallRuleException
import com.clsoft.netguard.features.firewall.rules.domain.usecase.AddFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.GetFirewallRulesUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.GetInstalledAppsUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.RemoveFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.domain.usecase.ToggleFirewallRuleUseCase
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesEvent
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesState
import com.clsoft.netguard.features.firewall.rules.presentation.contract.UiMessage
import com.clsoft.netguard.framework.vpn.domain.usecase.IsFirewallEnabledUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class FirewallRulesViewModel @Inject constructor(
    private val getRules: GetFirewallRulesUseCase,
    private val addFirewallRule: AddFirewallRuleUseCase,
    private val removeFirewallRule: RemoveFirewallRuleUseCase,
    private val toggleFirewallRule: ToggleFirewallRuleUseCase,
    private val getInstalledApps: GetInstalledAppsUseCase,
    private val isFirewallEnabledUseCase: IsFirewallEnabledUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(
        FirewallRulesState(isLoading = true)
    )
    val state: StateFlow<FirewallRulesState> = _state

    init {
        observeRules()
        observeFirewallStatus()
        loadInstalledApps()
    }

    fun onEvent(event: FirewallRulesEvent) {
        when (event) {
            is FirewallRulesEvent.AddRule -> addRule(event)
            is FirewallRulesEvent.RemoveRule -> removeRule(event.ruleId)
            is FirewallRulesEvent.ToggleRule -> toggleRule(event.ruleId)
            is FirewallRulesEvent.SearchQueryChanged ->
                _state.update { it.copy(searchQuery = event.query) }
            is FirewallRulesEvent.SetDialogVisible -> {
                _state.update { it.copy(isDialogVisible = event.visible) }
                if (event.visible && _state.value.availableApps.isEmpty() && !_state.value.isAppsLoading) {
                    loadInstalledApps()
                }
            }
            FirewallRulesEvent.RefreshInstalledApps -> loadInstalledApps(force = true)
            FirewallRulesEvent.ConsumeMessage ->
                _state.update { it.copy(snackbarMessage = null) }
        }
    }

    private fun observeRules() {
        viewModelScope.launch {
            getRules().collectLatest { rules ->
                _state.update { it.copy(rules = rules, isLoading = false) }
            }
        }
    }

    private fun observeFirewallStatus() {
        viewModelScope.launch {
            isFirewallEnabledUseCase().collectLatest { enabled ->
                _state.update { it.copy(isFirewallEnabled = enabled) }
            }
        }
    }

    private fun loadInstalledApps(force: Boolean = false) {
        if (_state.value.isAppsLoading && !force) return
        viewModelScope.launch {
            _state.update { it.copy(isAppsLoading = true) }
            runCatching { getInstalledApps() }
                .onSuccess { apps ->
                    _state.update {
                        it.copy(
                            availableApps = apps,
                            isAppsLoading = false
                        )
                    }
                }
                .onFailure { error ->
                    _state.update {
                        it.copy(
                            isAppsLoading = false,
                            snackbarMessage = UiMessage(
                                message = error.localizedMessage
                                    ?: "No se pudieron obtener las aplicaciones instaladas",
                                isError = true
                            )
                        )
                    }
                }
        }
    }

    private fun addRule(event: FirewallRulesEvent.AddRule) {
        viewModelScope.launch {
            runCatching { addFirewallRule(event.appPackage, event.appName) }
                .onSuccess {
                    _state.update {
                        it.copy(
                            snackbarMessage = UiMessage("Regla agregada exitosamente"),
                            isDialogVisible = false
                        )
                    }
                }
                .onFailure { error ->
                    val message = when (error) {
                        is DuplicateFirewallRuleException -> error.message
                        is IllegalArgumentException -> error.message
                        else -> "No se pudo crear la regla"
                    } ?: "No se pudo crear la regla"
                    _state.update {
                        it.copy(
                            snackbarMessage = UiMessage(message, isError = true)
                        )
                    }
                }
        }
    }

    private fun removeRule(ruleId: String) {
        viewModelScope.launch {
            runCatching { removeFirewallRule(ruleId) }
                .onSuccess {
                    _state.update {
                        it.copy(snackbarMessage = UiMessage("Regla eliminada"))
                    }
                }
                .onFailure {
                    _state.update {
                        it.copy(
                            snackbarMessage = UiMessage(
                                message = "No se pudo eliminar la regla",
                                isError = true
                            )
                        )
                    }
                }
        }
    }

    private fun toggleRule(ruleId: String) {
        viewModelScope.launch {
            runCatching { toggleFirewallRule(ruleId) }
                .onFailure {
                    _state.update {
                        it.copy(
                            snackbarMessage = UiMessage(
                                message = "No se pudo actualizar la regla",
                                isError = true
                            )
                        )
                    }
                }
        }
    }
}