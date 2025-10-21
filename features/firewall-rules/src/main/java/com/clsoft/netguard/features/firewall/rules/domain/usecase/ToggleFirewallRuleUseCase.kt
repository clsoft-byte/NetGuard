package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import javax.inject.Inject

class ToggleFirewallRuleUseCase @Inject constructor(
    private val repository: FirewallRulesRepository
) {
    suspend operator fun invoke(ruleId: String) = repository.toggleRule(ruleId)
}