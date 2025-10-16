package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.data.repository.FirewallRulesRepositoryImpl
import javax.inject.Inject


class RemoveFirewallRuleUseCase @Inject constructor(
    private val repository: FirewallRulesRepositoryImpl
) {
    operator fun invoke(ruleId: String) = repository.removeRule(ruleId)
}