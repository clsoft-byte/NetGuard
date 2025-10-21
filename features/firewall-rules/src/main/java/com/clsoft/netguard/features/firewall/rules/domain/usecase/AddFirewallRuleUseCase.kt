package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import javax.inject.Inject

class AddFirewallRuleUseCase @Inject constructor(
    private val repository: FirewallRulesRepository
) {
    suspend operator fun invoke(appPackage: String, appName: String) =
        repository.addRule(appPackage, appName)
}