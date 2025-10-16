package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.data.repository.FirewallRulesRepositoryImpl
import javax.inject.Inject

class AddFirewallRuleUseCase @Inject constructor(
    private val repository: FirewallRulesRepositoryImpl
) {
    operator fun invoke(appPackage: String, appName: String) =
        repository.addRule(appPackage, appName)
}