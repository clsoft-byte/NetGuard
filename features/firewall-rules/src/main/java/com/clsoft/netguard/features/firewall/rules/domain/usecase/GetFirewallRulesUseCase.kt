package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import javax.inject.Inject

class GetFirewallRulesUseCase @Inject constructor(
    private val repository: FirewallRulesRepository
) {
    operator fun invoke() = repository.getRules()
}