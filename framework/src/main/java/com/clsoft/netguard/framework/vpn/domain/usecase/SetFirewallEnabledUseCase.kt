package com.clsoft.netguard.framework.vpn.domain.usecase

import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import javax.inject.Inject

class SetFirewallEnabledUseCase @Inject constructor(
    private val firewallRepository: FirewallRepository
) {
    suspend operator fun invoke(enabled: Boolean) {
        firewallRepository.setFirewallEnabled(enabled)
    }
}