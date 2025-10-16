package com.clsoft.netguard.framework.vpn.domain.usecase

import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class IsFirewallEnabledUseCase @Inject constructor(
    private val firewallRepository: FirewallRepository
) {
    operator fun invoke(): Flow<Boolean> = firewallRepository.isFirewallEnabled()
}