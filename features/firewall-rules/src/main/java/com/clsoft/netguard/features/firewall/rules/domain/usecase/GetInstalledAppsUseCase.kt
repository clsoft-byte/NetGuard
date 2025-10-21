package com.clsoft.netguard.features.firewall.rules.domain.usecase

import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallAppsRepository
import javax.inject.Inject

class GetInstalledAppsUseCase @Inject constructor(
    private val repository: FirewallAppsRepository
) {
    suspend operator fun invoke() = repository.getInstalledApps()
}