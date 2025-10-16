package com.clsoft.netguard.features.dashboard.domain.usecase

import com.clsoft.netguard.features.dashboard.domain.model.DashboardSummary
import com.clsoft.netguard.features.dashboard.domain.repository.DashboardRepository
import com.clsoft.netguard.features.traffic.monitor.domain.repository.TrafficRepository
import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import javax.inject.Inject

/**
 * Use case simulado — en producción obtendría datos reales
 * desde los repositorios de tráfico y detección.
 */
class GetDashboardDataUseCase @Inject constructor(
    private val dashboardRepository: DashboardRepository
) {
    operator fun invoke(): Flow<DashboardSummary> = dashboardRepository.observeDashboardSummary()
}