package com.clsoft.netguard.features.dashboard.data.repository

import com.clsoft.netguard.core.database.dao.DetectionDao
import com.clsoft.netguard.core.database.dao.RuleDao
import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.dashboard.domain.model.DashboardSummary
import com.clsoft.netguard.features.dashboard.domain.model.Detection
import com.clsoft.netguard.features.dashboard.domain.model.TrafficSession
import com.clsoft.netguard.features.dashboard.domain.repository.DashboardRepository
import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import javax.inject.Inject

/**
 * Repositorio temporal (simulado).
 * En una etapa posterior consultará Room + Engine para datos reales.
 */
class DashboardRepositoryImpl @Inject constructor(
    private val trafficDao: TrafficDao,
    private val detectionDao: DetectionDao,
    private val firewallRepository: FirewallRepository
) : DashboardRepository {

    override fun observeDashboardSummary(): Flow<DashboardSummary> {
        val trafficFlow = trafficDao.observeTotalTraffic()
        val detectionsFlow = detectionDao.observeRecentDetections()
        val lastSessionFlow = trafficDao.observeLastSession()
        val firewallFlow = firewallRepository.isFirewallEnabled()


        return combine(
            trafficFlow,
            detectionsFlow,
            firewallFlow,
            lastSessionFlow
        ) { traffic, detections, firewall, session ->
            DashboardSummary(
                firewallEnabled = firewall,
                totalSent = traffic.totalSent,
                totalReceived = traffic.totalReceived,
                detections = detections.map {
                    Detection(
                        appName = it.appName,
                        riskLevel = it.riskLevel,
                        riskType = it.riskLevel,
                        timestamp = it.timestamp
                    )
                },
                lastSession = session?.let {
                    TrafficSession(
                        id = it.id,
                        appPackage = it.appPackage,
                        bytesSent = it.bytesSent,
                        bytesReceived = it.bytesReceived,
                        timestamp = it.timestamp
                    )
                }
            )
        }
    }
}