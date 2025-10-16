package com.clsoft.netguard.features.traffic.monitor.data.repository

import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.traffic.monitor.data.mapper.toEntity
import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic
import com.clsoft.netguard.features.traffic.monitor.domain.repository.TrafficRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject


class TrafficRepositoryImpl @Inject constructor(
    private val trafficDao: TrafficDao
) : TrafficRepository {
    override suspend fun insertTraffic(traffic: Traffic) =
        trafficDao.insert(traffic.toEntity())


    override fun getTrafficSummary(): Flow<TrafficSummary> {
        val totalFlow = trafficDao.getTotalTraffic().map { bytes ->
            val mb = bytes / (1024.0 * 1024.0)
            "%.2f".format(mb)
        }

        val blockedFlow = trafficDao.getBlockedConnections()
        val detectionsFlow = trafficDao.getDetectionsSince(System.currentTimeMillis() - 24 * 60 * 60 * 1000)
        val lastScanFlow = trafficDao.getLastScanTime().map {
            it?.let { ts ->
                val df = SimpleDateFormat("HH:mm", Locale.getDefault())
                "Última sesión: ${df.format(Date(ts))}"
            } ?: "Nunca"
        }

        return combine(totalFlow, blockedFlow, detectionsFlow, lastScanFlow) { total, blocked, detections, lastScan ->
            TrafficSummary(
                totalMB = total,
                blocked = blocked,
                alerts = detections,
                lastScan = lastScan
            )
        }
    }
}

data class TrafficSummary(
    val totalMB: String,
    val blocked: Int,
    val alerts: Int,
    val lastScan: String
)