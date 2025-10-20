package com.clsoft.netguard.features.traffic.monitor.data.repository

import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.features.traffic.monitor.data.mapper.toDomain
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
import kotlin.math.max


class TrafficRepositoryImpl @Inject constructor(
    private val trafficDao: TrafficDao
) : TrafficRepository {
    override suspend fun saveOrUpdateTraffic(traffic: Traffic) {
        val entity = traffic.toEntity()
        val existing = trafficDao.findActiveSession(
            entity.sourceIp, entity.destinationIp, entity.protocol, entity.destinationPort
        )
        if (existing != null) {
            val updated = existing.copy(
                bytesSent = existing.bytesSent + entity.bytesSent,
                bytesReceived = existing.bytesReceived + entity.bytesReceived,
                timestamp = System.currentTimeMillis(),
                riskScore = max(existing.riskScore, entity.riskScore),
                riskLabel = if (entity.riskScore > existing.riskScore) entity.riskLabel else existing.riskLabel
            )
            trafficDao.updateTraffic(updated)
        } else {
            trafficDao.insertTraffic(entity)
        }
    }


    override fun observeTraffic(): Flow<List<Traffic>> {
        return trafficDao.observeTraffic().map { entities ->
            entities.map { it.toDomain() }
        }
    }
}