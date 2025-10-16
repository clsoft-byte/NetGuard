package com.clsoft.netguard.features.traffic.monitor.domain.repository

import com.clsoft.netguard.features.traffic.monitor.data.repository.TrafficSummary
import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic
import kotlinx.coroutines.flow.Flow

interface TrafficRepository {
    suspend fun insertTraffic(traffic: Traffic)

    fun getTrafficSummary(): Flow<TrafficSummary>
}