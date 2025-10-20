package com.clsoft.netguard.features.traffic.monitor.domain.repository

import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic
import kotlinx.coroutines.flow.Flow

interface TrafficRepository {
    suspend fun saveOrUpdateTraffic(traffic: Traffic)

    fun observeTraffic(): Flow<List<Traffic>>
}