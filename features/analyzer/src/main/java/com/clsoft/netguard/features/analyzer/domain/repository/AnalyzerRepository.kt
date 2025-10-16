package com.clsoft.netguard.features.analyzer.domain.repository

import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import kotlinx.coroutines.flow.Flow

interface AnalyzerRepository {

    fun analyze(appPackage: String, destinationIp: String): TrafficRisk

    fun getHistory(): Flow<List<TrafficRisk>>

}