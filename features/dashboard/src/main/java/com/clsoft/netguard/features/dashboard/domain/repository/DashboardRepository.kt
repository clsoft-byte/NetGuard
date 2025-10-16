package com.clsoft.netguard.features.dashboard.domain.repository

import com.clsoft.netguard.features.dashboard.domain.model.DashboardSummary
import kotlinx.coroutines.flow.Flow

interface DashboardRepository {
    fun observeDashboardSummary(): Flow<DashboardSummary>
}