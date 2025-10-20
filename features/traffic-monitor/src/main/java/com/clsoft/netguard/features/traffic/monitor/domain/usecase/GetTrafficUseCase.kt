package com.clsoft.netguard.features.traffic.monitor.domain.usecase

import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic
import com.clsoft.netguard.features.traffic.monitor.domain.repository.TrafficRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetTrafficUseCase @Inject constructor(
    private val trafficRepository: TrafficRepository
) {
    operator fun invoke(): Flow<List<Traffic>> = trafficRepository.observeTraffic()
}