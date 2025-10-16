package com.clsoft.netguard.features.traffic.monitor.domain.usecase


import android.content.Context
import android.content.Intent
import com.clsoft.netguard.features.traffic.monitor.service.NetGuardVpnService

class StopMonitoringUseCase {
    operator fun invoke(context: Context) {
        val intent = Intent(context, NetGuardVpnService::class.java)
        context.stopService(intent)
    }
}