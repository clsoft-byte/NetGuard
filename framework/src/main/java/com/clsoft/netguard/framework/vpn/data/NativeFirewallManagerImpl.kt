package com.clsoft.netguard.framework.vpn.data

import android.util.Log
import com.clsoft.netguard.engine.network.analyzer.NativeBridge
import com.clsoft.netguard.framework.vpn.domain.manager.NativeFirewallManager
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NativeFirewallManagerImpl @Inject constructor() : NativeFirewallManager {

    override fun applyRule(packageName: String, allow: Boolean) {
        runCatching { NativeBridge.applyFirewallRule(packageName, allow) }
            .onFailure { error ->
                Log.e(TAG, "Error al aplicar la regla para $packageName", error)
            }
    }

    override fun clearRule(packageName: String) {
        applyRule(packageName, true)
    }

    private companion object {
        private const val TAG = "NativeFirewallManager"
    }
}