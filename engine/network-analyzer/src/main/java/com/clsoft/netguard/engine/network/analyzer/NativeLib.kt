package com.clsoft.netguard.engine.network.analyzer

object NativeBridge {

    init {
        System.loadLibrary("netguard_native")
    }

    external fun getNativeVersion(): String
    external fun analyzePackets(packetData: Array<String>): Array<String>
    external fun applyFirewallRule(packageName: String, allow: Boolean)
}