package com.clsoft.netguard.engine.network.analyzer

object NativeBridge {

    init {
        System.loadLibrary("netguard_native")
    }

    external fun getNativeVersion(): String
    @JvmStatic external fun analyzePackets(packets: Array<ByteArray>): Array<String>
    external fun applyFirewallRule(packageName: String, allow: Boolean)
}