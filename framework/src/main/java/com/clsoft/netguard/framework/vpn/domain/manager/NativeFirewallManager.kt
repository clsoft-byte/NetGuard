package com.clsoft.netguard.framework.vpn.domain.manager

interface NativeFirewallManager {
    fun applyRule(packageName: String, allow: Boolean)
    fun clearRule(packageName: String)
}