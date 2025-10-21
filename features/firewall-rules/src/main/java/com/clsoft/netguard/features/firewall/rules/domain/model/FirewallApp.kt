package com.clsoft.netguard.features.firewall.rules.domain.model

data class FirewallApp(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean
)
