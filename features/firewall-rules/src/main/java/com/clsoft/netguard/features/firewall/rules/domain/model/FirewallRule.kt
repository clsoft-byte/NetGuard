package com.clsoft.netguard.features.firewall.rules.domain.model

data class FirewallRule(
    val id: String,
    val appPackage: String,
    val appName: String,
    val isAllowed: Boolean
)