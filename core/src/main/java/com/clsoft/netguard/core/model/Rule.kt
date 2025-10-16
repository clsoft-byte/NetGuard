package com.clsoft.netguard.core.model


data class Rule(
    val id: String,
    val appPackage: String?,
    val domain: String?,
    val ip: String?,
    val protocol: String?,
    val action: RuleAction,
    val createdAt: Long
)

enum class RuleAction { ALLOW, BLOCK }