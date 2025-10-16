package com.clsoft.netguard.features_settings.domain.model

data class AppSetting(
    val darkMode: Boolean = false,
    val autoStart: Boolean = true,
    val language: String = "es",
    val notificationsEnabled: Boolean = true
)