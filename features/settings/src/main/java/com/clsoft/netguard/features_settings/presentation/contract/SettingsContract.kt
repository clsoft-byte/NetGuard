package com.clsoft.netguard.features_settings.presentation.contract

import com.clsoft.netguard.features_settings.domain.model.AppSetting

data class SettingsState(
    val current: AppSetting = AppSetting()
)

sealed class SettingsEvent {
    data class Update(val setting: AppSetting) : SettingsEvent()
    object Reset : SettingsEvent()
}