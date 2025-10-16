package com.clsoft.netguard.features_settings.domain.repository

import com.clsoft.netguard.features_settings.domain.model.AppSetting
import kotlinx.coroutines.flow.Flow

interface SettingsRepository {

    fun getSettings(): Flow<AppSetting>

    suspend fun updateSetting(setting: AppSetting)

    suspend fun resetSettings()
}