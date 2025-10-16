package com.clsoft.netguard.features_settings.data.repository

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import com.clsoft.netguard.features_settings.domain.model.AppSetting
import com.clsoft.netguard.features_settings.domain.repository.SettingsRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class SettingsRepositoryImpl @Inject constructor(
    private val dataStore: DataStore<Preferences>
): SettingsRepository {
    private object Keys {
        val DARK_MODE = booleanPreferencesKey("dark_mode")
        val AUTO_START = booleanPreferencesKey("auto_start")
        val LANGUAGE = stringPreferencesKey("language")
        val NOTIFICATIONS = booleanPreferencesKey("notifications_enabled")
    }

    override fun getSettings(): Flow<AppSetting> = dataStore.data.map { prefs ->
        AppSetting(
            darkMode = prefs[Keys.DARK_MODE] ?: false,
            autoStart = prefs[Keys.AUTO_START] ?: true,
            language = prefs[Keys.LANGUAGE] ?: "es",
            notificationsEnabled = prefs[Keys.NOTIFICATIONS] ?: true
        )
    }

    override suspend fun updateSetting(setting: AppSetting) {
        dataStore.edit { prefs ->
            prefs[Keys.DARK_MODE] = setting.darkMode
            prefs[Keys.AUTO_START] = setting.autoStart
            prefs[Keys.LANGUAGE] = setting.language
            prefs[Keys.NOTIFICATIONS] = setting.notificationsEnabled
        }
    }

    override suspend fun resetSettings() {
        dataStore.edit { it.clear() }
    }
}