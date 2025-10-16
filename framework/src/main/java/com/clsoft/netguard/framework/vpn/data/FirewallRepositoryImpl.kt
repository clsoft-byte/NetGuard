package com.clsoft.netguard.framework.vpn.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import com.clsoft.netguard.framework.vpn.domain.repository.FirewallRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class FirewallRepositoryImpl @Inject constructor(
    private val dataStore: DataStore<Preferences>
): FirewallRepository {
    private object Keys {
        val FIREWALL_ENABLED = booleanPreferencesKey("firewall_enabled")
    }

    override fun isFirewallEnabled(): Flow<Boolean> = dataStore.data.map {
        it[Keys.FIREWALL_ENABLED] ?: false
    }

    override suspend fun setFirewallEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.FIREWALL_ENABLED] = enabled
        }
    }
}