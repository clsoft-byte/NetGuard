package com.clsoft.netguard.features.firewall.rules.data.repository

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import com.clsoft.netguard.features.firewall.rules.domain.error.DuplicateFirewallRuleException
import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule
import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallRulesRepository
import com.clsoft.netguard.framework.vpn.domain.manager.NativeFirewallManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class FirewallRulesRepositoryImpl @Inject constructor(
    private val dataStore: DataStore<Preferences>,
    private val nativeFirewallManager: NativeFirewallManager
) : FirewallRulesRepository {

    private object Keys {
        val RULES = stringPreferencesKey("firewall_rules")
    }

    override fun getRules(): Flow<List<FirewallRule>> =
        dataStore.data
            .catch { exception ->
                if (exception is IOException) {
                    emit(emptyPreferences())
                } else {
                    throw exception
                }
            }
            .map { prefs -> prefs[Keys.RULES].toRules() }
            .distinctUntilChanged()

    override suspend fun addRule(appPackage: String, appName: String) {
        val sanitizedPackage = appPackage.trim()
        if (sanitizedPackage.isBlank()) {
            throw IllegalArgumentException("El package de la app no puede estar vacío")
        }
        val sanitizedName = appName.ifBlank { sanitizedPackage }

        var createdRule: FirewallRule? = null
        withContext(Dispatchers.IO) {
            dataStore.edit { prefs ->
                val current = prefs[Keys.RULES].toRules().toMutableList()
                if (current.any { it.appPackage == sanitizedPackage }) {
                    throw DuplicateFirewallRuleException()
                }
                createdRule = FirewallRule(
                    id = UUID.randomUUID().toString(),
                    appPackage = sanitizedPackage,
                    appName = sanitizedName,
                    isAllowed = false
                )
                current.add(createdRule!!)
                prefs[Keys.RULES] = current.toJson()
            }
        }
        createdRule?.let { rule ->
            runCatching { nativeFirewallManager.applyRule(rule.appPackage, rule.isAllowed) }
                .onFailure { Log.e(TAG, "No se pudo aplicar la regla tras crearla", it) }
        }
    }

    override suspend fun removeRule(ruleId: String) {
        var removedRule: FirewallRule? = null
        withContext(Dispatchers.IO) {
            dataStore.edit { prefs ->
                val current = prefs[Keys.RULES].toRules()
                val updated = current.filterNot {
                    val shouldRemove = it.id == ruleId
                    if (shouldRemove) removedRule = it
                    shouldRemove
                }
                if (updated.size != current.size) {
                    prefs[Keys.RULES] = updated.toJson()
                }
            }
        }
        removedRule?.let { rule ->
            runCatching { nativeFirewallManager.clearRule(rule.appPackage) }
                .onFailure { Log.e(TAG, "No se pudo limpiar la regla tras eliminarla", it) }
        }
    }

    override suspend fun toggleRule(ruleId: String) {
        var toggledRule: FirewallRule? = null
        withContext(Dispatchers.IO) {
            dataStore.edit { prefs ->
                val current = prefs[Keys.RULES].toRules()
                val updated = current.map { rule ->
                    if (rule.id == ruleId) {
                        val next = rule.copy(isAllowed = !rule.isAllowed)
                        toggledRule = next
                        next
                    } else {
                        rule
                    }
                }
                if (toggledRule != null) {
                    prefs[Keys.RULES] = updated.toJson()
                }
            }
        }
        toggledRule?.let { rule ->
            runCatching { nativeFirewallManager.applyRule(rule.appPackage, rule.isAllowed) }
                .onFailure { Log.e(TAG, "No se pudo aplicar la regla tras alternarla", it) }
        }
    }

    private fun String?.toRules(): List<FirewallRule> {
        if (this.isNullOrBlank()) return emptyList()
        return runCatching {
            val json = JSONArray(this)
            buildList {
                for (index in 0 until json.length()) {
                    val obj = json.getJSONObject(index)
                    add(
                        FirewallRule(
                            id = obj.getString("id"),
                            appPackage = obj.getString("package"),
                            appName = obj.getString("name"),
                            isAllowed = obj.optBoolean("allowed", false)
                        )
                    )
                }
            }
        }.getOrElse {
            Log.e(TAG, "Error al parsear las reglas de firewall almacenadas", it)
            emptyList()
        }
    }

    private fun List<FirewallRule>.toJson(): String {
        val array = JSONArray()
        forEach { rule ->
            array.put(
                JSONObject().apply {
                    put("id", rule.id)
                    put("package", rule.appPackage)
                    put("name", rule.appName)
                    put("allowed", rule.isAllowed)
                }
            )
        }
        return array.toString()
    }

    private companion object {
        private const val TAG = "FirewallRulesRepo"
    }
}