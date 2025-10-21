package com.clsoft.netguard.features.firewall.rules.domain.repository

import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallApp

interface FirewallAppsRepository {
    suspend fun getInstalledApps(): List<FirewallApp>
}
