package com.clsoft.netguard.features.firewall.rules.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallApp
import com.clsoft.netguard.features.firewall.rules.domain.repository.FirewallAppsRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class FirewallAppsRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : FirewallAppsRepository {

    override suspend fun getInstalledApps(): List<FirewallApp> = withContext(Dispatchers.IO) {
        val packageManager = context.packageManager
        val installed = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        installed
            .distinctBy { it.packageName }
            .map { appInfo ->
                val label = packageManager.getApplicationLabel(appInfo)?.toString().orEmpty()
                val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                FirewallApp(
                    packageName = appInfo.packageName,
                    appName = label.ifBlank { appInfo.packageName },
                    isSystemApp = isSystemApp
                )
            }
            .sortedWith(compareBy<FirewallApp> { it.isSystemApp }.thenBy { it.appName.lowercase() })
    }
}
