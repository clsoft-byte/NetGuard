package com.clsoft.netguard.navigation

import androidx.annotation.DrawableRes
import com.clsoft.netguard.R

sealed class BottomNavItem(
    val route: String,
    val label: String,
    @DrawableRes val icon: Int
) {
    object Dashboard : BottomNavItem("dashboard", "Inicio", R.drawable.ic_dashboard)
    object Traffic : BottomNavItem("traffic_monitor", "Tráfico", R.drawable.ic_traffic)
    object Firewall : BottomNavItem("firewall_rules", "Firewall", R.drawable.ic_firewall)
    object Analyzer : BottomNavItem("analyzer", "Análisis", R.drawable.ic_analyzer)
    object Settings : BottomNavItem("settings", "Ajustes", R.drawable.ic_settings)

    companion object {
        val items = listOf(Dashboard, Traffic, Firewall, Analyzer, Settings)
    }
}