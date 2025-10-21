package com.clsoft.netguard.navigation

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.clsoft.netguard.features.analyzer.presentation.screen.AnalyzerScreen
import com.clsoft.netguard.features.dashboard.presentation.screen.DashboardScreen
import com.clsoft.netguard.features.firewall.rules.presentation.screen.FirewallRulesScreen
import com.clsoft.netguard.features.traffic.monitor.presentation.screen.TrafficMonitorScreen
import com.clsoft.netguard.features_settings.presentation.screen.SettingsScreen

@Composable
fun NavGraph(
    navController: NavHostController,
    padding: PaddingValues
) {
    NavHost(
        navController = navController,
        startDestination = BottomNavItem.Dashboard.route,
        modifier = Modifier
    ) {
        composable(BottomNavItem.Dashboard.route) {
            DashboardScreen(navController = navController)
        }
        composable(BottomNavItem.Traffic.route) {
            TrafficMonitorScreen(navController = navController)
        }
        composable(BottomNavItem.Firewall.route) {
            FirewallRulesScreen(navController = navController, padding)
        }
        composable(BottomNavItem.Analyzer.route) {
            AnalyzerScreen(navController = navController)
        }
        composable(BottomNavItem.Settings.route) {
            SettingsScreen(navController = navController)
        }
    }
}
