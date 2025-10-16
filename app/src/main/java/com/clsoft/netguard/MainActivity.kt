package com.clsoft.netguard

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.navigation.compose.rememberNavController
import com.clsoft.netguard.navigation.NavGraph
import com.clsoft.netguard.ui.components.BottomNavigationBar
import com.clsoft.netguard.ui.theme.NetGuardTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Log.d("MainActivity", "❌ Permiso VPN Activado por el usuario")
        } else {
            Log.e("MainActivity", "❌ Permiso VPN denegado por el usuario")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        prepareVpnPermission()
        setContent {
            NetGuardTheme {
                val navController = rememberNavController()

                Scaffold(
                    bottomBar = { BottomNavigationBar(navController) }
                ) { innerPadding ->
                    NavGraph(
                        navController = navController,
                        padding = innerPadding
                    )
                }
            }
        }
    }

    private fun prepareVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // 🔹 Se necesita pedir permiso
            vpnPermissionLauncher.launch(intent)
        }
    }
}