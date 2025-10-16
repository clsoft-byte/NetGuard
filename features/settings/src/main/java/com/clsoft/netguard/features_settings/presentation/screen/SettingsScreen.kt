package com.clsoft.netguard.features_settings.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features_settings.presentation.SettingsViewModel
import com.clsoft.netguard.features_settings.presentation.components.SettingOptionItem
import com.clsoft.netguard.features_settings.presentation.components.SettingSwitchItem
import com.clsoft.netguard.features_settings.presentation.contract.SettingsEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    navController: NavController,
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    Scaffold(
        topBar = { TopAppBar(title = { Text("Configuraciones") }) }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            val setting = state.current

            SettingSwitchItem(
                title = "Modo oscuro",
                checked = setting.darkMode,
                onToggle = {
                    viewModel.onEvent(SettingsEvent.Update(setting.copy(darkMode = it)))
                }
            )

            SettingSwitchItem(
                title = "Inicio automático del firewall",
                checked = setting.autoStart,
                onToggle = {
                    viewModel.onEvent(SettingsEvent.Update(setting.copy(autoStart = it)))
                }
            )

            SettingSwitchItem(
                title = "Notificaciones",
                checked = setting.notificationsEnabled,
                onToggle = {
                    viewModel.onEvent(SettingsEvent.Update(setting.copy(notificationsEnabled = it)))
                }
            )

            SettingOptionItem(
                title = "Idioma",
                selected = setting.language,
                options = listOf("es", "en", "fr"),
                onSelected = {
                    viewModel.onEvent(SettingsEvent.Update(setting.copy(language = it)))
                }
            )

            Spacer(Modifier.height(24.dp))

            Button(
                onClick = { viewModel.onEvent(SettingsEvent.Reset) },
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) {
                Text("Restablecer configuraciones")
            }
        }
    }
}