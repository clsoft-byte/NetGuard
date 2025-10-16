package com.clsoft.netguard.features.traffic.monitor.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.traffic.monitor.presentation.TrafficMonitorViewModel
import com.clsoft.netguard.features.traffic.monitor.presentation.components.LiveTrafficList
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficMonitorScreen(
    navController: NavController,
    viewModel: TrafficMonitorViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    Scaffold(
        topBar = { TopAppBar(title = { Text("Monitor de Tráfico") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Estado: ${if (state.isMonitoring) "Monitoreando" else "Detenido"}")
                Button(
                    onClick = {
                        if (state.isMonitoring)
                            viewModel.onEvent(TrafficMonitorEvent.Stop, navController.context)
                        else
                            viewModel.onEvent(TrafficMonitorEvent.Start, navController.context)
                    }
                ) {
                    Text(if (state.isMonitoring) "Detener" else "Iniciar")
                }
            }

            Divider()

            if (state.sessions.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Sin tráfico detectado")
                }
            } else {
                LiveTrafficList(state.sessions)
            }
        }
    }
}