package com.clsoft.netguard.features.analyzer.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.analyzer.presentation.AnalyzerViewModel
import com.clsoft.netguard.features.analyzer.presentation.components.RiskItemCard
import com.clsoft.netguard.features.analyzer.presentation.components.RiskSummaryCard
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalyzerScreen(
    navController: NavController,
    viewModel: AnalyzerViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    var appInput by remember { mutableStateOf("") }
    var ipInput by remember { mutableStateOf("") }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Analizador de Tráfico") }) }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(value = appInput, onValueChange = { appInput = it }, label = { Text("App package") })
            OutlinedTextField(value = ipInput, onValueChange = { ipInput = it }, label = { Text("IP destino") })

            Button(onClick = {
                if (appInput.isNotEmpty() && ipInput.isNotEmpty()) {
                    viewModel.onEvent(AnalyzerEvent.Analyze(appInput, ipInput))
                }
            }) {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Analizar")
            }

            RiskSummaryCard(state.risks)

            Divider()

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.risks) { risk ->
                    RiskItemCard(risk)
                }
            }
        }
    }
}