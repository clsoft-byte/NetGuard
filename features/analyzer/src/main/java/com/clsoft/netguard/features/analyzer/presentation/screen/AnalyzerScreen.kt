package com.clsoft.netguard.features.analyzer.presentation.screen

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.analyzer.presentation.AnalyzerViewModel
import com.clsoft.netguard.features.analyzer.presentation.components.LastAnalysisBanner
import com.clsoft.netguard.features.analyzer.presentation.components.RiskItemCard
import com.clsoft.netguard.features.analyzer.presentation.components.RiskSummaryCard
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerEvent
import com.clsoft.netguard.features.analyzer.presentation.contract.AnalyzerState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalyzerScreen(
    navController: NavController,
    viewModel: AnalyzerViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    ErrorSnackbar(snackbarHostState = snackbarHostState, state = state, onConsumed = {
        viewModel.onEvent(AnalyzerEvent.DismissError)
    })

    Scaffold(
        topBar = { TopAppBar(title = { Text("Analizador de Tráfico") }) },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            AnalyzerContent(
                state = state,
                onAppChanged = { viewModel.onEvent(AnalyzerEvent.AppPackageChanged(it)) },
                onIpChanged = { viewModel.onEvent(AnalyzerEvent.DestinationIpChanged(it)) },
                onAnalyze = { viewModel.onEvent(AnalyzerEvent.Analyze) }
            )

            AnimatedVisibility(
                visible = state.isLoading,
                modifier = Modifier.align(Alignment.Center)
            ) {
                androidx.compose.material3.CircularProgressIndicator()
            }
        }
    }
}

@Composable
private fun ErrorSnackbar(
    snackbarHostState: SnackbarHostState,
    state: AnalyzerState,
    onConsumed: () -> Unit
) {
    LaunchedEffect(state.errorMessage) {
        val message = state.errorMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(message = message)
        onConsumed()
    }
}

@Composable
private fun AnalyzerContent(
    state: AnalyzerState,
    onAppChanged: (String) -> Unit,
    onIpChanged: (String) -> Unit,
    onAnalyze: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        item {
            AnalyzerForm(
                state = state,
                onAppChanged = onAppChanged,
                onIpChanged = onIpChanged,
                onAnalyze = onAnalyze
            )
        }

        state.lastResult?.let { result ->
            item { LastAnalysisBanner(result = result) }
        }

        item { RiskSummaryCard(state.risks) }

        if (state.risks.isEmpty()) {
            item {
                Text(
                    text = "Aún no hay historial. Ejecuta un análisis para comenzar.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            items(state.risks) { risk ->
                RiskItemCard(risk)
            }
        }
    }
}

@Composable
private fun AnalyzerForm(
    state: AnalyzerState,
    onAppChanged: (String) -> Unit,
    onIpChanged: (String) -> Unit,
    onAnalyze: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = state.appPackage,
            onValueChange = onAppChanged,
            label = { Text("Paquete de la app") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            leadingIcon = { Icon(Icons.Default.Bolt, contentDescription = null) },
            supportingText = { Text("Ejemplo: com.empresa.app") }
        )

        OutlinedTextField(
            value = state.destinationIp,
            onValueChange = onIpChanged,
            label = { Text("IP destino") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            keyboardOptions = KeyboardOptions.Default.copy(autoCorrect = false),
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            supportingText = { Text("IPv4 o IPv6") }
        )

        Button(
            onClick = onAnalyze,
            modifier = Modifier.fillMaxWidth(),
            enabled = state.isLoading.not()
        ) {
            Icon(Icons.Default.Search, contentDescription = null)
            Text(
                text = if (state.isLoading) "Analizando…" else "Analizar",
                modifier = Modifier.padding(start = 8.dp)
            )
        }
    }
}