package com.clsoft.netguard.features.firewall.rules.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.firewall.rules.presentation.FirewallRulesViewModel
import com.clsoft.netguard.features.firewall.rules.presentation.components.AddRuleDialog
import com.clsoft.netguard.features.firewall.rules.presentation.components.RuleRowItem
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallRulesScreen(
    navController: NavController,
    viewModel: FirewallRulesViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    var showDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Reglas del Firewall") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = { showDialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "Agregar regla")
            }
        }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(16.dp)
        ) {
            if (state.rules.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Sin reglas configuradas")
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(state.rules) { rule ->
                        RuleRowItem(
                            rule = rule,
                            onToggle = { viewModel.onEvent(FirewallRulesEvent.ToggleRule(rule.id)) },
                            onRemove = { viewModel.onEvent(FirewallRulesEvent.RemoveRule(rule.id)) }
                        )
                    }
                }
            }

            if (showDialog) {
                AddRuleDialog(
                    onConfirm = { pkg, name ->
                        viewModel.onEvent(FirewallRulesEvent.AddRule(pkg, name))
                        showDialog = false
                    },
                    onDismiss = { showDialog = false }
                )
            }
        }
    }
}