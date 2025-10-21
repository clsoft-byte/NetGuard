package com.clsoft.netguard.features.firewall.rules.presentation.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.firewall.rules.presentation.FirewallRulesViewModel
import com.clsoft.netguard.features.firewall.rules.presentation.components.AddRuleDialog
import com.clsoft.netguard.features.firewall.rules.presentation.components.FirewallSummaryCard
import com.clsoft.netguard.features.firewall.rules.presentation.components.RuleRowItem
import com.clsoft.netguard.features.firewall.rules.presentation.contract.FirewallRulesEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallRulesScreen(
    navController: NavController,
    paddingValues: PaddingValues,
    viewModel: FirewallRulesViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(state.snackbarMessage) {
        state.snackbarMessage?.let { message ->
            snackbarHostState.showSnackbar(message.message)
            viewModel.onEvent(FirewallRulesEvent.ConsumeMessage)
        }
    }

    val filteredRules = remember(state.rules, state.searchQuery) {
        if (state.searchQuery.isBlank()) state.rules
        else state.rules.filter {
            it.appName.contains(state.searchQuery, ignoreCase = true) ||
                    it.appPackage.contains(state.searchQuery, ignoreCase = true)
        }
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            background = FirewallPalette.Background,
            surface = FirewallPalette.CardBackground,
            primary = FirewallPalette.Accent,
            onSurface = FirewallPalette.TextPrimary,
            onBackground = FirewallPalette.TextPrimary
        )
    ) {
        Scaffold(
            containerColor = FirewallPalette.Background,
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = "Firewall",
                            color = FirewallPalette.TextPrimary,
                            fontWeight = FontWeight.SemiBold
                        )
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = FirewallPalette.Background
                    )
                )
            },
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            floatingActionButton = {
                FloatingActionButton(
                    modifier = Modifier.padding(bottom = paddingValues.calculateBottomPadding()),
                    onClick = { viewModel.onEvent(FirewallRulesEvent.SetDialogVisible(true)) },
                    containerColor = FirewallPalette.Accent
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Add,
                        contentDescription = "Agregar regla",
                        tint = Color.White
                    )
                }
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .background(FirewallPalette.Background)
                    .padding(horizontal = 16.dp)
            ) {
                Spacer(modifier = Modifier.height(12.dp))
                FirewallSummaryCard(
                    isEnabled = state.isFirewallEnabled,
                    totalRules = state.rules.size,
                    allowedRules = state.rules.count { it.isAllowed },
                    blockedRules = state.rules.count { !it.isAllowed }
                )

                Spacer(modifier = Modifier.height(20.dp))

                SearchField(
                    value = state.searchQuery,
                    onValueChange = { viewModel.onEvent(FirewallRulesEvent.SearchQueryChanged(it)) }
                )

                Spacer(modifier = Modifier.height(16.dp))

                when {
                    state.isLoading -> {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "Cargando reglas...",
                                color = FirewallPalette.TextSecondary
                            )
                        }
                    }
                    filteredRules.isEmpty() -> {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "No hay reglas configuradas",
                                color = FirewallPalette.TextSecondary
                            )
                        }
                    }
                    else -> {
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            items(filteredRules, key = { it.id }) { rule ->
                                RuleRowItem(
                                    rule = rule,
                                    onToggle = { viewModel.onEvent(FirewallRulesEvent.ToggleRule(rule.id)) },
                                    onRemove = { viewModel.onEvent(FirewallRulesEvent.RemoveRule(rule.id)) }
                                )
                            }
                            item { Spacer(modifier = Modifier.height(72.dp)) }
                        }
                    }
                }
            }
        }

        if (state.isDialogVisible) {
            AddRuleDialog(
                apps = state.availableApps,
                isLoading = state.isAppsLoading,
                onRefresh = { viewModel.onEvent(FirewallRulesEvent.RefreshInstalledApps) },
                onConfirm = { pkg, name -> viewModel.onEvent(FirewallRulesEvent.AddRule(pkg, name)) },
                onDismiss = { viewModel.onEvent(FirewallRulesEvent.SetDialogVisible(false)) }
            )
        }
    }
}

@Composable
private fun SearchField(value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        placeholder = { Text("Buscar reglas", color = FirewallPalette.TextSecondary) },
        leadingIcon = {
            Icon(
                imageVector = Icons.Rounded.Search,
                contentDescription = null,
                tint = FirewallPalette.TextSecondary
            )
        },
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .background(FirewallPalette.InputBackground, RoundedCornerShape(14.dp)),
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = FirewallPalette.InputBackground,
            unfocusedContainerColor = FirewallPalette.InputBackground,
            focusedBorderColor = Color.Transparent,
            unfocusedBorderColor = Color.Transparent,
            cursorColor = FirewallPalette.TextPrimary,
            focusedTextColor = FirewallPalette.TextPrimary,
            unfocusedTextColor = FirewallPalette.TextPrimary
        )
    )
}

internal object FirewallPalette {
    val Background = Color(0xFF0E1116)
    val CardBackground = Color(0xFF151922)
    val RowBackground = Color(0xFF1B202B)
    val InputBackground = Color(0xFF1F2430)
    val TextPrimary = Color(0xFFE4E9F7)
    val TextSecondary = Color(0xFF7A8197)
    val Accent = Color(0xFF5568F5)
    val Success = Color(0xFF5DD17E)
    val Warning = Color(0xFFF97373)
}