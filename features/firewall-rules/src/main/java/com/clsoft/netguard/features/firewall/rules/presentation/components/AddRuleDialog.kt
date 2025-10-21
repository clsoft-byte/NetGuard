package com.clsoft.netguard.features.firewall.rules.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallApp
import com.clsoft.netguard.features.firewall.rules.presentation.screen.FirewallPalette
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddRuleDialog(
    apps: List<FirewallApp>,
    isLoading: Boolean,
    onRefresh: () -> Unit,
    onConfirm: (String, String) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var manualPackage by remember { mutableStateOf("") }
    var manualName by remember { mutableStateOf("") }

    val filteredApps = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter {
            it.appName.contains(query, ignoreCase = true) ||
                    it.packageName.contains(query, ignoreCase = true)
        }
    }

    LaunchedEffect(Unit) {
        scope.launch { sheetState.expand() }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = FirewallPalette.CardBackground,
        dragHandle = null,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Agregar regla",
                    style = MaterialTheme.typography.titleLarge,
                    color = FirewallPalette.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.weight(1f))
                if (isLoading) {
                    Text(
                        text = "Actualizando...",
                        color = FirewallPalette.TextSecondary,
                        style = MaterialTheme.typography.bodySmall
                    )
                } else {
                    IconButton(onClick = onRefresh) {
                        Icon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = "Actualizar",
                            tint = FirewallPalette.TextSecondary
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp)),
                placeholder = { Text("Buscar aplicación", color = FirewallPalette.TextSecondary) },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = FirewallPalette.InputBackground,
                    unfocusedContainerColor = FirewallPalette.InputBackground,
                    focusedBorderColor = Color.Transparent,
                    unfocusedBorderColor = Color.Transparent,
                    cursorColor = FirewallPalette.TextPrimary,
                    focusedTextColor = FirewallPalette.TextPrimary,
                    unfocusedTextColor = FirewallPalette.TextPrimary
                ),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Aplicaciones instaladas",
                color = FirewallPalette.TextSecondary,
                style = MaterialTheme.typography.labelMedium
            )

            Spacer(modifier = Modifier.height(8.dp))

            val listModifier = Modifier
                .fillMaxWidth()
                .height(240.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(FirewallPalette.RowBackground)
            if (filteredApps.isEmpty()) {
                Column(
                    modifier = listModifier,
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = if (isLoading) "Cargando aplicaciones..." else "Sin resultados",
                        color = FirewallPalette.TextSecondary
                    )
                }
            } else {
                LazyColumn(
                    modifier = listModifier,
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        AppRow(
                            app = app,
                            onClick = {
                                onConfirm(app.packageName, app.appName)
                            }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "Agregar manualmente",
                color = FirewallPalette.TextSecondary,
                style = MaterialTheme.typography.labelMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = manualName,
                onValueChange = { manualName = it },
                label = { Text("Nombre visible", color = FirewallPalette.TextSecondary) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = FirewallPalette.InputBackground,
                    unfocusedContainerColor = FirewallPalette.InputBackground,
                    focusedBorderColor = Color.Transparent,
                    unfocusedBorderColor = Color.Transparent,
                    cursorColor = FirewallPalette.TextPrimary,
                    focusedTextColor = FirewallPalette.TextPrimary,
                    unfocusedTextColor = FirewallPalette.TextPrimary
                ),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = manualPackage,
                onValueChange = { manualPackage = it },
                label = { Text("Package name", color = FirewallPalette.TextSecondary) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = FirewallPalette.InputBackground,
                    unfocusedContainerColor = FirewallPalette.InputBackground,
                    focusedBorderColor = Color.Transparent,
                    unfocusedBorderColor = Color.Transparent,
                    cursorColor = FirewallPalette.TextPrimary,
                    focusedTextColor = FirewallPalette.TextPrimary,
                    unfocusedTextColor = FirewallPalette.TextPrimary
                ),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    onConfirm(manualPackage, manualName)
                },
                enabled = manualPackage.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text("Agregar regla", modifier = Modifier.padding(vertical = 2.dp))
            }

            TextButton(
                onClick = {
                    scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
                },
                modifier = Modifier.align(Alignment.CenterHorizontally)
            ) {
                Text("Cerrar", color = FirewallPalette.TextSecondary)
            }
        }
    }
}

@Composable
private fun AppRow(app: FirewallApp, onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .background(FirewallPalette.RowBackground),
        shape = RoundedCornerShape(0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.appName,
                    color = FirewallPalette.TextPrimary,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = app.packageName,
                    color = FirewallPalette.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(modifier = Modifier.height(0.dp))
            SurfaceIndicator(isSystem = app.isSystemApp)
        }
    }
}

@Composable
private fun SurfaceIndicator(isSystem: Boolean) {
    val background = if (isSystem) FirewallPalette.InputBackground else FirewallPalette.Success
    val label = if (isSystem) "Sistema" else "Usuario"
    val textColor = if (isSystem) FirewallPalette.TextSecondary else FirewallPalette.TextPrimary
    Text(
        text = label,
        color = textColor,
        style = MaterialTheme.typography.labelSmall,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(background)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    )
}