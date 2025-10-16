package com.clsoft.netguard.features.firewall.rules.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.unit.dp

@Composable
fun AddRuleDialog(
    onConfirm: (String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var appName by remember { mutableStateOf("") }
    var appPackage by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Agregar regla") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = appName, onValueChange = { appName = it }, label = { Text("Nombre de la app") })
                OutlinedTextField(value = appPackage, onValueChange = { appPackage = it }, label = { Text("Package name") })
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(appPackage, appName) }) { Text("Agregar") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancelar") }
        }
    )
}