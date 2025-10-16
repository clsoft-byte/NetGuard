package com.clsoft.netguard.features.dashboard.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun DetectionSummaryCard(detections: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Detecciones", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text("$detections riesgos detectados", style = MaterialTheme.typography.bodyLarge)
        }
    }
}