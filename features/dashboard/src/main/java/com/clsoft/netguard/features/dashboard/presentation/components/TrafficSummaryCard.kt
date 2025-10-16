package com.clsoft.netguard.features.dashboard.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun TrafficSummaryCard(totalTraffic: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Tráfico Total", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(totalTraffic, style = MaterialTheme.typography.bodyLarge)
        }
    }
}