package com.clsoft.netguard.features.analyzer.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk

@Composable
fun RiskItemCard(risk: TrafficRisk) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(risk.appPackage, style = MaterialTheme.typography.titleMedium)
            Text("Destino: ${risk.destinationIp}")
            Text("Riesgo: ${risk.riskLevel.label}", color = MaterialTheme.colorScheme.error)
            Text(risk.description, style = MaterialTheme.typography.bodySmall)
        }
    }
}