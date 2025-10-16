package com.clsoft.netguard.features.analyzer.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk

@Composable
fun RiskSummaryCard(risks: List<TrafficRisk>) {
    val high = risks.count { it.riskLevel.name == "HIGH" }
    val medium = risks.count { it.riskLevel.name == "MEDIUM" }
    val low = risks.count { it.riskLevel.name == "LOW" }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Resumen de Riesgos", style = MaterialTheme.typography.titleMedium)
            Text("Alto: $high | Medio: $medium | Bajo: $low")
        }
    }
}