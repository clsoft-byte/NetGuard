package com.clsoft.netguard.features.analyzer.presentation.components

import android.graphics.Color.parseColor
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk

@Composable
fun RiskSummaryCard(risks: List<TrafficRisk>, modifier: Modifier = Modifier) {
    val total = risks.size
    val high = risks.count { it.riskLevel.name == "HIGH" }
    val medium = risks.count { it.riskLevel.name == "MEDIUM" }
    val low = risks.count { it.riskLevel.name == "LOW" }
    val highRatio = if (total == 0) 0f else high.toFloat() / total

    Card(modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Column {
                    Text("Resumen de Riesgos", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (total == 0) "Sin análisis aún" else "$total análisis completados",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Crossfade(targetState = high) { critical ->
                    val tone = if (critical > 0) Color(parseColor("#F44336")) else MaterialTheme.colorScheme.primary
                    Text(
                        text = "$critical críticos",
                        style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                        color = tone
                    )
                }
            }

            LinearProgressIndicator(
                progress = { highRatio },
                modifier = Modifier.fillMaxWidth(),
                color = Color(parseColor("#F44336")),
                trackColor = MaterialTheme.colorScheme.surfaceVariant
            )

            Spacer(Modifier.height(4.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                SummaryPill(label = "Alto", value = high, color = "#F44336")
                SummaryPill(label = "Medio", value = medium, color = "#FFC107")
                SummaryPill(label = "Bajo", value = low, color = "#4CAF50")
            }
        }
    }
}

@Composable
private fun SummaryPill(label: String, value: Int, color: String) {
    Text(
        text = "$label $value",
        style = MaterialTheme.typography.labelMedium,
        color = Color(parseColor(color))
    )
}