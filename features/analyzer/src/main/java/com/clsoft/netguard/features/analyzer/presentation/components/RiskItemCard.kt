package com.clsoft.netguard.features.analyzer.presentation.components

import android.graphics.Color.parseColor
import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import kotlin.math.roundToInt

@Composable
fun RiskItemCard(
    risk: TrafficRisk,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val riskColor = Color(parseColor(risk.riskLevel.colorHex))
    val bytesSummary = Formatter.formatFileSize(context, risk.bytesSent + risk.bytesReceived)

    Card(modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(risk.appPackage, style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Destino ${risk.destinationIp}:${risk.destinationPort}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                AssistChip(
                    onClick = {},
                    enabled = false,
                    shape = MaterialTheme.shapes.large,
                    label = {
                        Text(
                            text = risk.riskLevel.label.uppercase(),
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold)
                        )
                    },
                    colors = AssistChipDefaults.assistChipColors(
                        disabledContainerColor = riskColor.copy(alpha = 0.12f),
                        disabledLabelColor = riskColor
                    )
                )
            }

            Text(
                text = risk.description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(Modifier.height(4.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "${(risk.riskScore * 100).roundToInt()}% de riesgo",
                    style = MaterialTheme.typography.bodySmall,
                    color = riskColor
                )
                Text(
                    text = bytesSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = risk.protocol,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}