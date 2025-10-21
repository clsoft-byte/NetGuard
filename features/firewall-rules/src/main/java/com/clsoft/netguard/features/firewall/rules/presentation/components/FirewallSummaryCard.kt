package com.clsoft.netguard.features.firewall.rules.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.firewall.rules.presentation.screen.FirewallPalette

@Composable
fun FirewallSummaryCard(
    isEnabled: Boolean,
    totalRules: Int,
    allowedRules: Int,
    blockedRules: Int,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .background(FirewallPalette.CardBackground, RoundedCornerShape(20.dp)),
        color = FirewallPalette.CardBackground,
        shape = RoundedCornerShape(20.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 18.dp)
        ) {
            Text(
                text = "Estado del Firewall",
                color = FirewallPalette.TextSecondary,
                style = MaterialTheme.typography.labelMedium
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = if (isEnabled) "Activo" else "Desactivado desde Dashboard",
                color = if (isEnabled) FirewallPalette.Success else FirewallPalette.Warning,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SummaryChip(label = "Reglas", value = totalRules.toString())
                SummaryChip(label = "Permitidas", value = allowedRules.toString())
                SummaryChip(label = "Bloqueadas", value = blockedRules.toString())
            }
        }
    }
}

@Composable
private fun SummaryChip(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            color = FirewallPalette.TextPrimary,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = label,
            color = FirewallPalette.TextSecondary,
            style = MaterialTheme.typography.bodySmall
        )
    }
}