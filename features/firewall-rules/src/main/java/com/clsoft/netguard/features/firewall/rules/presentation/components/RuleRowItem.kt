package com.clsoft.netguard.features.firewall.rules.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.features.firewall.rules.domain.model.FirewallRule
import com.clsoft.netguard.features.firewall.rules.presentation.screen.FirewallPalette

@Composable
fun RuleRowItem(
    rule: FirewallRule,
    onToggle: () -> Unit,
    onRemove: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp)),
        color = FirewallPalette.CardBackground,
        tonalElevation = 0.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(FirewallPalette.CardBackground)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Avatar(rule.appName)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = rule.appName,
                    color = FirewallPalette.TextPrimary,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.size(4.dp))
                Text(
                    text = rule.appPackage,
                    color = FirewallPalette.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            StatusPill(isAllowed = rule.isAllowed)
            Switch(
                checked = rule.isAllowed,
                onCheckedChange = { onToggle() },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = FirewallPalette.Success,
                    checkedTrackColor = FirewallPalette.Success.copy(alpha = 0.3f),
                    uncheckedThumbColor = FirewallPalette.Warning,
                    uncheckedTrackColor = FirewallPalette.Warning.copy(alpha = 0.3f)
                )
            )
            IconButton(onClick = onRemove) {
                Icon(
                    imageVector = Icons.Rounded.Delete,
                    contentDescription = "Eliminar regla",
                    tint = FirewallPalette.TextSecondary
                )
            }
        }
    }
}

@Composable
private fun Avatar(label: String) {
    val char = label.firstOrNull()?.uppercaseChar() ?: 'A'
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(FirewallPalette.RowBackground),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = char.toString(),
            color = FirewallPalette.TextSecondary,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun StatusPill(isAllowed: Boolean) {
    val background = if (isAllowed) FirewallPalette.Success.copy(alpha = 0.15f) else FirewallPalette.Warning.copy(alpha = 0.15f)
    val textColor = if (isAllowed) FirewallPalette.Success else FirewallPalette.Warning
    val label = if (isAllowed) "Permitido" else "Bloqueado"
    Text(
        text = label,
        color = textColor,
        style = MaterialTheme.typography.labelMedium,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(background)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    )
}