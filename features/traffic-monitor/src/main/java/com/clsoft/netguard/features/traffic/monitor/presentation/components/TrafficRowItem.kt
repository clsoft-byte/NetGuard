package com.clsoft.netguard.features.traffic.monitor.presentation.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.clsoft.netguard.core.utils.FormatUtils
import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession

@Composable
fun TrafficRowItem(session: TrafficSession) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(session.appPackage, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(2.dp))
            Text("${session.protocol} ${session.sourceIp} → ${session.destinationIp}")
            Text(
                "↑ ${FormatUtils.formatBytes(session.bytesSent)}  ↓ ${FormatUtils.formatBytes(session.bytesReceived)}",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}