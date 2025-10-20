package com.clsoft.netguard.features.traffic.monitor.presentation.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic
import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession
import com.clsoft.netguard.features.traffic.monitor.presentation.TrafficMonitorViewModel
import com.clsoft.netguard.features.traffic.monitor.presentation.components.LiveTrafficList
import com.clsoft.netguard.features.traffic.monitor.presentation.contract.TrafficMonitorEvent
import kotlin.collections.filter

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficMonitorScreen(
    navController: NavController,
    viewModel: TrafficMonitorViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    var query by remember { mutableStateOf("") }
    val filtered = remember(state.sessions, query) {
        if (query.isBlank()) state.sessions
        else state.sessions.filter {
            it.appPackage.contains(query, ignoreCase = true) ||
                    it.sourceIp.contains(query, ignoreCase = true)
        }
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            background = Bg,
            surface = CardBg,
            onSurface = TextPrimary,
            onBackground = TextPrimary
        )
    ) {
        Scaffold(
            containerColor = Bg,
            topBar = {
                TopAppBar(
                    title = { Text("Traffic Monitor", color = TextPrimary) },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Bg)
                )
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .background(Bg)
            ) {
                // Search bar
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("Search", color = TextSecondary) },
                    leadingIcon = {
                        Icon(Icons.Rounded.Search, contentDescription = null, tint = TextSecondary)
                    },
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .fillMaxWidth()
                        .height(52.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(SearchBg),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = SearchBg,
                        unfocusedContainerColor = SearchBg,
                        focusedBorderColor = Color.Transparent,
                        unfocusedBorderColor = Color.Transparent,
                        cursorColor = TextPrimary,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(color = TextPrimary)
                )

                // Card container (como en el mock)
                Surface(
                    color = CardBg,
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .padding(horizontal = 16.dp)
                        .fillMaxWidth()
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(CardBg)
                    ) {
                        items(filtered, key = { it.id }) { row ->
                            TrafficItemRow(
                                item = row,
                                onClick = {viewModel.onEvent(TrafficMonitorEvent.onEditTrafficSession(row))}
                            )
                            Divider(
                                color = DividerColor,
                                thickness = 1.dp,
                                modifier = Modifier.padding(start = 84.dp) // alineado tras el icono
                            )
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun TrafficItemRow(
    item: Traffic,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(RowBg)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Icono (48dp redondeado, como en el diseño)
        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF1C2330)),
            contentAlignment = Alignment.Center
        ) {
            // Si tienes recursos, descomenta:
            // item.iconRes?.let {
            //     Image(
            //         painter = painterResource(id = it),
            //         contentDescription = item.appName,
            //         modifier = Modifier.fillMaxSize().padding(6.dp),
            //         contentScale = ContentScale.Fit
            //     )
            // } ?: run {
            Text(
                text = item.appPackage.firstOrNull()?.uppercase() ?: "A",
                color = TextSecondary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            // }
        }

        Spacer(Modifier.width(16.dp))

        Column(
            modifier = Modifier.weight(1f)
        ) {
            Text(
                text = item.appPackage,
                color = TextPrimary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "${item.destinationIp}:${item.destinationPort}",
                color = TextSecondary,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Clip
            )
        }

        Spacer(Modifier.width(12.dp))

        Column(horizontalAlignment = Alignment.End) {
            val statusColor = when (item.riskLabel) {
                "High" -> MediumColor
                "Medium" -> MediumColor
                "Low" -> LowColor
                else -> MediumColor
            }
            Text(
                text = item.riskLabel?: "",
                color = statusColor,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = formatBytes(item.bytesSent + item.bytesReceived),
                color = TextSecondary,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}


private fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "0 KB"
    val kb = bytes / 1024.0
    if (kb < 1024) return "${kb.toInt()} KB"
    val mb = kb / 1024.0
    return String.format("%.1f MB", mb)
}

private val Bg = Color(0xFF0E1116)         // fondo raíz
private val CardBg = Color(0xFF151922)      // contenedores
private val RowBg = Color(0xFF0F141B)       // fila
private val DividerColor = Color(0x1FFFFFFF)
private val TextPrimary = Color(0xFFEAEFF7)
private val TextSecondary = Color(0xFF9AA5B1)
private val LowColor = Color(0xFF7ED957) // verde suave
private val MediumColor = Color(0xAEFF9800) // rojo suave
private val SearchBg = Color(0xFF0F141B)