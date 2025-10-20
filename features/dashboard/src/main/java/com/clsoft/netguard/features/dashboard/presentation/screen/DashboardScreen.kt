package com.clsoft.netguard.features.dashboard.presentation.screen

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.clsoft.netguard.features.dashboard.presentation.DashboardViewModel
import com.clsoft.netguard.features.dashboard.presentation.components.FirewallSwitchCard
import com.clsoft.netguard.features.dashboard.presentation.contract.DashboardEvent
import java.util.concurrent.TimeUnit

@Composable
fun DashboardScreen(
    navController: NavController,
    viewModel: DashboardViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {

        // ─── Header ────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Traffic Monitor",
                color = MaterialTheme.colorScheme.onBackground,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        }

        FirewallSwitchCard(
            isEnabled = state.data.firewallEnabled,
            onToggle = { viewModel.onEvent(DashboardEvent.ToggleFirewall(it)) }
        )

        // ─── Network Overview ───────────────────────
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        )
        {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Network Overview",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceAround,
                    verticalAlignment = Alignment.CenterVertically
                )
                {
                    val totalSent = state.data.totalSent
                    val totalReceived = state.data.totalReceived
                    val total = totalSent + totalReceived
                    NetworkOverview(totalSent.toMB(), totalReceived.toMB())
                    // Circular chart
//                    Box(
//                        contentAlignment = Alignment.Center,
//                        modifier = Modifier.size(120.dp)
//                    ) {
//                        Canvas(modifier = Modifier.size(120.dp)) {
//                            drawArc(
//                                color = Color(0xFF007AFF),
//                                startAngle = -90f,
//                                sweepAngle = 220f,
//                                useCenter = false,
//                                style = Stroke(width = 14f, cap = StrokeCap.Round)
//                            )
//                            drawArc(
//                                color = Color(0xFF5AC8FA),
//                                startAngle = 130f,
//                                sweepAngle = 110f,
//                                useCenter = false,
//                                style = Stroke(width = 14f, cap = StrokeCap.Round)
//                            )
//                        }
//                        Text(
//                            text = "${formatMb(total)} MB",
//                            color = Color.White,
//                            fontWeight = FontWeight.Bold
//                        )
//                    }

                    Column(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(20.dp)
                    ) {

                        MetricRow("Total", "${formatMb(total)} MB")
                        MetricRow("Sent", "${formatMb(totalSent)} MB")
                        MetricRow("Received", "${formatMb(totalReceived)} MB")
                    }
                }
            }
        }

        // ─── Security Insights ─────────────────────
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = "Security Insights",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold
                )
                state.data?.detections?.forEach { detection ->
                    RiskRow(
                        riskLevel = detection.riskLevel,
                        appName = detection.appName,
                        riskType = detection.riskType
                    )
                }
            }
        }

        // ─── Last Session ──────────────────────────
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val last = state.data?.lastSession
                Text("Last Session")
                if (last != null) {
                    Text("${formatDuration(last.timestamp)} • ${formatMb(last.bytesReceived)} MB")
                } else {
                    Text("--- --- • --- MB")
                }
            }
        }
    }
}

@Composable
private fun MetricRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = Color.Gray)
        Text(value, color = Color.White, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun RiskRow(riskLevel: String, appName: String, riskType: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(riskLevel, color = if(riskLevel == "Low Risk") Color(0xFF5AC8FA) else Color(0xFFFF6B6B), fontWeight = FontWeight.Bold)
            Text(appName, color = Color.Gray, fontSize = 13.sp)
        }
        Text(riskType, color = Color.White, fontWeight = FontWeight.Medium)
    }
}

@Composable
fun NetworkOverview(
    sentMb: Float,
    receivedMb: Float
) {
    val totalMb = sentMb + receivedMb
    val sentPercent = if (totalMb > 0) sentMb / totalMb else 0f
    val receivedPercent = if (totalMb > 0) receivedMb / totalMb else 0f
    val sentSweep = sentPercent * 360f
    val receivedSweep = receivedPercent * 360f
    val animatedSentSweep by animateFloatAsState(targetValue = sentSweep, label = "sentSweep")
    val animatedReceivedSweep by animateFloatAsState(targetValue = receivedSweep, label = "receivedSweep")

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(120.dp)
    ) {
        Canvas(modifier = Modifier.size(120.dp)) {
            // Fondo (track)
            drawArc(
                color = Color(0xFF2C2C2E),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                style = Stroke(width = 14f, cap = StrokeCap.Round)
            )

            // Tráfico enviado (azul fuerte)
            drawArc(
                color = Color(0xFF007AFF),
                startAngle = -90f,
                sweepAngle = animatedSentSweep,
                useCenter = false,
                style = Stroke(width = 14f, cap = StrokeCap.Round)
            )

            // Tráfico recibido (celeste, inicia donde termina el enviado)
            drawArc(
                color = Color(0xFF5AC8FA),
                startAngle = -90f + sentSweep,
                sweepAngle = animatedReceivedSweep,
                useCenter = false,
                style = Stroke(width = 14f, cap = StrokeCap.Round)
            )
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = String.format("%.2f MB", totalMb),
                style = MaterialTheme.typography.titleMedium,
                color = Color.White
            )
            Text(
                text = "Total",
                style = MaterialTheme.typography.bodySmall,
                color = Color.Gray
            )
        }
    }
}
fun formatMb(bytes: Long): String = "%.2f".format(bytes / (1024f * 1024f))
fun Long.toMB(): Float = this / (1024f * 1024f)


fun formatDuration(durationMillis: Long): String {
    if (durationMillis <= 0) return "---"

    val hours = TimeUnit.MILLISECONDS.toHours(durationMillis)
    val minutes = TimeUnit.MILLISECONDS.toMinutes(durationMillis) % 60
    val seconds = TimeUnit.MILLISECONDS.toSeconds(durationMillis) % 60

    return buildString {
        if (hours > 0) append("${hours}h ")
        if (minutes > 0 || hours > 0) append("${minutes}m ")
        append("${seconds}s")
    }.trim()
}