package com.clsoft.netguard.features.traffic.monitor.service

import android.content.Context
import com.clsoft.netguard.core.utils.Logger
import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession
import com.clsoft.netguard.framework.notification.ChannelConfig
import com.clsoft.netguard.framework.notification.NotificationHelper
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.json.JSONObject
import java.util.Locale
import java.util.UUID
import kotlin.random.Random

/**
 * Gestiona las sesiones de tráfico detectadas por el VPNService.
 * Por ahora, puede generar sesiones mock para pruebas locales.
 */
object TrafficSessionManager {
    private const val UNKNOWN_APP = "unknown"

    private val _sessionsFlow = MutableSharedFlow<TrafficSession>(replay = 0)
    val sessionsFlow = _sessionsFlow.asSharedFlow()

    /**
     * Se invoca cuando se detecta una nueva sesión (real o simulada).
     */
    suspend fun onNewSessionDetected(context: Context, session: TrafficSession) {
        Logger.d("TrafficSessionManager", "Nueva sesión detectada: $session")

        // Emitir sesión al flujo para que la UI la reciba
        _sessionsFlow.emit(session)

        val shouldAlert = session.destinationIp == "8.8.8.8" ||
                session.riskLabel?.equals("High", ignoreCase = true) == true

        if (shouldAlert) {
            val helper = NotificationHelper(context)
            val appName = session.appPackage.takeIf { it.isNotBlank() && it != UNKNOWN_APP }
                ?: "una app"
            helper.showNotification(
                channelId = ChannelConfig.TRAFFIC_CHANNEL_ID,
                title = "Tráfico inusual detectado",
                message = buildString {
                    append("La app $appName se conectó a ${session.destinationIp}")
                    session.riskLabel?.let { label ->
                        append(" (riesgo $label")
                        if (session.riskScore > 0f) {
                            append(String.format(Locale.US, " %.0f%%", session.riskScore * 100f))
                        }
                        append(')')
                    }
                },
                notificationId = Random.nextInt(1000, 9999)
            )
        }
    }

    fun buildFromJson(obj: JSONObject): TrafficSession {
        return TrafficSession(
            id = UUID.randomUUID().toString(),
            appPackage = "unknown",
            sourceIp = obj.optString("src", ""),
            destinationIp = obj.optString("dst", ""),
            protocol = obj.optString("proto", ""),
            bytesSent = obj.optLong("bytes", 0L),
            bytesReceived = 0L,
            timestamp = System.currentTimeMillis()
        )
    }

    /**
     * Genera tráfico simulado para pruebas y desarrollo sin NDK.
     */
    fun mockSession(): TrafficSession {
        val destinations = listOf(
            "8.8.8.8",          // Google DNS (sospechoso)
            "1.1.1.1",          // Cloudflare
            "172.217.10.14",    // Google
            "104.244.42.129",   // Twitter
            "142.250.190.78"    // YouTube
        )

        val apps = listOf(
            "com.whatsapp",
            "com.instagram.android",
            "com.google.chrome",
            "com.tiktok.android",
            "com.spotify.music"
        )

        return TrafficSession(
            id = UUID.randomUUID().toString(),
            appPackage = apps.random(),
            sourceIp = "192.168.1.${Random.nextInt(2, 200)}",
            destinationIp = destinations.random(),
            protocol = listOf("TCP", "UDP").random(),
            bytesSent = Random.nextLong(10_000, 5_000_000),
            bytesReceived = Random.nextLong(10_000, 10_000_000),
            timestamp = System.currentTimeMillis()
        )
    }
}