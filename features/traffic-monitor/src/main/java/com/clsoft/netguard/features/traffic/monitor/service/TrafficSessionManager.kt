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
}