package com.clsoft.netguard.framework.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

/**
 * Crea y gestiona los canales de notificaciones requeridos por la app.
 */
object ChannelConfig {
    const val FIREWALL_CHANNEL_ID = "firewall_status_channel"
    const val TRAFFIC_CHANNEL_ID = "traffic_monitor_channel"

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val firewallChannel = NotificationChannel(
                FIREWALL_CHANNEL_ID,
                "Firewall Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Notificaciones sobre el estado del firewall"
            }

            val trafficChannel = NotificationChannel(
                TRAFFIC_CHANNEL_ID,
                "Traffic Monitor",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Actividad de monitoreo de tráfico en tiempo real"
            }

            val manager = context.getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(firewallChannel)
            manager?.createNotificationChannel(trafficChannel)
        }
    }
}