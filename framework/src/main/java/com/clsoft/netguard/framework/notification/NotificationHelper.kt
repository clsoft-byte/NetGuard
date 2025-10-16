package com.clsoft.netguard.framework.notification

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import com.clsoft.netguard.framework.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

/**
 * Builder simplificado para enviar notificaciones desde distintos módulos.
 */
class NotificationHelper @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    fun showNotification(
        channelId: String,
        title: String,
        message: String,
        notificationId: Int
    ) {
        val notification: Notification = NotificationCompat.Builder(context, channelId)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .build()

        manager.notify(notificationId, notification)
    }

    /**
     * Crea una notificación persistente para servicios en primer plano (foreground).
     */
    fun buildStatusNotification(): Notification {
        return NotificationCompat.Builder(context, ChannelConfig.TRAFFIC_CHANNEL_ID)
            .setContentTitle("NDK NetGuard activo")
            .setContentText("Monitoreando tráfico en segundo plano")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun cancelNotification(notificationId: Int) {
        manager.cancel(notificationId)
    }
}