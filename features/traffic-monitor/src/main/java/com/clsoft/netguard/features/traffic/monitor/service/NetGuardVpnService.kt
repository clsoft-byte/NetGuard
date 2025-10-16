package com.clsoft.netguard.features.traffic.monitor.service

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import com.clsoft.netguard.core.utils.Logger
import com.clsoft.netguard.framework.notification.ChannelConfig
import com.clsoft.netguard.framework.notification.NotificationHelper
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import javax.inject.Inject

@AndroidEntryPoint
class NetGuardVpnService : VpnService() {

    @Inject lateinit var notificationHelper: NotificationHelper

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var monitorJob: Job? = null
    @Volatile private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        ChannelConfig.createChannels(this)
        Logger.d("NetGuardVpnService", "Servicio creado")

        val notification = notificationHelper.buildStatusNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                1,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(1, notification)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                Logger.d("NetGuardVpnService", "Recibida acción STOP")
                stopVpnService()
                return START_NOT_STICKY
            }

            else -> {
                if (isRunning) {
                    Logger.d("NetGuardVpnService", "Servicio ya en ejecución, ignorando nuevo inicio")
                    return START_NOT_STICKY
                }

                Logger.d("NetGuardVpnService", "Iniciando simulación de tráfico")
                isRunning = true
                vpnInterface = establishVPN()

                monitorJob = serviceScope.launch {
                    try {
                        Logger.d("NetGuardVpnService", "Simulación de tráfico iniciada")
                        while (isActive && isRunning) {
                            delay(2000)
                            if (!isActive || !isRunning) break

                            val session = TrafficSessionManager.mockSession()
                            try {
                                TrafficSessionManager.onNewSessionDetected(
                                    this@NetGuardVpnService, session
                                )
                            } catch (ce: CancellationException) {
                                Logger.d("NetGuardVpnService", "Emisión cancelada")
                                break
                            } catch (e: Exception) {
                                Logger.e("NetGuardVpnService", "Error emitiendo sesión", e)
                            }
                        }
                    } catch (ce: CancellationException) {
                        Logger.d("NetGuardVpnService", "Monitor cancelado")
                    } finally {
                        Logger.d("NetGuardVpnService", "Monitor terminado")
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun stopVpnService() {
        Logger.d("NetGuardVpnService", "Deteniendo servicio VPN internamente")

        isRunning = false

        // Cierra el túnel ANTES de cancelar coroutines
        try {
            vpnInterface?.close()
            vpnInterface = null
            Logger.d("NetGuardVpnService", "Interfaz VPN liberada")
        } catch (e: Exception) {
            Logger.e("NetGuardVpnService", "Error al cerrar interfaz VPN", e)
        }

        runBlocking {
            monitorJob?.cancelAndJoin()
            serviceScope.cancel()
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Logger.d("NetGuardVpnService", "Servicio detenido completamente")
    }

    override fun onDestroy() {
        super.onDestroy()
        Logger.d("NetGuardVpnService", "onDestroy() ejecutado (cleanup final)")
    }

    private fun establishVPN(): ParcelFileDescriptor? {
        Logger.d("NetGuardVpnService", "Configurando túnel VPN...")
        val builder = Builder()
            .setSession("NDK NetGuard VPN")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)

        return builder.establish().also {
            if (it != null)
                Logger.d("NetGuardVpnService", "VPN establecida correctamente")
            else
                Logger.e("NetGuardVpnService", "Error al establecer VPN")
        }
    }

    companion object {
        private const val ACTION_STOP = "com.ndk.netguard.STOP"

        fun start(ctx: Context) {
            Logger.d("NetGuardVpnService", "Iniciando servicio VPN")
            val intent = Intent(ctx, NetGuardVpnService::class.java)
            ContextCompat.startForegroundService(ctx, intent)
        }

        fun stop(ctx: Context) {
            Logger.d("NetGuardVpnService", "Deteniendo servicio VPN (solicitado por app)")
            val stopIntent = Intent(ctx, NetGuardVpnService::class.java).apply {
                action = ACTION_STOP
            }
            ContextCompat.startForegroundService(ctx, stopIntent)
        }
    }
}
