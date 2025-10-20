package com.clsoft.netguard.features.traffic.monitor.service

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import com.clsoft.netguard.core.utils.Logger
import com.clsoft.netguard.engine.network.analyzer.NativeBridge
import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession
import com.clsoft.netguard.features.traffic.monitor.domain.model.toTraffic
import com.clsoft.netguard.features.traffic.monitor.domain.repository.TrafficRepository
import com.clsoft.netguard.framework.notification.ChannelConfig
import com.clsoft.netguard.framework.notification.NotificationHelper
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.FileInputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import kotlin.coroutines.coroutineContext

@AndroidEntryPoint
class NetGuardVpnService : VpnService() {

    @Inject lateinit var notificationHelper: NotificationHelper
    @Inject lateinit var trafficRepository: TrafficRepository

    private val vpnScopeRef = AtomicReference(createScope())
    private var vpnInterface: ParcelFileDescriptor? = null
    private var monitorJob: Job? = null
    @Volatile private var isRunning = false

    private val localVpnAddressV4: String by lazy { InetAddress.getByName(VPN_ADDRESS).hostAddress }
    private val localVpnAddressV6: String = "fd00:1:fd00::2" // misma que añadiste en Builder


    private val connectivityManager: ConnectivityManager? by lazy {
        getSystemService(ConnectivityManager::class.java)
    }

    private val connectionOwnerResolver: ConnectionOwnerResolver? by lazy {
        connectivityManager?.let { manager ->
            ConnectionOwnerResolver(manager, ::lookupPackageName)
        }
    }


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

                Logger.d("NetGuardVpnService", "Iniciando captura de tráfico real desde el túnel")
                isRunning = true
                vpnInterface = establishVPN()

                val scope = ensureScope()
                monitorJob = scope.launch {
                    captureVpnTraffic()
//                    captureTrafficLoop()
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun stopVpnService() {
        Logger.d("NetGuardVpnService", "Deteniendo servicio VPN")

        isRunning = false
        try {
            vpnInterface?.close()
            vpnInterface = null
            Logger.d("NetGuardVpnService", "Interfaz VPN liberada")
        } catch (e: Exception) {
            Logger.e("NetGuardVpnService", "Error al cerrar interfaz VPN", e)
        }

        runBlocking {
            monitorJob?.cancelAndJoin()
            vpnScopeRef.getAndSet(createScope()).cancel()
            monitorJob = null
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        Logger.d("NetGuardVpnService", "onDestroy() ejecutado (cleanup final)")
    }

    private fun establishVPN(): ParcelFileDescriptor? {
        Logger.d("NetGuardVpnService", "Configurando túnel VPN...")
        val builder = Builder()
            .setSession("NDK NetGuard VPN")
            .addAddress(VPN_ADDRESS, 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:1:fd00::2", 128)
            .addRoute("::", 0)

        return builder.establish().also {
            if (it != null)
                Logger.d("NetGuardVpnService", "VPN establecida correctamente")
            else
                Logger.e("NetGuardVpnService", "Error al establecer VPN")
        }
    }

    private suspend fun captureVpnTraffic() {
        val interfaceFd = vpnInterface ?: run {
            Logger.e("NetGuardVpnService", "Interfaz VPN no disponible para captura")
            isRunning = false
            return
        }

        val aggregator = TrafficSessionAggregator()
        val buffer = ByteArray(MAX_PACKET_SIZE)

        try {
            FileInputStream(interfaceFd.fileDescriptor).use { input ->
                Logger.d("NetGuardVpnService", "Captura iniciada: esperando paquetes del túnel")
                while (coroutineContext.isActive && isRunning) {
                    val length = try {
                        input.read(buffer)
                    } catch (ioe: IOException) {
                        if (coroutineContext.isActive && isRunning) {
                            Logger.e("NetGuardVpnService", "Error leyendo paquete", ioe)
                        }
                        break
                    }

                    if (length <= 0) {
                        continue
                    }

                    val rawPacket = buffer.copyOf(length)
                    val parsed = VpnPacketParser.parsePacket(rawPacket, rawPacket.size, localVpnAddressV4, localVpnAddressV6)
                    if (parsed == null) {
                        continue
                    }

                    val packageName = connectionOwnerResolver?.resolve(parsed)

                    try {
                        aggregator.register(parsed, rawPacket, packageName) { session ->
                            emitSession(session)
                        }
                    } catch (ce: CancellationException) {
                        throw ce
                    } catch (e: Exception) {
                        Logger.e("NetGuardVpnService", "Error emitiendo sesión agregada", e)
                    }
                }
            }
        } catch (ce: CancellationException) {
            Logger.d("NetGuardVpnService", "Captura cancelada")
            throw ce
        } finally {
            aggregator.flushAll { session ->
                try {
                    emitSession(session)
                } catch (ce: CancellationException) {
                    throw ce
                } catch (e: Exception) {
                    Logger.e("NetGuardVpnService", "Error finalizando emisión de sesión", e)
                }
            }
            Logger.d("NetGuardVpnService", "Captura finalizada")
        }
    }
    private suspend fun emitSession(session: TrafficSession) {
        try {
            trafficRepository.saveOrUpdateTraffic(session.toTraffic())
        } catch (e: Exception) {
            Logger.e("NetGuardVpnService", "No se pudo persistir el tráfico", e)
        }

        try {
            TrafficSessionManager.onNewSessionDetected(this@NetGuardVpnService, session)
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            Logger.e("NetGuardVpnService", "Error notificando nueva sesión", e)
        }
    }

    private fun lookupPackageName(uid: Int): String? {
        val directName = runCatching { packageManager.getNameForUid(uid) }.getOrNull()
        if (!directName.isNullOrBlank()) {
            return directName
        }

        val candidates = runCatching { packageManager.getPackagesForUid(uid) }.getOrNull()
        return candidates?.firstOrNull()
    }

    private fun createScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun ensureScope(): CoroutineScope {
        val current = vpnScopeRef.get()
        return if (current.isActive) {
            current
        } else {
            val newScope = createScope()
            vpnScopeRef.set(newScope)
            newScope
        }
    }

    companion object {
        private const val ACTION_STOP = "com.ndk.netguard.STOP"
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val MAX_PACKET_SIZE = 32_768

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
