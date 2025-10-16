package com.clsoft.netguard.framework.connectivity

/**
 * Representa el estado de red actual de la app.
 */
sealed class NetworkState {
    object Available : NetworkState()
    object Unavailable : NetworkState()
    object Losing : NetworkState()
    object Lost : NetworkState()
}