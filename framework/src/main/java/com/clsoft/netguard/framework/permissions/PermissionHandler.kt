package com.clsoft.netguard.framework.permissions


import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import androidx.activity.result.ActivityResultLauncher
import androidx.core.content.ContextCompat

/**
 * Manejador central de permisos en tiempo de ejecución.
 * Permite solicitar permisos de manera segura y reutilizable.
 */
class PermissionHandler(
    private val activity: Activity,
    private val permissionLauncher: ActivityResultLauncher<String>
) {

    fun hasPermission(permission: String): Boolean {
        return ContextCompat.checkSelfPermission(activity, permission) == PackageManager.PERMISSION_GRANTED
    }

    fun requestPermission(permission: String) {
        if (!hasPermission(permission)) {
            permissionLauncher.launch(permission)
        }
    }

    fun hasNotificationPermission(): Boolean {
        return hasPermission(Manifest.permission.POST_NOTIFICATIONS)
    }

    fun requestNotificationPermission() {
        requestPermission(Manifest.permission.POST_NOTIFICATIONS)
    }
}