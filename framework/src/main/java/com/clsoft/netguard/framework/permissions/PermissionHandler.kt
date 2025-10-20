package com.clsoft.netguard.framework.permissions


import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

/**
 * Manejador central de permisos en tiempo de ejecución.
 * Permite solicitar permisos de manera segura y reutilizable.
 */
class PermissionHandler(
    private val activity: ComponentActivity,
    private val onResult: (Boolean) -> Unit
) {
    private val launcher = activity.registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> onResult(granted) }

    fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) {
            onResult(true); return
        }
        val perm = Manifest.permission.POST_NOTIFICATIONS
        if (ContextCompat.checkSelfPermission(activity, perm)
            == PackageManager.PERMISSION_GRANTED) {
            onResult(true)
        } else {
            launcher.launch(perm)
        }
    }
}
