package com.clsoft.netguard.framework.di

import android.content.Context
import com.clsoft.netguard.framework.connectivity.ConnectivityObserver
import com.clsoft.netguard.framework.notification.NotificationHelper
import com.clsoft.netguard.framework.vpn.data.NativeFirewallManagerImpl
import com.clsoft.netguard.framework.vpn.domain.manager.NativeFirewallManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object FrameworkModule {

    @Provides
    @Singleton
    fun provideConnectivityObserver(@ApplicationContext context: Context): ConnectivityObserver =
        ConnectivityObserver(context)

    @Provides
    @Singleton
    fun provideNotificationHelper(@ApplicationContext context: Context): NotificationHelper =
        NotificationHelper(context)

    @Provides
    @Singleton
    fun provideNativeFirewallManager(): NativeFirewallManager = NativeFirewallManagerImpl()
}