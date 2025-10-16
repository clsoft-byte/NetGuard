package com.clsoft.netguard.engine.detector.di

import android.content.Context
import com.clsoft.netguard.engine.detector.api.TrafficDetector
import com.clsoft.netguard.engine.detector.tf.TFLiteTrafficDetector
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DetectorModule {

    @Provides
    @Singleton
    fun provideTrafficDetector(@ApplicationContext context: Context): TrafficDetector =
        TFLiteTrafficDetector(context)
}