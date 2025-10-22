package com.clsoft.netguard.core.di

import android.content.Context
import androidx.room.Room
import com.clsoft.netguard.core.database.NetGuardDatabase
import com.clsoft.netguard.core.database.dao.AnalyzerDao
import com.clsoft.netguard.core.database.dao.DetectionDao
import com.clsoft.netguard.core.database.dao.RuleDao
import com.clsoft.netguard.core.database.dao.TrafficDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): NetGuardDatabase {
        return Room.databaseBuilder(
            context,
            NetGuardDatabase::class.java,
            "netguard_db",
        ).fallbackToDestructiveMigration().build()
    }

    @Provides
    @Singleton
    fun provideTrafficDao(appDatabase: NetGuardDatabase): TrafficDao = appDatabase.trafficDao()

    @Provides
    @Singleton
    fun provideRuleDao(appDatabase: NetGuardDatabase): RuleDao = appDatabase.ruleDao()

    @Provides
    @Singleton
    fun provideDetectionDao(appDatabase: NetGuardDatabase): DetectionDao = appDatabase.detectionDao()

    @Provides
    @Singleton
    fun provideAnalyzerDao(appDatabase: NetGuardDatabase): AnalyzerDao = appDatabase.analyzerDao()

}