package com.clsoft.netguard.core.database

import androidx.room.Database
import androidx.room.RoomDatabase
import com.clsoft.netguard.core.database.dao.*
import com.clsoft.netguard.core.database.entities.*

@Database(
    entities = [
        TrafficEntity::class,
        RuleEntity::class,
        DetectionEntity::class,
        AnalysisResultEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class NetGuardDatabase : RoomDatabase() {
    abstract fun trafficDao(): TrafficDao
    abstract fun ruleDao(): RuleDao
    abstract fun detectionDao(): DetectionDao
    abstract fun analyzerDao(): AnalyzerDao
}