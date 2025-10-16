package com.clsoft.netguard.core.database

import androidx.room.Database
import androidx.room.RoomDatabase
import com.clsoft.netguard.core.database.dao.*
import com.clsoft.netguard.core.database.entities.*

@Database(
    entities = [TrafficEntity::class, RuleEntity::class, DetectionEntity::class],
    version = 1,
    exportSchema = false
)
abstract class NetGuardDatabase : RoomDatabase() {
    abstract fun trafficDao(): TrafficDao
    abstract fun ruleDao(): RuleDao
    abstract fun detectionDao(): DetectionDao
}