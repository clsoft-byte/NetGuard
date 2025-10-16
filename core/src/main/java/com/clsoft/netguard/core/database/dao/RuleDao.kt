package com.clsoft.netguard.core.database.dao

import androidx.room.*
import com.clsoft.netguard.core.database.entities.RuleEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface RuleDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRule(rule: RuleEntity)

    @Query("SELECT * FROM rules")
    fun getRules(): Flow<List<RuleEntity>>

    @Delete
    suspend fun deleteRule(rule: RuleEntity)
}