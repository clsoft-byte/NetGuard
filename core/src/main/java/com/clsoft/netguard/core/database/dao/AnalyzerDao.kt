package com.clsoft.netguard.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.clsoft.netguard.core.database.entities.AnalysisResultEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AnalyzerDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertResult(result: AnalysisResultEntity)

    @Query("SELECT * FROM analysis_result ORDER BY timestamp DESC")
    fun observeResults(): Flow<List<AnalysisResultEntity>>

    @Query("DELETE FROM analysis_result")
    suspend fun clear()
}
