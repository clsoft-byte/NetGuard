package com.clsoft.netguard.core.database.dao


import androidx.room.*
import com.clsoft.netguard.core.database.entities.DetectionEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface DetectionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDetection(detection: DetectionEntity)

    @Query("SELECT * FROM detection ORDER BY timestamp DESC")
    fun getDetections(): Flow<List<DetectionEntity>>

    @Query("SELECT * FROM detection ORDER BY timestamp DESC LIMIT 5")
    fun observeRecentDetections(): Flow<List<DetectionEntity>>
    @Query("DELETE FROM detection")
    suspend fun clearAll()
}