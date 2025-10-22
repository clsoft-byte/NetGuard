package com.clsoft.netguard.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.clsoft.netguard.core.database.entities.TrafficEntity
import com.clsoft.netguard.core.database.entities.TrafficSummary
import kotlinx.coroutines.flow.Flow

@Dao
interface TrafficDao {
    @Query("""
        SELECT * FROM traffic 
        WHERE sourceIp = :srcIp 
        AND destinationIp = :dstIp 
        AND protocol = :protocol 
        AND destinationPort = :dstPort
        LIMIT 1
    """)
    suspend fun findActiveSession(
        srcIp: String,
        dstIp: String,
        protocol: String,
        dstPort: Int
    ): TrafficEntity?

    @Query("SELECT * FROM traffic ORDER BY timestamp DESC")
    fun observeTraffic(): Flow<List<TrafficEntity>>


    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTraffic(entity: TrafficEntity)

    @Update
    suspend fun updateTraffic(entity: TrafficEntity)

    @Query("SELECT SUM(bytesSent + bytesReceived) FROM traffic")
    fun getTotalTraffic(): Flow<Long>

    @Query("SELECT SUM(bytesSent) AS totalSent, SUM(bytesReceived) AS totalReceived FROM traffic")
    fun observeTotalTraffic(): Flow<TrafficSummary>

    @Query("SELECT COUNT(*) FROM traffic WHERE blocked = 1")
    fun getBlockedConnections(): Flow<Int>

    @Query("SELECT COUNT(*) FROM traffic WHERE timestamp > :since")
    fun getDetectionsSince(since: Long): Flow<Int>

    @Query("SELECT MAX(timestamp) FROM traffic")
    fun getLastScanTime(): Flow<Long?>

    @Query("SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 1")
    fun observeLastSession(): Flow<TrafficEntity?>

    @Query(
        """
        SELECT * FROM traffic
        WHERE appPackage = :appPackage AND destinationIp = :destinationIp
        ORDER BY timestamp DESC
        LIMIT 1
        """
    )
    suspend fun findLatestByAppAndDestination(
        appPackage: String,
        destinationIp: String
    ): TrafficEntity?
}