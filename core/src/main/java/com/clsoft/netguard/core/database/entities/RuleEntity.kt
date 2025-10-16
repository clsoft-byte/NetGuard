package com.clsoft.netguard.core.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.clsoft.netguard.core.model.RuleAction

@Entity(tableName = "rules")
data class RuleEntity(
    @PrimaryKey val id: String,
    val appPackage: String?,
    val domain: String?,
    val ip: String?,
    val protocol: String?,
    val action: RuleAction,
    val createdAt: Long
)

