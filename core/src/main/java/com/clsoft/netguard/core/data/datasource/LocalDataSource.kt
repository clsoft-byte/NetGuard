package com.clsoft.netguard.core.data.datasource

interface LocalDataSource<T> {
    suspend fun insert(item: T)
    suspend fun delete(item: T)
    suspend fun getAll(): kotlinx.coroutines.flow.Flow<List<T>>
}