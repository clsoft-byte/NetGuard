package com.clsoft.netguard.core.data.repository

interface BaseRepository<T> {
    /**
     * Inserta o actualiza un objeto en el repositorio.
     */
    suspend fun upsert(item: T)

    /**
     * Elimina un objeto del repositorio.
     */
    suspend fun delete(item: T)

    /**
     * Retorna todos los objetos en forma de flujo (Flow)
     */
    suspend fun getAll(): kotlinx.coroutines.flow.Flow<List<T>>
}