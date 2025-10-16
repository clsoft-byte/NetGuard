package com.clsoft.netguard.features.traffic.monitor.presentation.components

import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import com.clsoft.netguard.features.traffic.monitor.domain.model.TrafficSession

@Composable
fun LiveTrafficList(sessions: List<TrafficSession>) {
    LazyColumn {
        items(sessions) { session ->
            TrafficRowItem(session)
        }
    }
}