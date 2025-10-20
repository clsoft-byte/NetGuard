package com.clsoft.netguard.features.traffic.monitor.data.mapper

import com.clsoft.netguard.core.database.entities.TrafficEntity
import com.clsoft.netguard.features.traffic.monitor.domain.model.Traffic

fun TrafficEntity.toDomain() : Traffic {
    return Traffic(
        id = id,
        appPackage = appPackage,
        bytesSent = bytesSent,
        bytesReceived = bytesReceived,
        timestamp = timestamp,
        sourceIp = sourceIp,
        destinationIp = destinationIp,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        protocol = protocol,
        blocked = blocked,
        riskScore = riskScore,
        riskLabel = riskLabel,
    )
}

fun Traffic.toEntity() : TrafficEntity {
    return TrafficEntity(
        id = id,
        appPackage = appPackage,
        bytesSent = bytesSent,
        bytesReceived = bytesReceived,
        timestamp = timestamp,
        sourceIp = sourceIp,
        destinationIp = destinationIp,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        protocol = protocol,
        blocked = blocked,
        riskScore = riskScore,
        riskLabel = riskLabel,
    )
}