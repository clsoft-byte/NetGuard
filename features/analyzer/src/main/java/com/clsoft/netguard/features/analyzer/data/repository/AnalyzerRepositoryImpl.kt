package com.clsoft.netguard.features.analyzer.data.repository

import com.clsoft.netguard.core.database.dao.AnalyzerDao
import com.clsoft.netguard.core.database.dao.TrafficDao
import com.clsoft.netguard.core.database.entities.AnalysisResultEntity
import com.clsoft.netguard.core.database.entities.TrafficEntity
import com.clsoft.netguard.features.analyzer.domain.model.RiskAssessment
import com.clsoft.netguard.features.analyzer.domain.model.RiskLevel
import com.clsoft.netguard.features.analyzer.domain.model.TrafficRisk
import com.clsoft.netguard.features.analyzer.domain.repository.AnalyzerRepository
import com.clsoft.netguard.features.analyzer.domain.usecase.ClassifyRiskUseCase
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.util.UUID
import javax.inject.Inject

class AnalyzerRepositoryImpl @Inject constructor(
    private val trafficDao: TrafficDao,
    private val analyzerDao: AnalyzerDao,
    private val classifyRisk: ClassifyRiskUseCase
) : AnalyzerRepository {

    override suspend fun analyze(appPackage: String, destinationIp: String): TrafficRisk {
        val session = trafficDao.findLatestByAppAndDestination(appPackage, destinationIp)
            ?: throw MissingTrafficDataException(appPackage, destinationIp)

        val now = System.currentTimeMillis()
        val assessment = classifyRisk(
            bytesSent = session.bytesSent,
            bytesReceived = session.bytesReceived,
            protocol = session.protocol,
            destinationIp = session.destinationIp,
            now = now
        )

        val risk = TrafficRisk(
            id = UUID.randomUUID().toString(),
            appPackage = session.appPackage,
            destinationIp = session.destinationIp,
            riskLevel = assessment.level,
            riskScore = assessment.score,
            description = buildDescription(assessment.level, session),
            timestamp = now,
            bytesSent = session.bytesSent,
            bytesReceived = session.bytesReceived,
            protocol = session.protocol,
            destinationPort = session.destinationPort
        )

        persistResult(risk)
        updateTrafficRisk(session, assessment)

        return risk
    }

    override fun getHistory(): Flow<List<TrafficRisk>> {
        return analyzerDao.observeResults().map { entities ->
            entities.map { it.toDomain() }
        }
    }

    private suspend fun persistResult(risk: TrafficRisk) {
        val entity = AnalysisResultEntity(
            appPackage = risk.appPackage,
            destinationIp = risk.destinationIp,
            bytesSent = risk.bytesSent,
            bytesReceived = risk.bytesReceived,
            protocol = risk.protocol,
            destinationPort = risk.destinationPort,
            riskScore = risk.riskScore,
            riskLevel = risk.riskLevel.name,
            description = risk.description,
            timestamp = risk.timestamp
        )
        analyzerDao.insertResult(entity)
    }

    private suspend fun updateTrafficRisk(
        session: TrafficEntity,
        assessment: RiskAssessment
    ) {
        val updated = session.copy(
            riskScore = assessment.score,
            riskLabel = assessment.level.name,
            timestamp = System.currentTimeMillis()
        )
        trafficDao.updateTraffic(updated)
    }

    private fun buildDescription(level: RiskLevel, session: TrafficEntity): String {
        return when (level) {
            RiskLevel.LOW -> "Sin anomalías relevantes detectadas para ${session.destinationIp}."
            RiskLevel.MEDIUM -> "Actividad inusual detectada: ${session.bytesSent + session.bytesReceived} bytes transferidos."
            RiskLevel.HIGH -> "Posible exfiltración hacia ${session.destinationIp}:${session.destinationPort}."
        }
    }
}

class MissingTrafficDataException(
    appPackage: String,
    destinationIp: String
) : IllegalStateException(
    "No se encontró tráfico reciente para $appPackage hacia $destinationIp"
)

private fun AnalysisResultEntity.toDomain(): TrafficRisk = TrafficRisk(
    id = id.toString(),
    appPackage = appPackage,
    destinationIp = destinationIp,
    riskLevel = RiskLevel.valueOf(riskLevel),
    riskScore = riskScore,
    description = description,
    timestamp = timestamp,
    bytesSent = bytesSent,
    bytesReceived = bytesReceived,
    protocol = protocol,
    destinationPort = destinationPort
)
