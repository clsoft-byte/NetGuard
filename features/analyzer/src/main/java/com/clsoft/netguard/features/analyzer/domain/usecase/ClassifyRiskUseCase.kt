package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.engine.detector.api.RiskLabel
import com.clsoft.netguard.engine.detector.api.TrafficDetector
import com.clsoft.netguard.engine.detector.core.FeatureExtractor
import com.clsoft.netguard.features.analyzer.domain.model.RiskAssessment
import com.clsoft.netguard.features.analyzer.domain.model.RiskLevel
import javax.inject.Inject

class ClassifyRiskUseCase @Inject constructor(
    private val trafficDetector: TrafficDetector
) {

    operator fun invoke(
        bytesSent: Long,
        bytesReceived: Long,
        protocol: String,
        destinationIp: String,
        now: Long
    ): RiskAssessment {
        val features = FeatureExtractor.fromRaw(
            bytesUp = bytesSent,
            bytesDown = bytesReceived,
            protocol = protocol,
            destIp = destinationIp,
            nowMillis = now
        )

        val result = trafficDetector.predict(features)
        val level = when (result.label) {
            RiskLabel.LOW -> RiskLevel.LOW
            RiskLabel.MEDIUM -> RiskLevel.MEDIUM
            RiskLabel.HIGH -> RiskLevel.HIGH
        }
        return RiskAssessment(level = level, score = result.score)
    }
}