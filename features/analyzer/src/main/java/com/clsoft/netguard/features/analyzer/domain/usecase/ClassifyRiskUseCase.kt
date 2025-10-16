package com.clsoft.netguard.features.analyzer.domain.usecase

import com.clsoft.netguard.features.analyzer.domain.model.RiskLevel
import javax.inject.Inject


/**
 * Caso de uso que simula una clasificación con IA.
 * En producción delegará a TensorFlow/ONNX en engine/ai-detector.
 */
class ClassifyRiskUseCase @Inject constructor() {
    operator fun invoke(bytesSent: Long, bytesReceived: Long, destinationIp: String): RiskLevel {
        return when {
            bytesSent > 5_000_000 || destinationIp.startsWith("8.8.") -> RiskLevel.HIGH
            bytesSent > 500_000 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }
}