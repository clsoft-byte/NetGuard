package com.clsoft.netguard.features.traffic.monitor.service

import com.clsoft.netguard.core.utils.Logger
import com.clsoft.netguard.engine.network.analyzer.NativeBridge
import org.json.JSONObject

internal object NativeRiskEvaluator {

    private const val TAG = "NativeRiskEvaluator"

    data class RiskSummary(
        val label: String?,
        val score: Float,
        val blocked: Boolean
    ) {
        companion object {
            val Default = RiskSummary(label = "Low", score = 0f, blocked = false)
        }
    }

    private val labelPriority = mapOf(
        "LOW" to 0,
        "MEDIUM" to 1,
        "HIGH" to 2
    )

    fun evaluate(packets: List<ByteArray>): RiskSummary {
        if (packets.isEmpty()) {
            return RiskSummary.Default
        }

        return try {
            val responses = NativeBridge.analyzePackets(packets.toTypedArray())
            mergeResponses(responses)
        } catch (t: Throwable) {
            Logger.e(TAG, "Native analysis failed", t)
            RiskSummary.Default
        }
    }

    private fun mergeResponses(responses: Array<String>): RiskSummary {
        var bestScore = 0f
        var bestLabel = "Low"
        var blocked = false

        responses.forEach { raw ->
            val json = runCatching { JSONObject(raw) }.getOrNull() ?: return@forEach
            val scoreValue = json.optDouble("riskScore", Double.NaN)
            if (!scoreValue.isNaN()) {
                val clampedScore = scoreValue.coerceIn(0.0, 1.0)
                if (clampedScore > bestScore) {
                    bestScore = clampedScore.toFloat()
                }
            }

            val label = normalizeLabel(json.optString("riskLabel", ""))
            if (isHigherPriority(label, bestLabel)) {
                bestLabel = label
            }

            if (json.optBoolean("blocked", false)) {
                blocked = true
            }
        }

        return RiskSummary(
            label = bestLabel,
            score = bestScore,
            blocked = blocked
        )
    }

    private fun normalizeLabel(value: String): String {
        return when (value.lowercase()) {
            "high" -> "High"
            "medium" -> "Medium"
            "low" -> "Low"
            else -> "Low"
        }
    }

    private fun isHigherPriority(candidate: String, current: String): Boolean {
        val candidatePriority = labelPriority[candidate.uppercase()] ?: -1
        val currentPriority = labelPriority[current.uppercase()] ?: -1
        return candidatePriority > currentPriority
    }
}