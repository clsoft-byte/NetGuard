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
            val score = json.optDouble("riskScore", Double.NaN)
            if (!score.isNaN() && score > bestScore) {
                bestScore = score.toFloat()
            }

            val label = json.optString("riskLabel", "")
            if (label.isNotBlank() && isHigherPriority(label, bestLabel)) {
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

    private fun isHigherPriority(candidate: String, current: String): Boolean {
        val candidatePriority = labelPriority[candidate.uppercase()] ?: -1
        val currentPriority = labelPriority[current.uppercase()] ?: -1
        return candidatePriority > currentPriority
    }
}