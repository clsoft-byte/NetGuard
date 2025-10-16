package com.clsoft.netguard.engine.detector.tf

import android.content.Context
import com.clsoft.netguard.engine.detector.api.DetectorResult
import com.clsoft.netguard.engine.detector.api.RiskLabel
import com.clsoft.netguard.engine.detector.api.TrafficDetector
import com.clsoft.netguard.engine.detector.core.InputFeatures
import com.clsoft.netguard.engine.detector.core.Preprocessing
import org.tensorflow.lite.Interpreter
import java.util.concurrent.atomic.AtomicReference

class TFLiteTrafficDetector(
    context: Context,
    modelAsset: String = "traffic_model.tflite"
) : TrafficDetector {

    private val interpreterRef = AtomicReference<Interpreter>(
        ModelLoader.loadModel(context, modelAsset)
    )

    override fun predict(features: InputFeatures): DetectorResult {
        val input = Preprocessing.normalize(features.asFloatArray())
        val output = Array(1) { FloatArray(1) }   // salida escalar 0..1
        interpreterRef.get().run(arrayOf(input), output)

        val score = output[0][0].coerceIn(0f, 1f)
        val label = when {
            score >= 0.7f -> RiskLabel.HIGH
            score >= 0.4f -> RiskLabel.MEDIUM
            else -> RiskLabel.LOW
        }
        return DetectorResult(score, label)
    }

    fun close() {
        interpreterRef.getAndSet(null)?.close()
    }

}