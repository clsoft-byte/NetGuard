package com.clsoft.netguard.engine.detector.api

import com.clsoft.netguard.engine.detector.core.InputFeatures


interface TrafficDetector {
    /**
     * Retorna un resultado de riesgo normalizado [0..1] y etiqueta discreta.
     * Las implementaciones deben ser thread-safe o sincronizadas.
     */
    fun predict(features: InputFeatures): DetectorResult
}