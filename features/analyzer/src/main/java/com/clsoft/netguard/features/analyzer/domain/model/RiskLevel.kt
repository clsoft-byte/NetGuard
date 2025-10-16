package com.clsoft.netguard.features.analyzer.domain.model

enum class RiskLevel(val label: String, val colorHex: String) {
    LOW("Bajo", "#4CAF50"),
    MEDIUM("Medio", "#FFC107"),
    HIGH("Alto", "#F44336")
}