package com.clsoft.netguard.features_settings.domain.usecase

import com.clsoft.netguard.features_settings.domain.repository.SettingsRepository
import javax.inject.Inject


class ResetSettingsUseCase @Inject constructor(
    private val repository: SettingsRepository
) {
    suspend operator fun invoke() = repository.resetSettings()
}