package com.clsoft.netguard.features_settings.domain.usecase

import com.clsoft.netguard.features_settings.domain.repository.SettingsRepository
import javax.inject.Inject

class GetSettingsUseCase @Inject constructor(
    private val repository: SettingsRepository
) {
    operator fun invoke() = repository.getSettings()
}