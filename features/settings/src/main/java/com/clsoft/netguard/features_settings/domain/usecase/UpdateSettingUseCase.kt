package com.clsoft.netguard.features_settings.domain.usecase

import com.clsoft.netguard.features_settings.domain.model.AppSetting
import com.clsoft.netguard.features_settings.domain.repository.SettingsRepository
import javax.inject.Inject


class UpdateSettingUseCase @Inject constructor(
    private val repository: SettingsRepository
) {
    suspend operator fun invoke(setting: AppSetting) = repository.updateSetting(setting)
}