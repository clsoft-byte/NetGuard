package com.clsoft.netguard.features_settings.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.clsoft.netguard.features_settings.domain.model.AppSetting
import com.clsoft.netguard.features_settings.domain.usecase.GetSettingsUseCase
import com.clsoft.netguard.features_settings.domain.usecase.ResetSettingsUseCase
import com.clsoft.netguard.features_settings.domain.usecase.UpdateSettingUseCase
import com.clsoft.netguard.features_settings.presentation.contract.SettingsEvent
import com.clsoft.netguard.features_settings.presentation.contract.SettingsState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject


@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val getSettings: GetSettingsUseCase,
    private val updateSetting: UpdateSettingUseCase,
    private val resetSettings: ResetSettingsUseCase
) : ViewModel() {

    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state

    init {
        observeSettings()
    }

    fun onEvent(event: SettingsEvent) {
        when (event) {
            is SettingsEvent.Update -> update(event.setting)
            is SettingsEvent.Reset -> reset()
        }
    }

    private fun observeSettings() {
        viewModelScope.launch {
            getSettings().collectLatest { setting ->
                _state.value = SettingsState(setting)
            }
        }
    }

    private fun update(setting: AppSetting) {
        viewModelScope.launch { updateSetting(setting) }
    }

    private fun reset() {
        viewModelScope.launch { resetSettings() }
    }
}