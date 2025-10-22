//
// Created by Cardiell on 12/10/25.
//
#include <jni.h>
#include <string>
#include <android/log.h>

#include "FirewallController.hpp"

#define LOG_TAG "FirewallBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {

JNIEXPORT void JNICALL
Java_com_clsoft_netguard_engine_network_analyzer_NativeBridge_applyFirewallRule(
        JNIEnv* env,
        jobject /* this */,
        jstring packageName,
        jboolean allow
) {
    const char* pkgChars = env->GetStringUTFChars(packageName, nullptr);
    if (pkgChars == nullptr) {
        return;
    }

    std::string pkg(pkgChars);
    env->ReleaseStringUTFChars(packageName, pkgChars);

    firewall::setRule(pkg, allow);
    LOGI("Firewall rule applied: %s -> %s", pkg.c_str(), allow ? "ALLOW" : "BLOCK");
}

}