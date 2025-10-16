//
// Created by Cardiell on 12/10/25.
//
#include <jni.h>
#include <string>
#include <android/log.h>

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
    const char* pkg = env->GetStringUTFChars(packageName, nullptr);
    LOGI("Firewall rule applied: %s -> %s", pkg, allow ? "ALLOW" : "BLOCK");
    env->ReleaseStringUTFChars(packageName, pkg);
}

}
