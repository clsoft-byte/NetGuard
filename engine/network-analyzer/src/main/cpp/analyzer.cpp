#include <jni.h>
#include <string>
#include <android/log.h>
#include "PacketAnalyzer.hpp"

#define LOG_TAG "NDKNetGuard"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_clsoft_netguard_engine_network_analyzer_NativeBridge_getNativeVersion(JNIEnv* env, jobject /* this */) {
    std::string version = "NDK Engine v1.0.0";
    return env->NewStringUTF(version.c_str());
}

JNIEXPORT jobjectArray JNICALL
Java_com_clsoft_netguard_engine_network_analyzer_NativeBridge_analyzePackets(
        JNIEnv* env,
        jobject /* this */,
        jobjectArray packetData
) {
    // Simula análisis nativo
    jsize length = env->GetArrayLength(packetData);
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(length, stringClass, nullptr);

    for (jsize i = 0; i < length; i++) {
        jstring item = (jstring) env->GetObjectArrayElement(packetData, i);
        const char* raw = env->GetStringUTFChars(item, nullptr);
        std::string analyzed = PacketAnalyzer::analyzePacket(raw);
        env->SetObjectArrayElement(result, i, env->NewStringUTF(analyzed.c_str()));
        env->ReleaseStringUTFChars(item, raw);
    }

    LOGI("Packet analysis simulated for %d packets", length);
    return result;
}

}