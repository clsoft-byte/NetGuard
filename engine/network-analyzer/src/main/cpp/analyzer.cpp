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
        JNIEnv* env, jclass, jobjectArray packetArray) {

    jsize count = env->GetArrayLength(packetArray);
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray out = env->NewObjectArray(count, stringClass, nullptr);

    for (jsize i = 0; i < count; ++i) {
        jbyteArray pkt = (jbyteArray) env->GetObjectArrayElement(packetArray, i);
        if (!pkt) { env->SetObjectArrayElement(out, i, env->NewStringUTF("{\"error\":\"null\"}")); continue; }

        jsize len = env->GetArrayLength(pkt);
        std::string raw;
        raw.resize(static_cast<size_t>(len));
        env->GetByteArrayRegion(pkt, 0, len, reinterpret_cast<jbyte*>(&raw[0]));

        std::string json = PacketAnalyzer::analyzePacket(raw);
        env->SetObjectArrayElement(out, i, env->NewStringUTF(json.c_str()));

        env->DeleteLocalRef(pkt);
    }
    return out;
}

}