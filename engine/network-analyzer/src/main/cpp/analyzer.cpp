#include <jni.h>
#include <string>
#include <vector>
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
        JNIEnv* env, jclass, jstring packageName, jobjectArray packetArray) {

    std::string package;
    if (packageName != nullptr) {
        const char* packageChars = env->GetStringUTFChars(packageName, nullptr);
        if (packageChars != nullptr) {
            package.assign(packageChars);
            env->ReleaseStringUTFChars(packageName, packageChars);
        }
    }

    if (packetArray == nullptr) {
        jclass stringClass = env->FindClass("java/lang/String");
        if (stringClass == nullptr) {
            env->ExceptionClear();
            return nullptr;
        }
        jobjectArray out = env->NewObjectArray(1, stringClass, nullptr);
        PacketAnalysisResult result = PacketAnalyzer::analyzePacket(std::vector<uint8_t>{}, package);
        env->SetObjectArrayElement(out, 0, env->NewStringUTF(result.json.c_str()));
        env->DeleteLocalRef(stringClass);
        return out;
    }

    jsize count = env->GetArrayLength(packetArray);
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }

    jobjectArray out = env->NewObjectArray(count, stringClass, nullptr);
    if (out == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }

    for (jsize i = 0; i < count; ++i) {
        jbyteArray pkt = static_cast<jbyteArray>(env->GetObjectArrayElement(packetArray, i));
        if (pkt == nullptr) {
            PacketAnalysisResult fallback = PacketAnalyzer::analyzePacket(std::vector<uint8_t>{}, package);
            env->SetObjectArrayElement(out, i, env->NewStringUTF(fallback.json.c_str()));
            continue;
        }

        jsize len = env->GetArrayLength(pkt);
        std::vector<uint8_t> buffer(static_cast<size_t>(len));
        if (len > 0) {
            env->GetByteArrayRegion(pkt, 0, len, reinterpret_cast<jbyte*>(buffer.data()));
        }

        PacketAnalysisResult analysis = PacketAnalyzer::analyzePacket(buffer, package);
        if (!analysis.highRisk) {
            PacketAnalysisResult verification = PacketAnalyzer::analyzePacket(buffer, package);
            if (verification.highRisk) {
                analysis = verification;
            }
        }

        env->SetObjectArrayElement(out, i, env->NewStringUTF(analysis.json.c_str()));
        env->DeleteLocalRef(pkt);
    }

    env->DeleteLocalRef(stringClass);
    return out;
}

}