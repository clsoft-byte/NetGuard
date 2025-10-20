#include "PacketAnalyzer.hpp"

#include <algorithm>
#include <android/log.h>
#include <array>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <iomanip>
#include <mutex>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

    constexpr const char* LOG_TAG = "NDKNetGuard";
    constexpr size_t MAX_PACKET_SIZE = 65535;           // RFC 791
    constexpr double HIGH_RISK_THRESHOLD = 0.82;
    constexpr double MEDIUM_RISK_THRESHOLD = 0.45;
    constexpr double ABSOLUTE_HIGH_SCORE = 0.98;
    constexpr size_t MAX_TRACKED_SESSIONS = 2048;
    constexpr std::chrono::seconds SESSION_EXPIRATION(10);

    struct JsonBuilder {
        std::ostringstream out;
        bool first = true;

        JsonBuilder() { out << '{'; }

        void kv(const char* key, const std::string& value) {
            prefix();
            out << '"' << key << "\":";
            escape(value);
        }

        void kv(const char* key, const char* value) {
            prefix();
            out << '"' << key << "\":";
            escape(std::string(value));
        }

        void kv(const char* key, int64_t value) {
            prefix();
            out << '"' << key << "\":" << value;
        }

        void kv(const char* key, uint64_t value) {
            prefix();
            out << '"' << key << "\":" << value;
        }

        void kv(const char* key, double value) {
            prefix();
            out << '"' << key << "\":" << std::fixed << std::setprecision(4) << value;
        }

        void kv(const char* key, bool value) {
            prefix();
            out << '"' << key << "\":" << (value ? "true" : "false");
        }

        void raw(const char* key, const std::string& rawValue) {
            prefix();
            out << '"' << key << "\":" << rawValue;
        }

        std::string str() {
            out << '}';
            return out.str();
        }

    private:
        void prefix() {
            if (!first) {
                out << ',';
            }
            first = false;
        }

        void escape(const std::string& value) {
            out << '"';
            for (unsigned char c : value) {
                switch (c) {
                    case '"': out << "\\\""; break;
                    case '\\': out << "\\\\"; break;
                    case '\b': out << "\\b"; break;
                    case '\f': out << "\\f"; break;
                    case '\n': out << "\\n"; break;
                    case '\r': out << "\\r"; break;
                    case '\t': out << "\\t"; break;
                    default:
                        if (c < 0x20) {
                            out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                                << static_cast<int>(c) << std::dec;
                        } else {
                            out << c;
                        }
                }
            }
            out << '"';
        }
    };

    struct DnsHeader {
        uint16_t id;
        uint16_t flags;
        uint16_t qdCount;
        uint16_t anCount;
        uint16_t nsCount;
        uint16_t arCount;
    } __attribute__((packed));

    struct DnsMinimal {
        bool ok = false;
        std::string qname;
        uint16_t qtype = 0;
        uint16_t rcode = 0;
    };

    struct TlsIndicators {
        bool parsed = false;
        bool clientHello = false;
        bool malformed = false;
        uint16_t version = 0;
        size_t cipherCount = 0;
        std::string serverName;
    };

    struct RunningStats {
        size_t n = 0;
        double mean = 0.0;
        double m2 = 0.0;

        void add(double sample) {
            n++;
            double delta = sample - mean;
            mean += delta / static_cast<double>(n);
            double delta2 = sample - mean;
            m2 += delta * delta2;
        }

        double variance() const {
            if (n < 2) {
                return 0.0;
            }
            return m2 / static_cast<double>(n - 1);
        }

        double stddev() const {
            return std::sqrt(variance());
        }
    };

    struct PacketContext {
        bool valid = false;
        bool truncated = false;
        bool hookSuspected = false;
        bool dnsParsed = false;
        bool tampered = false;
        size_t length = 0;
        size_t payloadLength = 0;
        uint32_t crc32 = 0;
        double entropy = 0.0;
        std::string srcIp;
        std::string dstIp;
        std::string protocol = "OTHER";
        std::string direction = "outbound";
        int srcPort = 0;
        int dstPort = 0;
        uint8_t hopLimit = 0;
        DnsMinimal dns;
        TlsIndicators tls;
    };

    struct RiskAssessment {
        double primaryScore = 0.08;
        double secondaryScore = 0.05;
        double correlationScore = 0.0;
        bool highRiskConfirmed = false;
        bool possibleFalseNegative = false;
        std::string primaryReason;
        std::string secondaryReason;
        std::string correlationReason;
    };

    struct SessionInfo {
        std::chrono::steady_clock::time_point lastSeen{};
        size_t count = 0;
        size_t smallPayloadCount = 0;
        size_t totalBytes = 0;
        size_t inboundPackets = 0;
        size_t outboundPackets = 0;
        size_t burstPackets = 0;
        size_t burstSmallPayloads = 0;
        RunningStats payloadStats;
        RunningStats interArrivalMs;
        std::chrono::steady_clock::time_point previousSeen{};
    };

    std::mutex gSessionMutex;
    std::unordered_map<std::string, SessionInfo> gSessions;

    uint32_t computeCrc32(const uint8_t* data, size_t len) {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i) {
            crc ^= static_cast<uint32_t>(data[i]);
            for (int j = 0; j < 8; ++j) {
                uint32_t mask = -(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }

    double calculateEntropy(const uint8_t* data, size_t len) {
        if (len == 0) {
            return 0.0;
        }

        std::array<size_t, 256> histogram{};
        for (size_t i = 0; i < len; ++i) {
            histogram[data[i]]++;
        }

        double entropy = 0.0;
        for (size_t value : histogram) {
            if (value == 0) continue;
            double p = static_cast<double>(value) / static_cast<double>(len);
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    bool isPrintableDomainChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
    }

    double safeRatio(size_t numerator, size_t denominator) {
        if (denominator == 0) {
            return 0.0;
        }
        return static_cast<double>(numerator) / static_cast<double>(denominator);
    }

    DnsMinimal parseDns(const uint8_t* data, size_t len) {
        DnsMinimal result;
        if (len < sizeof(DnsHeader)) {
            return result;
        }

        const DnsHeader* header = reinterpret_cast<const DnsHeader*>(data);
        uint16_t flags = ntohs(header->flags);
        result.rcode = flags & 0x000F;
        uint16_t qdCount = ntohs(header->qdCount);
        if (qdCount == 0) {
            return result;
        }

        size_t offset = sizeof(DnsHeader);
        std::ostringstream domain;
        while (offset < len) {
            uint8_t labelLength = data[offset++];
            if (labelLength == 0) {
                break;
            }
            if (labelLength & 0xC0) {
                return result;
            }
            if (offset + labelLength > len) {
                return result;
            }
            for (size_t i = 0; i < labelLength; ++i) {
                char c = static_cast<char>(data[offset + i]);
                domain << (isPrintableDomainChar(c) ? c : '_');
            }
            offset += labelLength;
            if (offset < len) {
                domain << '.';
            }
            if (domain.tellp() > 253) {
                break;
            }
        }

        if (offset + 4 > len) {
            return result;
        }

        result.qname = domain.str();
        result.qtype = ntohs(*reinterpret_cast<const uint16_t*>(data + offset));
        result.ok = true;
        return result;
    }

    TlsIndicators inspectTlsPayload(const uint8_t* data, size_t len) {
        TlsIndicators info;
        if (len < 6) {
            return info;
        }

        if (data[0] != 0x16) {
            return info;
        }

        size_t offset = 5; // start of handshake
        uint8_t hsType = data[offset];
        if (hsType != 0x01) { // only process ClientHello
            info.parsed = true;
            return info;
        }

        if (len < offset + 4) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }

        uint32_t hsLen = (static_cast<uint32_t>(data[offset + 1]) << 16) |
                         (static_cast<uint32_t>(data[offset + 2]) << 8) |
                         static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (len < offset + 2 + 32) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }

        info.version = static_cast<uint16_t>(data[offset]) << 8 | static_cast<uint16_t>(data[offset + 1]);
        offset += 2;
        offset += 32; // random

        if (len < offset + 1) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        uint8_t sessionIdLen = data[offset++];
        if (len < offset + sessionIdLen) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        offset += sessionIdLen;

        if (len < offset + 2) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        uint16_t cipherLen = static_cast<uint16_t>(data[offset]) << 8 | static_cast<uint16_t>(data[offset + 1]);
        offset += 2;
        if (cipherLen % 2 != 0 || len < offset + cipherLen) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        info.cipherCount = cipherLen / 2u;
        offset += cipherLen;

        if (len < offset + 1) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        uint8_t compressionLen = data[offset++];
        if (len < offset + compressionLen) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }
        offset += compressionLen;

        if (len < offset + 2) {
            info.parsed = true;
            info.clientHello = true;
            return info;
        }

        uint16_t extensionsLen = static_cast<uint16_t>(data[offset]) << 8 | static_cast<uint16_t>(data[offset + 1]);
        offset += 2;
        size_t extensionsEnd = offset + extensionsLen;
        if (extensionsEnd > len) {
            info.malformed = true;
            info.parsed = true;
            return info;
        }

        while (offset + 4 <= extensionsEnd) {
            uint16_t extType = static_cast<uint16_t>(data[offset]) << 8 | static_cast<uint16_t>(data[offset + 1]);
            uint16_t extSize = static_cast<uint16_t>(data[offset + 2]) << 8 | static_cast<uint16_t>(data[offset + 3]);
            offset += 4;
            if (offset + extSize > extensionsEnd) {
                info.malformed = true;
                info.parsed = true;
                return info;
            }

            if (extType == 0x0000 && extSize >= 5) { // SNI
                uint16_t listLen = static_cast<uint16_t>(data[offset]) << 8 | static_cast<uint16_t>(data[offset + 1]);
                size_t cursor = offset + 2;
                size_t listEnd = offset + 2 + listLen;
                if (listEnd > offset + extSize) {
                    info.malformed = true;
                    info.parsed = true;
                    return info;
                }
                while (cursor + 3 <= listEnd) {
                    uint8_t nameType = data[cursor++];
                    uint16_t nameLen = static_cast<uint16_t>(data[cursor]) << 8 | static_cast<uint16_t>(data[cursor + 1]);
                    cursor += 2;
                    if (cursor + nameLen > listEnd) {
                        info.malformed = true;
                        info.parsed = true;
                        return info;
                    }
                    if (nameType == 0x00) {
                        info.serverName.assign(reinterpret_cast<const char*>(data + cursor), nameLen);
                        break;
                    }
                    cursor += nameLen;
                }
            }

            offset += extSize;
        }

        info.parsed = true;
        info.clientHello = true;
        if (extensionsEnd != offset) {
            info.malformed = true;
        }
        if (hsLen + 4 > len - 5) {
            info.malformed = true;
        }
        return info;
    }

    bool isPrivateIPv4(uint32_t address) {
        uint32_t host = ntohl(address);
        if ((host & 0xFF000000u) == 0x0A000000u) return true;
        if ((host & 0xFFF00000u) == 0xAC100000u) return true;
        if ((host & 0xFFFF0000u) == 0xC0A80000u) return true;
        if ((host & 0xFF000000u) == 0x7F000000u) return true;
        return false;
    }

    std::string toIPv4String(uint32_t address) {
        char buffer[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
        return std::string(buffer);
    }

    std::string toIPv6String(const in6_addr& address) {
        char buffer[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &address, buffer, sizeof(buffer));
        return std::string(buffer);
    }

    bool detectHooking() {
        Dl_info info{};
        if (dladdr(reinterpret_cast<const void*>(&PacketAnalyzer::analyzePacket), &info) == 0) {
            return true;
        }
        if (info.dli_fname == nullptr) {
            return true;
        }
        std::string libraryName(info.dli_fname);
        return libraryName.find("netguard_native") == std::string::npos;
    }

    void cleanupSessionsLocked(const std::chrono::steady_clock::time_point& now) {
        for (auto it = gSessions.begin(); it != gSessions.end();) {
            if (now - it->second.lastSeen > SESSION_EXPIRATION) {
                it = gSessions.erase(it);
            } else {
                ++it;
            }
        }
        if (gSessions.size() > MAX_TRACKED_SESSIONS) {
            gSessions.clear();
        }
    }

    SessionInfo registerSession(const std::string& key,
                                size_t payloadLength,
                                size_t packetLength,
                                const std::string& direction) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(gSessionMutex);
        cleanupSessionsLocked(now);

        SessionInfo& info = gSessions[key];
        bool seenBefore = info.count > 0;
        bool sameBurst = seenBefore && (now - info.lastSeen < std::chrono::milliseconds(500));

        if (!seenBefore) {
            info.count = 0;
            info.smallPayloadCount = 0;
            info.burstPackets = 0;
            info.burstSmallPayloads = 0;
        }

        if (!sameBurst) {
            info.burstPackets = 0;
            info.burstSmallPayloads = 0;
        }

        info.count++;
        info.burstPackets++;

        if (payloadLength <= 150) {
            info.smallPayloadCount++;
            info.burstSmallPayloads++;
        }

        info.totalBytes += packetLength;
        if (direction == "inbound") {
            info.inboundPackets++;
        } else if (direction == "outbound") {
            info.outboundPackets++;
        }

        info.payloadStats.add(static_cast<double>(payloadLength));
        if (info.previousSeen.time_since_epoch().count() != 0) {
            auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - info.previousSeen);
            info.interArrivalMs.add(static_cast<double>(delta.count()));
        }
        info.previousSeen = now;
        info.lastSeen = now;
        return info;
    }

    void applyPortHeuristics(const PacketContext& ctx, RiskAssessment& risk) {
        switch (ctx.dstPort) {
            case 21: case 22: case 23: case 25: case 135: case 137: case 138: case 139:
            case 445: case 3389:
                risk.primaryScore = std::max(risk.primaryScore, 0.92);
                risk.primaryReason = "Sensitive service port";
                risk.highRiskConfirmed = true;
                break;
            case 53:
                risk.primaryScore = std::max(risk.primaryScore, 0.55);
                if (risk.primaryReason.empty()) risk.primaryReason = "DNS communication";
                break;
            case 80: case 443:
                risk.primaryScore = std::max(risk.primaryScore, 0.5);
                if (risk.primaryReason.empty()) risk.primaryReason = "HTTP/HTTPS traffic";
                break;
            default:
                if (ctx.dstPort != 0 && ctx.dstPort < 1024) {
                    risk.primaryScore = std::max(risk.primaryScore, 0.65);
                    risk.secondaryScore = std::max(risk.secondaryScore, 0.35);
                    risk.secondaryReason = "Privileged port anomaly";
                }
                if (ctx.dstPort == 0 || ctx.srcPort == 0) {
                    risk.secondaryScore = std::max(risk.secondaryScore, 0.6);
                    risk.secondaryReason = "Null port detected";
                }
                break;
        }

        if (ctx.dstPort >= 49152 && ctx.dstPort <= 65535 && ctx.payloadLength > 1000) {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.58);
            if (risk.secondaryReason.empty()) risk.secondaryReason = "Large transfer to dynamic port";
        }
    }

    void applyDnsHeuristics(const PacketContext& ctx, RiskAssessment& risk) {
        if (!ctx.dnsParsed) {
            return;
        }

        const auto& dns = ctx.dns;
        if (dns.qname.size() > 80) {
            risk.primaryScore = std::max(risk.primaryScore, 0.72);
            risk.secondaryScore = std::max(risk.secondaryScore, 0.68);
            risk.secondaryReason = "Potential DNS tunneling";
        }

        if (dns.qtype == 255 || dns.qtype == 41) {
            risk.primaryScore = std::max(risk.primaryScore, 0.6);
            if (risk.primaryReason.empty()) risk.primaryReason = "Suspicious DNS query";
        }

        size_t hyphenCount = std::count(dns.qname.begin(), dns.qname.end(), '-');
        if (hyphenCount > 5 || dns.qname.find("_tcp") != std::string::npos) {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.55);
            if (risk.secondaryReason.empty()) risk.secondaryReason = "DNS pattern anomaly";
        }
    }

    void applyBehaviorHeuristics(const PacketContext& ctx, const SessionInfo& session, RiskAssessment& risk) {
        double meanPayload = session.payloadStats.mean;
        double payloadStddev = session.payloadStats.stddev();
        double interArrivalMean = session.interArrivalMs.mean;
        double interArrivalStddev = session.interArrivalMs.stddev();
        double smallPayloadRatio = safeRatio(session.smallPayloadCount, session.count);
        double burstSmallRatio = safeRatio(session.burstSmallPayloads, session.burstPackets);

        if (ctx.protocol == "TCP") {
            if (ctx.payloadLength == 0 && session.count > 6) {
                risk.correlationScore = std::max(risk.correlationScore, 0.65);
                risk.correlationReason = "Repeated empty TCP frames";
            }
            if (ctx.payloadLength > 1400) {
                risk.secondaryScore = std::max(risk.secondaryScore, 0.6);
                if (risk.secondaryReason.empty()) risk.secondaryReason = "Oversized TCP payload";
            }
            if (ctx.tls.malformed) {
                risk.highRiskConfirmed = true;
                risk.primaryScore = std::max(risk.primaryScore, 0.95);
                risk.primaryReason = "Malformed TLS handshake";
            }
        }

        if (session.count > 24 && smallPayloadRatio > 0.88 &&
            interArrivalMean < 120.0 && interArrivalStddev < 18.0) {
            risk.correlationScore = std::max(risk.correlationScore, 0.82);
            risk.correlationReason = "Persistent low-latency stream";
        }

        if (ctx.entropy > 7.5 && ctx.payloadLength > 200) {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.7);
            risk.secondaryReason = "High-entropy payload";
        }

        if (session.count > 12 && smallPayloadRatio > 0.7 && meanPayload < 180.0 && payloadStddev < 60.0) {
            risk.correlationScore = std::max(risk.correlationScore, 0.82);
            risk.correlationReason = "Beacon-like session pattern";
        }

        if (session.burstPackets > 6 && burstSmallRatio > 0.85 && interArrivalStddev < 15.0) {
            risk.correlationScore = std::max(risk.correlationScore, 0.84);
            risk.correlationReason = "Short-burst command channel";
        }

        if (session.totalBytes > 2 * 1024 * 1024 && smallPayloadRatio > 0.55) {
            risk.primaryScore = std::max(risk.primaryScore, 0.78);
            if (risk.primaryReason.empty()) {
                risk.primaryReason = "Sustained transfer with small frames";
            }
        }

        if (session.interArrivalMs.n > 8 && interArrivalMean < 70.0 &&
            interArrivalStddev < 10.0 && smallPayloadRatio > 0.55) {
            risk.correlationScore = std::max(risk.correlationScore, 0.84);
            risk.correlationReason = "Highly periodic session";
        }

        if (ctx.hopLimit != 0 && ctx.hopLimit < 32 && ctx.direction == "inbound") {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.62);
            risk.secondaryReason = "Low TTL inbound packet";
        }

        if (ctx.direction == "inbound" && session.outboundPackets == 0 && session.count > 8) {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.66);
            if (risk.secondaryReason.empty()) {
                risk.secondaryReason = "Inbound-only unsolicited flow";
            }
        }

        if (ctx.direction == "outbound" && session.inboundPackets == 0 && session.count > 30) {
            risk.primaryScore = std::max(risk.primaryScore, 0.8);
            if (risk.primaryReason.empty()) {
                risk.primaryReason = "Outbound-only persistence";
            }
        }

        if (ctx.tampered || ctx.hookSuspected) {
            risk.highRiskConfirmed = true;
            risk.correlationScore = std::max(risk.correlationScore, 0.95);
            risk.correlationReason = "Integrity or hooking detection";
        }

        if (ctx.tls.clientHello && ctx.tls.serverName.empty() && ctx.direction == "outbound") {
            risk.secondaryScore = std::max(risk.secondaryScore, 0.72);
            risk.secondaryReason = "TLS client hello without SNI";
        }
    }

    void applyTlsHeuristics(const PacketContext& ctx, RiskAssessment& risk) {
        if (!ctx.tls.parsed) {
            return;
        }

        if (ctx.tls.clientHello) {
            if (ctx.tls.version != 0 && ctx.tls.version < 0x0303) {
                risk.secondaryScore = std::max(risk.secondaryScore, 0.68);
                if (risk.secondaryReason.empty()) {
                    risk.secondaryReason = "Outdated TLS version";
                }
            }

            if (ctx.tls.cipherCount == 0) {
                risk.secondaryScore = std::max(risk.secondaryScore, 0.7);
                if (risk.secondaryReason.empty()) {
                    risk.secondaryReason = "TLS client without ciphers";
                }
            }

            if (ctx.tls.cipherCount > 140) {
                risk.primaryScore = std::max(risk.primaryScore, 0.83);
                if (risk.primaryReason.empty()) {
                    risk.primaryReason = "Suspicious TLS cipher enumeration";
                }
            }

            if (!ctx.tls.serverName.empty()) {
                size_t digitCount = 0;
                for (unsigned char c : ctx.tls.serverName) {
                    if (std::isdigit(c)) {
                        digitCount++;
                    }
                }
                if (ctx.tls.serverName.size() > 40 && digitCount > ctx.tls.serverName.size() / 2) {
                    risk.secondaryScore = std::max(risk.secondaryScore, 0.76);
                    if (risk.secondaryReason.empty()) {
                        risk.secondaryReason = "Numeric-heavy TLS SNI";
                    }
                }
            }
        }

        if (ctx.tls.malformed) {
            risk.highRiskConfirmed = true;
            risk.primaryScore = std::max(risk.primaryScore, ABSOLUTE_HIGH_SCORE);
            risk.primaryReason = "Critical TLS parsing failure";
        }
    }

    double consolidateScore(const RiskAssessment& risk) {
        double score = std::max({risk.primaryScore, risk.secondaryScore, risk.correlationScore});
        if (risk.highRiskConfirmed) {
            score = std::max(score, ABSOLUTE_HIGH_SCORE);
        }
        return std::min(std::max(score, 0.0), 1.0);
    }

    double calibrateScore(double rawScore, const RiskAssessment& risk, const SessionInfo& session) {
        double adjusted = rawScore;
        if (risk.highRiskConfirmed) {
            adjusted = std::max(adjusted, 0.93);
        }

        if (rawScore >= 0.6) {
            double sessionBoost = std::min(0.08, safeRatio(session.count, static_cast<size_t>(150)) * 0.4);
            adjusted = std::min(1.0, adjusted + sessionBoost);
        }

        if (rawScore >= 0.7 && session.interArrivalMs.n > 5 && session.interArrivalMs.stddev() < 8.0) {
            adjusted = std::min(1.0, adjusted + 0.05);
        }

        if (rawScore >= 0.65 && session.totalBytes > 4 * 1024 * 1024) {
            adjusted = std::min(1.0, adjusted + 0.03);
        }

        return std::clamp(adjusted, 0.0, 1.0);
    }

    double computeConfidence(double calibratedScore, const RiskAssessment& risk, const SessionInfo& session) {
        double confidence = 0.35 + 0.4 * calibratedScore;
        if (risk.highRiskConfirmed) {
            confidence += 0.18;
        }
        if (session.count > 10) {
            confidence += 0.05;
        }
        if (session.interArrivalMs.n > 3) {
            confidence += 0.04;
        }
        return std::clamp(confidence, 0.0, 1.0);
    }

    std::string determineLabel(double score, const RiskAssessment& risk) {
        if (score >= HIGH_RISK_THRESHOLD || risk.highRiskConfirmed) {
            return "High";
        }
        if (score >= MEDIUM_RISK_THRESHOLD) {
            return "Medium";
        }
        return "Low";
    }

    PacketContext parsePacket(const std::vector<uint8_t>& rawData) {
        PacketContext ctx;
        ctx.length = rawData.size();
        ctx.tampered = rawData.empty();
        ctx.hookSuspected = detectHooking();

        if (rawData.empty()) {
            return ctx;
        }

        if (rawData.size() > MAX_PACKET_SIZE) {
            ctx.truncated = true;
        }

        const uint8_t* bytes = rawData.data();
        ctx.crc32 = computeCrc32(bytes, std::min(rawData.size(), MAX_PACKET_SIZE));

        uint8_t version = (bytes[0] >> 4) & 0x0F;
        if (version == 4) {
            if (rawData.size() < sizeof(iphdr)) {
                ctx.tampered = true;
                return ctx;
            }
            const iphdr* ip = reinterpret_cast<const iphdr*>(bytes);
            size_t headerLen = static_cast<size_t>(ip->ihl) * 4u;
            if (headerLen < sizeof(iphdr) || headerLen > rawData.size()) {
                ctx.tampered = true;
                return ctx;
            }
            ctx.srcIp = toIPv4String(ip->saddr);
            ctx.dstIp = toIPv4String(ip->daddr);
            ctx.hopLimit = ip->ttl;

            if (!isPrivateIPv4(ip->daddr)) {
                ctx.direction = "outbound";
            } else if (!isPrivateIPv4(ip->saddr)) {
                ctx.direction = "inbound";
            } else {
                ctx.direction = "lan";
            }

            const uint8_t* l4 = bytes + headerLen;
            size_t remain = rawData.size() - headerLen;
            ctx.payloadLength = remain;

            if (ip->protocol == IPPROTO_TCP && remain >= sizeof(tcphdr)) {
                ctx.protocol = "TCP";
                const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
                ctx.srcPort = ntohs(tcp->source);
                ctx.dstPort = ntohs(tcp->dest);
                size_t tcpHeaderLen = static_cast<size_t>(tcp->doff) * 4u;
                if (tcpHeaderLen < sizeof(tcphdr) || tcpHeaderLen > remain) {
                    ctx.tampered = true;
                    return ctx;
                }
                ctx.payloadLength = remain - tcpHeaderLen;
                const uint8_t* payload = l4 + tcpHeaderLen;
                bool likelyTls = (ctx.srcPort == 443 || ctx.dstPort == 443 ||
                                   ctx.srcPort == 8443 || ctx.dstPort == 8443 ||
                                   ctx.dstPort == 9443);
                if (likelyTls && ctx.payloadLength >= 6) {
                    ctx.tls = inspectTlsPayload(payload, ctx.payloadLength);
                }
            } else if (ip->protocol == IPPROTO_UDP && remain >= sizeof(udphdr)) {
                ctx.protocol = "UDP";
                const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
                ctx.srcPort = ntohs(udp->source);
                ctx.dstPort = ntohs(udp->dest);
                size_t udpHeaderLen = sizeof(udphdr);
                ctx.payloadLength = remain > udpHeaderLen ? remain - udpHeaderLen : 0;
                if (ctx.srcPort == 53 || ctx.dstPort == 53) {
                    const uint8_t* dnsPtr = l4 + udpHeaderLen;
                    size_t dnsLen = remain > udpHeaderLen ? remain - udpHeaderLen : 0;
                    ctx.dns = parseDns(dnsPtr, dnsLen);
                    ctx.dnsParsed = ctx.dns.ok;
                }
            }
        } else if (version == 6) {
            if (rawData.size() < sizeof(ip6_hdr)) {
                ctx.tampered = true;
                return ctx;
            }
            const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(bytes);
            ctx.srcIp = toIPv6String(ip6->ip6_src);
            ctx.dstIp = toIPv6String(ip6->ip6_dst);
            ctx.hopLimit = ip6->ip6_hlim;

            const uint8_t* l4 = bytes + sizeof(ip6_hdr);
            size_t remain = rawData.size() - sizeof(ip6_hdr);
            ctx.payloadLength = remain;
            uint8_t next = ip6->ip6_nxt;

            if (next == IPPROTO_TCP && remain >= sizeof(tcphdr)) {
                ctx.protocol = "TCP";
                const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
                ctx.srcPort = ntohs(tcp->source);
                ctx.dstPort = ntohs(tcp->dest);
                size_t tcpHeaderLen = static_cast<size_t>(tcp->doff) * 4u;
                if (tcpHeaderLen < sizeof(tcphdr) || tcpHeaderLen > remain) {
                    ctx.tampered = true;
                    return ctx;
                }
                ctx.payloadLength = remain - tcpHeaderLen;
                const uint8_t* payload = l4 + tcpHeaderLen;
                bool likelyTls = (ctx.srcPort == 443 || ctx.dstPort == 443 ||
                                   ctx.srcPort == 8443 || ctx.dstPort == 8443 ||
                                   ctx.dstPort == 9443);
                if (likelyTls && ctx.payloadLength >= 6) {
                    ctx.tls = inspectTlsPayload(payload, ctx.payloadLength);
                }
            } else if (next == IPPROTO_UDP && remain >= sizeof(udphdr)) {
                ctx.protocol = "UDP";
                const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
                ctx.srcPort = ntohs(udp->source);
                ctx.dstPort = ntohs(udp->dest);
                size_t udpHeaderLen = sizeof(udphdr);
                ctx.payloadLength = remain > udpHeaderLen ? remain - udpHeaderLen : 0;
                if (ctx.srcPort == 53 || ctx.dstPort == 53) {
                    const uint8_t* dnsPtr = l4 + udpHeaderLen;
                    size_t dnsLen = remain > udpHeaderLen ? remain - udpHeaderLen : 0;
                    ctx.dns = parseDns(dnsPtr, dnsLen);
                    ctx.dnsParsed = ctx.dns.ok;
                }
            }
        } else {
            ctx.tampered = true;
            return ctx;
        }

        ctx.valid = true;
        ctx.entropy = calculateEntropy(rawData.data(), std::min(rawData.size(), static_cast<size_t>(512)));
        return ctx;
    }

} // namespace

PacketAnalysisResult PacketAnalyzer::analyzePacket(const std::vector<uint8_t>& rawData) {
    PacketAnalysisResult result;

    PacketContext ctx = parsePacket(rawData);
    JsonBuilder json;
    json.kv("bytes", static_cast<int64_t>(ctx.length));
    json.kv("crc32", static_cast<uint64_t>(ctx.crc32));
    json.kv("truncated", ctx.truncated);
    json.kv("hookSuspected", ctx.hookSuspected);
    json.kv("integrityViolation", ctx.tampered);

    if (!ctx.srcIp.empty()) json.kv("src", ctx.srcIp);
    if (!ctx.dstIp.empty()) json.kv("dst", ctx.dstIp);
    json.kv("proto", ctx.protocol);
    json.kv("srcPort", static_cast<int64_t>(ctx.srcPort));
    json.kv("dstPort", static_cast<int64_t>(ctx.dstPort));
    json.kv("direction", ctx.direction);
    json.kv("payloadBytes", static_cast<int64_t>(ctx.payloadLength));
    json.kv("entropy", ctx.entropy);
    json.kv("hopLimit", static_cast<int64_t>(ctx.hopLimit));
    json.kv("tlsParsed", ctx.tls.parsed);
    json.kv("tlsClientHello", ctx.tls.clientHello);
    json.kv("tlsMalformed", ctx.tls.malformed);
    json.kv("tlsCipherCount", static_cast<int64_t>(ctx.tls.cipherCount));
    json.kv("tlsVersion", static_cast<int64_t>(ctx.tls.version));
    if (!ctx.tls.serverName.empty()) json.kv("tlsServerName", ctx.tls.serverName);

    if (ctx.dnsParsed) {
        JsonBuilder dnsJson;
        dnsJson.kv("qname", ctx.dns.qname);
        dnsJson.kv("qtype", static_cast<int64_t>(ctx.dns.qtype));
        dnsJson.kv("rcode", static_cast<int64_t>(ctx.dns.rcode));
        json.raw("dns", dnsJson.str());
    }

    RiskAssessment risk;
    if (!ctx.valid) {
        risk.highRiskConfirmed = true;
        risk.primaryScore = std::max(risk.primaryScore, ABSOLUTE_HIGH_SCORE);
        risk.primaryReason = "Malformed or unsupported packet";
    }

    if (ctx.hookSuspected) {
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "Hooking or tampering indicator detected");
    }
    if (ctx.tampered) {
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "Packet integrity violation detected");
    }

    const std::string sessionKey = (!ctx.srcIp.empty() || !ctx.dstIp.empty())
                                   ? (ctx.srcIp + "->" + ctx.dstIp + ':' + std::to_string(ctx.dstPort))
                                   : std::string("unknown:") + std::to_string(ctx.dstPort);
    SessionInfo sessionInfo = registerSession(sessionKey, ctx.payloadLength, ctx.length, ctx.direction);

    applyPortHeuristics(ctx, risk);
    applyDnsHeuristics(ctx, risk);
    applyBehaviorHeuristics(ctx, sessionInfo, risk);
    applyTlsHeuristics(ctx, risk);

    if (ctx.direction == "inbound" && ctx.payloadLength > 512 && ctx.entropy > 6.5) {
        risk.secondaryScore = std::max(risk.secondaryScore, 0.7);
        risk.secondaryReason = "High-entropy inbound payload";
    }

    if (ctx.dnsParsed && ctx.dns.qname.size() == 0) {
        risk.secondaryScore = std::max(risk.secondaryScore, 0.65);
        risk.secondaryReason = "Empty DNS query";
    }

    JsonBuilder sessionJson;
    sessionJson.kv("count", static_cast<int64_t>(sessionInfo.count));
    sessionJson.kv("bytes", static_cast<int64_t>(sessionInfo.totalBytes));
    sessionJson.kv("smallPayloadRatio", safeRatio(sessionInfo.smallPayloadCount, sessionInfo.count));
    sessionJson.kv("meanPayload", sessionInfo.payloadStats.mean);
    sessionJson.kv("payloadStddev", sessionInfo.payloadStats.stddev());
    sessionJson.kv("meanInterArrivalMs", sessionInfo.interArrivalMs.mean);
    sessionJson.kv("interArrivalStddev", sessionInfo.interArrivalMs.stddev());
    sessionJson.kv("burstPackets", static_cast<int64_t>(sessionInfo.burstPackets));
    sessionJson.kv("burstSmallPayloads", static_cast<int64_t>(sessionInfo.burstSmallPayloads));
    sessionJson.kv("burstSmallPayloadRatio", safeRatio(sessionInfo.burstSmallPayloads, sessionInfo.burstPackets));
    sessionJson.kv("inboundPackets", static_cast<int64_t>(sessionInfo.inboundPackets));
    sessionJson.kv("outboundPackets", static_cast<int64_t>(sessionInfo.outboundPackets));
    json.raw("session", sessionJson.str());

    double rawScore = consolidateScore(risk);
    double finalScore = calibrateScore(rawScore, risk, sessionInfo);
    std::string label = determineLabel(finalScore, risk);

    if (label != "High" && risk.highRiskConfirmed) {
        label = "High";
        finalScore = std::max(finalScore, ABSOLUTE_HIGH_SCORE);
        risk.possibleFalseNegative = true;
    }

    json.kv("riskLabel", label);
    json.kv("rawRiskScore", rawScore);
    json.kv("riskScore", finalScore);
    json.kv("confidence", computeConfidence(finalScore, risk, sessionInfo));

    bool blocked = label == "High";
    json.kv("blocked", blocked);

    JsonBuilder assurance;
    assurance.kv("primary", risk.primaryReason.empty() ? "none" : risk.primaryReason);
    assurance.kv("secondary", risk.secondaryReason.empty() ? "none" : risk.secondaryReason);
    assurance.kv("correlation", risk.correlationReason.empty() ? "none" : risk.correlationReason);
    assurance.kv("falseNegativeGuard", risk.possibleFalseNegative);
    assurance.kv("highRiskConfirmed", risk.highRiskConfirmed);
    json.raw("assurance", assurance.str());

    result.json = json.str();
    result.highRisk = (label == "High");
    return result;
}