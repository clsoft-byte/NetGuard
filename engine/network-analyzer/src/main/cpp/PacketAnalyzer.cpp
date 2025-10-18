//
// Created by Cardiell on 12/10/25.
//

#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

#include <arpa/inet.h>
#include <netinet/ip.h>    // IPv4
#include <netinet/ip6.h>   // IPv6
#include <netinet/tcp.h>
#include <netinet/udp.h>

// -------------- Utilidades JSON (sin librerías externas) -----------------

static void jsonEscape(const std::string& in, std::ostringstream& out) {
    out << '"';
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b";  break;
            case '\f': out << "\\f";  break;
            case '\n': out << "\\n";  break;
            case '\r': out << "\\r";  break;
            case '\t': out << "\\t";  break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << (int)c << std::dec;
                } else {
                    out << c;
                }
        }
    }
    out << '"';
}

static void jsonKV(std::ostringstream& out, const char* key, const std::string& val, bool last=false) {
    out << '"'; out << key; out << "\":";
    jsonEscape(val, out);
    if (!last) out << ',';
}
static void jsonKV(std::ostringstream& out, const char* key, const char* val, bool last=false) {
    out << '"'; out << key; out << "\":";
    jsonEscape(std::string(val), out);
    if (!last) out << ',';
}
static void jsonKV(std::ostringstream& out, const char* key, int64_t val, bool last=false) {
    out << '"'; out << key; out << "\":" << val;
    if (!last) out << ',';
}
static void jsonKV(std::ostringstream& out, const char* key, double val, bool last=false) {
    out << '"'; out << key; out << "\":" << std::fixed << std::setprecision(2) << val;
    if (!last) out << ',';
}
static void jsonKV(std::ostringstream& out, const char* key, bool val, bool last=false) {
    out << '"'; out << key; out << "\":" << (val ? "true" : "false");
    if (!last) out << ',';
}

// ---------------- DNS mínimo (solo header y QNAME de primera pregunta) ----------------

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};
#pragma pack(pop)

struct DnsMinimal {
    bool ok = false;
    std::string qname;
    uint16_t qtype = 0;
    uint16_t rcode = 0; // flags bits 0..3
};

static bool isPrintableDomainChar(char c) {
    return (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='-' || c=='.' || c=='_';
}

static DnsMinimal parseDns(const uint8_t* data, size_t len) {
    DnsMinimal out;
    if (len < sizeof(DnsHeader)) return out;
    const DnsHeader* hdr = reinterpret_cast<const DnsHeader*>(data);
    const uint16_t flags = ntohs(hdr->flags);
    out.rcode = flags & 0x000F;
    uint16_t qd = ntohs(hdr->qdCount);
    if (qd == 0) return out;

    size_t off = sizeof(DnsHeader);
    // parse QNAME
    std::ostringstream qn;
    while (off < len) {
        uint8_t labLen = data[off++];
        if (labLen == 0) break; // end
        if (labLen & 0xC0) { // compression not supported in queries usually, but bail out
            return out;
        }
        if (off + labLen > len) return out;
        for (size_t i=0;i<labLen;i++) {
            char c = (char)data[off+i];
            qn << (isPrintableDomainChar(c) ? c : '_');
        }
        off += labLen;
        if (off < len) qn << '.';
        if (qn.tellp() > 253) break; // domain max len
    }
    if (off + 4 > len) return out;
    out.qname = qn.str();
    out.qtype = ntohs(*reinterpret_cast<const uint16_t*>(data+off));
    // uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t*>(data+off+2)); // usually IN=1
    out.ok = true;
    return out;
}

// ---------------- Heurísticas de riesgo (ligeras, ampliables) ----------------

static bool isPrivateIPv4(uint32_t beAddr) {
    // beAddr: network byte order
    uint32_t addr = ntohl(beAddr);
    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((addr & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((addr & 0xFFFF0000) == 0xC0A80000) return true;
    // 127.0.0.0/8 (loopback)
    if ((addr & 0xFF000000) == 0x7F000000) return true;
    return false;
}

static void riskFromPorts(int dstPort, std::string& label, double& score) {
    // base
    if (dstPort == 22 || dstPort == 23 || dstPort == 445 || dstPort == 3389) { // SSH/Telnet/SMB/RDP
        label = "High";
        score = std::max(score, 0.90);
    } else if (dstPort == 53) { // DNS
        label = "Medium";
        score = std::max(score, 0.40);
    } else if (dstPort == 80 || dstPort == 443) {
        label = (score >= 0.6 ? "High" : "Medium");
        score = std::max(score, 0.50);
    } else {
        // keep defaults
    }
}

static void riskFromDns(const DnsMinimal& dns, std::string& label, double& score) {
    if (!dns.ok) return;
    // Heurística básica: dominios muy largos o con muchos labels → posible tunneling
    if (dns.qname.size() > 80) {
        score = std::max(score, 0.65);
        label = (score >= 0.8) ? "High" : "Medium";
    }
    // Tipos poco comunes pueden sumar un poco (0x00FF ANY, 0x0029 OPT)
    if (dns.qtype == 255 || dns.qtype == 41) {
        score = std::max(score, 0.55);
        label = "Medium";
    }
}

// ----------------- Analizador principal --------------------

// NativeBridge.cpp
#include <jni.h>
#include <string>
#include <vector>

// Declaración de tu clase (el .cpp que pegaste)



class PacketAnalyzer {
public:
    // Devuelve JSON compacto con:
    // src, dst, proto, srcPort, dstPort, bytes, direction, dns (si aplica),
    // riskLabel, riskScore, blocked
    static std::string analyzePacket(const std::string& rawData);

};

static std::string toIpStringV4(uint32_t beAddr) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &beAddr, buf, sizeof(buf));
    return std::string(buf);
}

std::string PacketAnalyzer::analyzePacket(const std::string& rawData) {
    std::ostringstream out;

    if (rawData.size() < 1) {
        out << "{\"error\":\"empty\"}";
        return out.str();
    }

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(rawData.data());
    const size_t   len   = rawData.size();

    // JSON scaffold
    out << '{';
    jsonKV(out, "bytes", (int64_t)len);

    // Detección de versión (primer nibble)
    uint8_t version = (bytes[0] >> 4) & 0x0F;

    std::string proto = "OTHER";
    int srcPort = 0, dstPort = 0;
    std::string srcIp = "", dstIp = "";
    std::string direction = "outbound"; // heurística: VPN TUN suele ver outbound principalmente
    bool blocked = false;
    std::string riskLabel = "Low";
    double riskScore = 0.10;

    if (version == 4) {
        if (len < sizeof(iphdr)) {
            out << ",\"error\":\"short ipv4\"}";
            return out.str();
        }
        const iphdr* ip = reinterpret_cast<const iphdr*>(bytes);
        size_t ihlBytes = (size_t)ip->ihl * 4;
        if (ihlBytes < sizeof(iphdr) || ihlBytes > len) {
            out << ",\"error\":\"bad ihl\"}";
            return out.str();
        }

        srcIp = toIpStringV4(ip->saddr);
        dstIp = toIpStringV4(ip->daddr);
        jsonKV(out, "src", srcIp.c_str());
        jsonKV(out, "dst", dstIp.c_str());

        // Ajuste simple de direction: si destino no es RFC1918 → outbound a Internet
        if (!isPrivateIPv4(ip->daddr)) direction = "outbound";
        else if (!isPrivateIPv4(ip->saddr))     direction = "inbound";
        else                                    direction = "lan";

        const uint8_t* l4 = bytes + ihlBytes;
        size_t remain = len - ihlBytes;

        if (ip->protocol == IPPROTO_TCP && remain >= sizeof(tcphdr)) {
            proto = "TCP";
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
            srcPort = ntohs(tcp->source);
            dstPort = ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP && remain >= sizeof(udphdr)) {
            proto = "UDP";
            const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
            srcPort = ntohs(udp->source);
            dstPort = ntohs(udp->dest);

            // DNS parse si dstPort/srcPort = 53 y hay payload suficiente
            size_t udpHeaderLen = sizeof(udphdr);
            if (remain > udpHeaderLen) {
                const uint8_t* dnsPtr = l4 + udpHeaderLen;
                size_t dnsLen = remain - udpHeaderLen;
                if (srcPort == 53 || dstPort == 53) {
                    DnsMinimal dns = parseDns(dnsPtr, dnsLen);
                    if (dns.ok) {
                        out << "\"dns\":{";
                        jsonKV(out, "qname", dns.qname, false);
                        jsonKV(out, "qtype", (int64_t)dns.qtype, false);
                        jsonKV(out, "rcode", (int64_t)dns.rcode, true);
                        out << "},";
                        // Heurística de riesgo por DNS
                        riskFromDns(dns, riskLabel, riskScore);
                    }
                }
            }
        } else {
            proto = "OTHER";
        }

        jsonKV(out, "proto", proto.c_str());
        jsonKV(out, "srcPort", (int64_t)srcPort);
        jsonKV(out, "dstPort", (int64_t)dstPort);
        jsonKV(out, "direction", direction.c_str());

        // Reglas de riesgo básicas por puertos
        riskFromPorts(dstPort, riskLabel, riskScore);

    } else if (version == 6) {
        if (len < sizeof(ip6_hdr)) {
            out << ",\"error\":\"short ipv6\"}";
            return out.str();
        }
        const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(bytes);

        char src6[INET6_ADDRSTRLEN] = {0};
        char dst6[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &ip6->ip6_src, src6, sizeof(src6));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst6, sizeof(dst6));
        srcIp = src6; dstIp = dst6;

        jsonKV(out, "src", srcIp.c_str());
        jsonKV(out, "dst", dstIp.c_str());

        const uint8_t* l4 = bytes + sizeof(ip6_hdr);
        size_t remain = len - sizeof(ip6_hdr);
        uint8_t nxt = ip6->ip6_nxt;

        // Nota: aquí no resolvemos headers de extensión; para algo rápido nos quedamos con ip6_nxt
        if (nxt == IPPROTO_TCP && remain >= sizeof(tcphdr)) {
            proto = "TCP";
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
            srcPort = ntohs(tcp->source);
            dstPort = ntohs(tcp->dest);
        } else if (nxt == IPPROTO_UDP && remain >= sizeof(udphdr)) {
            proto = "UDP";
            const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
            srcPort = ntohs(udp->source);
            dstPort = ntohs(udp->dest);

            size_t udpHeaderLen = sizeof(udphdr);
            if (remain > udpHeaderLen) {
                const uint8_t* dnsPtr = l4 + udpHeaderLen;
                size_t dnsLen = remain - udpHeaderLen;
                if (srcPort == 53 || dstPort == 53) {
                    DnsMinimal dns = parseDns(dnsPtr, dnsLen);
                    if (dns.ok) {
                        out << "\"dns\":{";
                        jsonKV(out, "qname", dns.qname, false);
                        jsonKV(out, "qtype", (int64_t)dns.qtype, false);
                        jsonKV(out, "rcode", (int64_t)dns.rcode, true);
                        out << "},";
                        riskFromDns(dns, riskLabel, riskScore);
                    }
                }
            }
        } else {
            proto = "OTHER";
        }

        jsonKV(out, "proto", proto.c_str());
        jsonKV(out, "srcPort", (int64_t)srcPort);
        jsonKV(out, "dstPort", (int64_t)dstPort);
        jsonKV(out, "direction", direction.c_str());

        riskFromPorts(dstPort, riskLabel, riskScore);

    } else {
        out << ",\"error\":\"unsupported ip version\"}";
        return out.str();
    }

    // --- Acción (placeholder): aquí puedes cruzar con tus RuleEntity (ALLOW/BLOCK)
    // blocked = (riskScore >= 0.85); // ejemplo si quieres modo agresivo
    // En producción: consulta tus reglas por app/host/puerto/SNI antes de decidir.

    jsonKV(out, "riskLabel", riskLabel.c_str());
    jsonKV(out, "riskScore", riskScore);
    jsonKV(out, "blocked", blocked, true);
    out << '}';

    return out.str();
}

