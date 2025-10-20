//
// Created by Cardiell on 12/10/25.
//

#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <string>
#include <vector>

struct PacketAnalysisResult {
    std::string json;
    bool highRisk = false;
};

class PacketAnalyzer {
public:
    static PacketAnalysisResult analyzePacket(const std::vector<uint8_t>& rawData);
};

#endif