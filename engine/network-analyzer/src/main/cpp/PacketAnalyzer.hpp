//
// Created by Cardiell on 12/10/25.
//

#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <string>

class PacketAnalyzer {
public:
    static std::string analyzePacket(const std::string& rawData);
};

#endif