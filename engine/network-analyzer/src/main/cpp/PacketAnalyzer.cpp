//
// Created by Cardiell on 12/10/25.
//

#include "PacketAnalyzer.hpp"
#include <sstream>

std::string PacketAnalyzer::analyzePacket(const std::string& rawData) {
    // Aquí se podrían parsear encabezados IP/TCP/UDP.
    // Por ahora devolvemos una descripción simulada.
    std::stringstream ss;
    ss << "Packet(" << rawData << "): OK";
    return ss.str();
}