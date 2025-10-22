#include "FirewallController.hpp"

#include <mutex>
#include <unordered_map>

namespace firewall {

namespace {
    std::mutex gMutex;
    std::unordered_map<std::string, bool> gRules;
}

void setRule(const std::string& packageName, bool allow) {
    if (packageName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gMutex);
    if (allow) {
        gRules.erase(packageName);
    } else {
        gRules[packageName] = false;
    }
}

bool isAllowed(const std::string& packageName) {
    if (packageName.empty()) {
        return true;
    }
    std::lock_guard<std::mutex> lock(gMutex);
    const auto it = gRules.find(packageName);
    if (it == gRules.end()) {
        return true;
    }
    return it->second;
}

void clearAll() {
    std::lock_guard<std::mutex> lock(gMutex);
    gRules.clear();
}

} // namespace firewall

