#pragma once

#include <string>

namespace firewall {

void setRule(const std::string& packageName, bool allow);

bool isAllowed(const std::string& packageName);

void clearAll();

} // namespace firewall

