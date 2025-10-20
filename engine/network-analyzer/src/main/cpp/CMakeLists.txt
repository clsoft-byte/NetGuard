cmake_minimum_required(VERSION 3.22.1)
project("netguard_native")

add_library(
        netguard_native
        SHARED
        analyzer.cpp
        PacketAnalyzer.cpp
        FirewallBridge.cpp
)

find_library(
        log-lib
        log
)

find_library(
        dl-lib
        dl
)

target_link_libraries(
        netguard_native
        ${log-lib}
        ${dl-lib}
)