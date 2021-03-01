cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-utils)

add_subdirectory(sap-pack)
add_subdirectory(sap-unpack)
add_subdirectory(sap-server)

add_subdirectory(sdp-parse)
add_subdirectory(sdp-gen)

add_subdirectory(rtsp-describe)

add_subdirectory(rav-lookup)
add_subdirectory(rav2sap)


