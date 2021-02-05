cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-utils)

add_subdirectory(sap-pack)
add_subdirectory(sap-unpack)

add_subdirectory(sdp-parse)


