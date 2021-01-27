cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-unix)


set(AES67_PORT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include" PARENT_SCOPE)