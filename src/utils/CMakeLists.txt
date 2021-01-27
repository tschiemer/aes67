cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-utils)

add_executable(sap sap.cpp)
target_include_directories(sap
        PRIVATE
        ${AES67_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sap aes67 "${AES67_PORT_LIB}")


add_executable(sap-pack sap-pack.c)
target_include_directories(sap-pack
        PRIVATE
        ${AES67_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sap-pack aes67 "${AES67_PORT_LIB}")


