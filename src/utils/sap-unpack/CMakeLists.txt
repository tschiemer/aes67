cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sap-unpack)

add_executable(sap-unpack
        sap-unpack.c
        aes67opts.h
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(sap-unpack
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sap-unpack "${AES67_PORT_LIB}")


