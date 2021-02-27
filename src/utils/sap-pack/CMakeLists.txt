cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sap-pack)

add_executable(sap-pack
        sap-pack.c
        aes67opts.h
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(sap-pack
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sap-pack "${AES67_PORT_LIB}")



