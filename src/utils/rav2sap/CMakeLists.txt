cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(rav2sap)

add_executable(rav2sap
        rav2sap.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/mdns.h
        ${AES67_DIR}/src/utils/mdns-${AES67_MDNS}.c
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(rav2sap
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(rav2sap "${AES67_PORT_LIB}")


