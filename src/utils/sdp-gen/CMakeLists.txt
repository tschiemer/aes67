cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sdp-gen)

add_executable(sdp-gen
        sdp-gen.c
        aes67opts.h
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(sdp-gen
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sdp-gen "${AES67_PORT_LIB}")


