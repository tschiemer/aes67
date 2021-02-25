cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(rtsp-describe)

add_executable(rtsp-describe
        rtsp-describe.c
        aes67opts.h
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(rtsp-describe
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(rtsp-describe "${AES67_PORT_LIB}")


