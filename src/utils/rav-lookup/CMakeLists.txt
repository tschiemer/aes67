cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(rav-lookup)

add_executable(rav-lookup
        rav-lookup.c
        aes67opts.h
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(rav-lookup
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(rav-lookup "${AES67_PORT_LIB}")


