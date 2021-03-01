cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sap-server)


add_executable(sap-server
        sap-server.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/sapsrv.h
        ${AES67_DIR}/src/utils/sapsrv.c
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(sap-server
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sap-server "${AES67_PORT_LIB}")


