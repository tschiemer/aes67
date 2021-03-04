cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sapd)


add_executable(sapd
        sapd.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/sapsrv.h
        ${AES67_DIR}/src/include/aes67/utils/sapd.h
        ${AES67_DIR}/src/include/aes67/utils/daemonize.h
        ${AES67_DIR}/src/utils/sapsrv.c
        ${AES67_DIR}/src/utils/daemonize.c
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(sapd
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_link_libraries(sapd "${AES67_PORT_LIB}")


