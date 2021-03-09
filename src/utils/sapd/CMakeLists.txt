cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(sapd)

if (NOT DEFINED SAPD_WITH_RAV)
    set(SAPD_WITH_RAV TRUE)
endif()

if (${SAPD_WITH_RAV})

    if (NOT DEFINED AES67_MDNS)
        message(FATAL_ERROR Please define an mDNS implementation.)
    endif()

    set(RAV_SOURCE_FILES
            ${AES67_DIR}/src/include/aes67/utils/mdns.h
            ${AES67_DIR}/src/utils/mdns-${AES67_MDNS}.c
    )
endif()

add_executable(sapd
        sapd.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/sapsrv.h
        ${AES67_DIR}/src/include/aes67/utils/sapd.h
        ${AES67_DIR}/src/include/aes67/utils/daemonize.h
        ${AES67_DIR}/src/utils/sapsrv.c
        ${AES67_DIR}/src/utils/daemonize.c
        ${RAV_SOURCE_FILES}
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


