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
            ${AES67_MDNS_SOURCE_FILES}
            ${AES67_DIR}/src/include/aes67/utils/rtsp-dsc.h
            ${AES67_DIR}/src/utils/rtsp-dsc.c
            ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.h
            ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.c
    )
    set(RAV_INCLUDE_DIRS
            ${AES67_MDNS_INCLUDE_DIRS}
            )
    set(RAV_LIBRARIES ${AES67_MDNS_LIBRARIES})
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
        ${RAV_INCLUDE_DIRS}
        )
target_link_libraries(sapd "${AES67_PORT_LIB}" ${RAV_LIBRARIES})


