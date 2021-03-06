cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(rav-publish)

if (NOT DEFINED AES67_MDNS)
    message(FATAL_ERROR Please define an mDNS implementation.)
endif()

add_executable(rav-publish
        rav-publish.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/mdns.h
        ${AES67_MDNS_SOURCE_FILES}
        ${AES67_DIR}/src/include/aes67/utils/rtsp-srv.h
        ${AES67_DIR}/src/utils/rtsp-srv.c
        ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.h
        ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.c
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(rav-publish
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        ${AES67_THIRDPARTY_DIR}
        ${AES67_MDNS_INCLUDE_DIRS}
        )
target_link_libraries(rav-publish ${AES67_PORT_LIB} ${AES67_MDNS_LIBRARIES})


