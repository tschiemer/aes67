cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(rav-lookup)

if (NOT DEFINED AES67_MDNS)
    message(FATAL_ERROR Please define an mDNS implementation.)
endif()

add_executable(rav-lookup
        rav-lookup.c
        aes67opts.h
        ${AES67_DIR}/src/include/aes67/utils/mdns.h
        ${AES67_DIR}/src/utils/mdns-${AES67_MDNS}.c
        ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.h
        ${AES67_DIR}/src/third_party/dnmfarrell/URI-Encode-C/src/uri_encode.c
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(rav-lookup
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AES67_INCLUDE_DIRS}
        ${AES67_PORT_INCLUDE_DIRS}
        ${AES67_THIRDPARTY_DIR}
        ${AES67_MDNS_INCLUDE_DIRS}
        )
target_link_libraries(rav-lookup ${AES67_PORT_LIB} ${AES67_MDNS_LIBRARIES})


