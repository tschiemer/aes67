cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#set(dir ${CMAKE_CURRENT_SOURCE_DIR}/build)


project(aes67)

################
################ User Options
################

# Which port to use
# see dir ports (ie macos, unix)
# if not set assumes is setup will guess based on platform
#set(AES67_PORT "macos")

# Explicitly specify which mDNS backend implementation to use:
# - dnssd
# - avahi
# If not set, will try to guess based on platform.
#set(AES67_MDNS "dnssd")

# Compile Ravenna support into sapd
set(SAPD_WITH_RAV TRUE)


################
################ Core Configuration
################

set(AES67_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(AES67_INCLUDE_DIRS
        ${AES67_DIR}/src/include
        ${AES67_DIR}/src/third_party
)
set(AES67_THIRDPARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party")

set(CMAKE_C_FLAGS "-Wall -O")

set(AES67_INCLUDES

        ${AES67_DIR}/src/include/aes67/opt.h
        ${AES67_DIR}/src/include/aes67/arch.h
        ${AES67_DIR}/src/include/aes67/debug.h
        ${AES67_DIR}/src/include/aes67/def.h

        ${AES67_DIR}/src/include/aes67/net.h
        ${AES67_DIR}/src/include/aes67/ptp.h
        ${AES67_DIR}/src/include/aes67/sdp.h
        ${AES67_DIR}/src/include/aes67/sap.h
        ${AES67_DIR}/src/include/aes67/rtp-avp.h
        ${AES67_DIR}/src/include/aes67/rtp.h
        ${AES67_DIR}/src/include/aes67/audio.h

        ${AES67_DIR}/src/include/aes67/host/time.h
        ${AES67_DIR}/src/include/aes67/host/timer.h

        #        src/include/aes67/host/sock.h
)

set(AES67_SOURCE_FILES

        ${AES67_DIR}/src/core/def.c
        ${AES67_DIR}/src/core/net.c

        ${AES67_DIR}/src/core/sdp.c
        ${AES67_DIR}/src/core/sap.c
        ${AES67_DIR}/src/core/rtp.c

)

################
################ Platform Port
################

if (NOT DEFINED ${AES67_PORT})
    message(STATUS "No aes67 ports specified, trying to guess")

    if (APPLE)
        set(AES67_PORT "macos")
    elseif(UNIX)
        set(AES67_PORT "unix")
    elseif(WIN32)
        set(AES67_PORT "win32")
    endif()
endif()

message(STATUS "aes67 platform/port: ${AES67_PORT}")
if(AES67_PORT)
    set(AES67_PORT_DIR "${AES67_DIR}/ports/${AES67_PORT}")
    set(AES67_PORT_LIB "aes67-port-${AES67_PORT}")
    add_subdirectory("${AES67_PORT_DIR}")
else()
    message(FATAL_ERROR "no port defined!")
endif()

################
################ mDNS backend
################

if (NOT DEFINED ${AES67_MDNS})
    message(STATUS "No mDNS backend selected, trying to guess")

    if (APPLE)
        set(AES67_MDNS "dnssd")
    elseif(UNIX)
        set(AES67_MDNS "avahi")
    elseif(WIN32)
        # assume that windows machines will use bonjour
        set(AES67_MDNS "dnssd")
    endif()
endif()

message(STATUS "mDNS backend: ${AES67_MDNS}")
if ("${AES67_MDNS}" STREQUAL "dnssd")

    find_package(DNSSD REQUIRED)

    set(AES67_MDNS_SOURCE_FILES
            ${AES67_DIR}/src/utils/mdns-dnssd.c
    )
    set(AES67_MDNS_INCLUDE_DIRS ${DNSSD_INCLUDE_DIRS})
    set(AES67_MDNS_LIBRARIES ${DNSSD_LIBRARIES})

elseif("${AES67_MDNS}" STREQUAL "avahi")

    find_package(Avahi REQUIRED)

    set(AES67_MDNS_SOURCE_FILES ${AES67_DIR}/src/utils/mdns-avahi.c)
    set(AES67_MDNS_INCLUDE_DIRS ${Avahi_CLIENT_INCLUDE_DIRS})
    set(AES67_MDNS_LIBRARIES ${Avahi_COMMON_LIBRARY} ${Avahi_CLIENT_LIBRARY})

elseif(DEFINED AES67_MDNS)
    message(ERROR "mDNS option '${AES67_MDNS}' unknown")
endif()




# Archive
list(APPEND AES67_TARGET_LIST aes67)
add_library(aes67 STATIC
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(aes67 PRIVATE
        ${AES67_DIR}
        ${AES67_PORT_INCLUDE_DIRS}
        )
target_include_directories(aes67 PUBLIC
        ${AES67_INCLUDE_DIRS}
        )
target_link_libraries(aes67 ${AES67_PORT_LIB})

# Shared library
#list(APPEND AES67_TARGET_LIST caes67)
#add_library(caes67 SHARED
#        ${AES67_INCLUDES}
#        ${AES67_SOURCE_FILES}
#        )
#target_include_directories(caes67 PRIVATE
#        ${AES67_DIR}
#        ${AES67_PORT_INCLUDE_DIRS}
#        )
#target_include_directories(caes67 PUBLIC
#        ${AES67_INCLUDE_DIRS}
#        )

set_property(TARGET aes67 PROPERTY C_STANDARD 99)
set_property(TARGET aes67 PROPERTY LINKER_LANGUAGE C)


add_subdirectory("${AES67_DIR}/test" EXCLUDE_FROM_ALL)

#if(NOT ${AES67_WITHOUT_UTILS})
    add_subdirectory("${AES67_DIR}/src/utils")
#endif()

#list(APPEND AES67_TARGET_LIST mytest)
#add_executable(mytest test.c)
#target_include_directories(mytest PRIVATE
#        ${AES67_DIR}
#        ${AES67_PORT_INCLUDE_DIRS}
#        )
#target_link_libraries(mytest aes67 ${AES67_PORT_LIB})

if(CMAKE_BUILD_TYPE MATCHES Debug)
    foreach(TARGET IN LISTS AES67_TARGET_LIST)
        target_compile_definitions(${TARGET} PUBLIC DEBUG=1)
    endforeach()
elseif(CMAKE_BUILD_TYPE MATCHES Release)
    foreach(TARGET IN LISTS AES67_TARGET_LIST)
        target_compile_definitions(${TARGET} PUBLIC RELEASE=1)
    endforeach()
endif()

install(TARGETS
        aes67
        sap-pack
        sap-unpack
        sapd
        sdp-gen
        sdp-parse
        rtsp-describe
        rav-lookup
)
install(DIRECTORY "${AES67_DIR}/src/include/aes67" DESTINATION include)
