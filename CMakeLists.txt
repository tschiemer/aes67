cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67)


set(AES67_PORT "macos")

set(AES67_WITH_SAP TRUE)
set(AES67_WITH_SIP TRUE)


set(AES67_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(AES67_INCLUDE_DIRS ${AES67_DIR}/src/include)

set(CMAKE_C_FLAGS "-Wall -O")

set(AES67_INCLUDES

        ${AES67_DIR}/src/include/aes67/opt.h
        ${AES67_DIR}/src/include/aes67/arch.h
        ${AES67_DIR}/src/include/aes67/debug.h
        ${AES67_DIR}/src/include/aes67/def.h

        ${AES67_DIR}/src/include/aes67/net.h
        ${AES67_DIR}/src/include/aes67/ptp.h
        ${AES67_DIR}/src/include/aes67/sdp.h
        ${AES67_DIR}/src/include/aes67/avp.h
        ${AES67_DIR}/src/include/aes67/audio.h

        ${AES67_DIR}/src/include/aes67/host/time.h
        ${AES67_DIR}/src/include/aes67/host/timer.h

#        src/include/aes67/host/sock.h
        )

set(AES67_SOURCE_FILES

        ${AES67_DIR}/src/core/def.c

        ${AES67_DIR}/src/core/net.c
        ${AES67_DIR}/src/core/sdp.c

        )

if(AES67_WITH_SAP)
    list(APPEND AES67_INCLUDES ${AES67_DIR}/src/include/aes67/sap.h)
    list(APPEND AES67_SOURCE_FILES  ${AES67_DIR}/src/core/sap.c)
endif()

if(AES67_WITH_SIP)
#    list(APPEND AES67_INCLUDES src/include/aes67/sip.h)
#    list(APPEND AES67_SOURCE_FILES  src/core/sip.c)
endif()


if(AES67_PORT)
    set(AES67_PORT_DIR "${AES67_DIR}/ports/${AES67_PORT}")
    set(AES67_PORT_LIB "aes67-port-${AES67_PORT}")
    add_subdirectory("${AES67_PORT_DIR}")
endif()




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

set_property(TARGET aes67 PROPERTY C_STANDARD 99)
set_property(TARGET aes67 PROPERTY LINKER_LANGUAGE C)


add_subdirectory("${AES67_DIR}/test" EXCLUDE_FROM_ALL)

add_subdirectory("${AES67_DIR}/src/utils" EXCLUDE_FROM_ALL)

#if(AES67_DEV_UTILS)
#    include(contrib/dev/Targets.cmake)
#endif()




#if(TESTS)

#endif()


if(CMAKE_BUILD_TYPE MATCHES Debug)
    foreach(TARGET IN LISTS AES67_TARGET_LIST)
        target_compile_definitions(${TARGET} PUBLIC DEBUG=1)
    endforeach()
elseif(CMAKE_BUILD_TYPE MATCHES Release)
    foreach(TARGET IN LISTS AES67_TARGET_LIST)
        target_compile_definitions(${TARGET} PUBLIC RELEASE=1)
    endforeach()
endif()
