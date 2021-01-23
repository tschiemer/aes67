cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67)

set(AES67_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT USER_INCLUDE_DIRS)
    set(USER_INCLUDE_DIRS
            "${AES67_DIR}/contrib/ports/unix/include"
            )
endif()

set(AES67_WITH_SAP TRUE)
set(AES67_WITH_SIP TRUE)


#set(AES67_DEV_UTILS TRUE)

set(AES67_INCLUDES

        src/include/aes67/opt.h
        src/include/aes67/arch.h
        src/include/aes67/debug.h
        src/include/aes67/def.h

        src/include/aes67/net.h
        src/include/aes67/ptp.h
        src/include/aes67/sdp.h

#        src/include/aes67/host/timer.h
#        src/include/aes67/host/sock.h
        )

set(AES67_SOURCE_FILES

        src/core/def.c

        src/core/net.c
        src/core/sdp.c

        )

if(AES67_WITH_SAP)
    list(APPEND AES67_INCLUDES src/include/aes67/sap.h)
    list(APPEND AES67_SOURCE_FILES  src/core/sap.c)
endif()

if(AES67_WITH_SIP)
    list(APPEND AES67_INCLUDES src/include/aes67/sip.h)
#    list(APPEND AES67_SOURCE_FILES  src/core/sip.c)
endif()


list(APPEND AES67_TARGET_LIST aes67)
add_library(aes67 STATIC
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        ${USER_INCLUDES}
        )
target_include_directories(aes67 PRIVATE ${AES67_DIR})
target_include_directories(aes67 PUBLIC
        src/include
        "${USER_INCLUDE_DIRS}"
        )

set_property(TARGET aes67 PROPERTY C_STANDARD 99)
set_property(TARGET aes67 PROPERTY LINKER_LANGUAGE C)


#if(AES67_DEV_UTILS)
    include(contrib/dev/Targets.cmake)
#endif()




#if(TESTS)

    # CppUTest
    include(FetchContent)
    FetchContent_Declare(
            CppUTest
            GIT_REPOSITORY https://github.com/cpputest/cpputest.git
            GIT_TAG        latest-passing-build # or use release tag, eg. v3.8
    )
    # Set this to ON if you want to have the CppUTests in your project as well.
    set(TESTS OFF CACHE BOOL "Switch off CppUTest Test build")
    FetchContent_MakeAvailable(CppUTest)

    set(TEST_UNIT_SOURCE_FILES
            test/stubs/timer.c
            test/stubs/time.c

            test/unit/def.cpp
            test/unit/net.cpp
            test/unit/sap.cpp
            )

    add_executable(run_tests
            test/test_runner.cpp
            ${TEST_UNIT_SOURCE_FILES}
            ${AES67_INCLUDES}
            ${AES67_SOURCE_FILES}
            )
    target_include_directories(run_tests PRIVATE
            src/include
            "${USER_INCLUDE_DIRS}"
            "${AES67_DIR}/test/")
    target_link_libraries(run_tests PRIVATE CppUTest CppUTestExt)


    list(APPEND AES67_TARGET_LIST run_tests)
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
