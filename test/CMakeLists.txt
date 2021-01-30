cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-test)


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

set(TEST_UNIT_INCLUDES
        stubs/host/timer.h
        stubs/host/time.h
        )

set(TEST_UNIT_SOURCE_FILES
        stubs/host/timer.c
        stubs/host/time.c

        unit/def.cpp
        unit/net.cpp
        unit/sap.cpp
        unit/sdp.cpp
        )


#if(AES67_WITH_SAP)
#    list(APPEND AES67_INCLUDES src/include/aes67/sap.h)
#    list(APPEND AES67_SOURCE_FILES  src/core/sap.c)
#endif()

add_executable(run_tests
        test_runner.cpp
        ${TEST_UNIT_INCLUDES}
        ${TEST_UNIT_SOURCE_FILES}
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        )
target_include_directories(run_tests PRIVATE
        ${AES67_INCLUDE_DIRS}
        "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(run_tests PRIVATE CppUTest CppUTestExt)


list(APPEND AES67_TARGET_LIST run_tests)