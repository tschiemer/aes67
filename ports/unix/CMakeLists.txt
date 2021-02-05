cmake_minimum_required(VERSION 3.11)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(aes67-port-unix)

set(AES67_PORT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include" PARENT_SCOPE)

set(INCLUDES

)

message("aes ${AES67_INCLUDE_DIRS}")
message("aesport ${AES67_PORT_INCLUDE_DIRS} ")

set(SOURCE_FILES
        time.c
        timer.c
)

add_library(${PROJECT_NAME} STATIC
        ${SOURCE_FILES}
)

target_include_directories(${PROJECT_NAME}
        PRIVATE
        ${AES67_DIR}
        ${AES67_INCLUDE_DIRS}
)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include")