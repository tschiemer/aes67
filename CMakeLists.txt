cmake_minimum_required(VERSION 3.3)
project(aes67)

if(NOT USER_INCLUDE_DIRS)
    set(USER_INCLUDE_DIRS
            "contrib/ports/unix/port/include"
            )
endif()

set(AES67_CORE_INCLUDES

        src/include/ocac/opt.h
        src/include/ocac/arch.h
        src/include/ocac/debug.h
        src/include/ocac/def.h

#        src/include/ocac/host/timer.h
#        src/include/ocac/host/sock.h
        )

set(AES67_SOURCE_FILES

        src/core/def.c
        )


add_library(aes67 STATIC
        ${AES67_INCLUDES}
        ${AES67_SOURCE_FILES}
        ${USER_INCLUDES}
        )
target_include_directories(aes67 PUBLIC
        src/include
        "${USER_INCLUDE_DIRS}"
        )

set_property(TARGET aes67 PROPERTY C_STANDARD 99)
set_property(TARGET aes67 PROPERTY LINKER_LANGUAGE C)
