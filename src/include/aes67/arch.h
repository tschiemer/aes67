/**
 * AES67 Framework
 * Copyright (C) 2021  Philip Tschiemer, https://github.com/tschiemer/aes67
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef AES67_ARCH_H
#define AES67_ARCH_H

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#include "arch/cc.h"

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#ifndef AES67_PLATFORM_ASSERT
#define AES67_PLATFORM_ASSERT(x) do {printf("Assertion \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); fflush(NULL); abort();} while(0)
#include <stdio.h>
#include <stdlib.h>
#endif


#include <stdint.h>

typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;

#if !defined(AES67_HAVE_INT64) && defined(UINT64_MAX)
#define AES67_HAVE_INT64 1
#endif


typedef struct {
    u32_t msb;
    u32_t lsb;
} u64_t;

#define u64_eq(lhs, rhs)    ((lhs).msb == (rhs).msb && (lhs).lsb == (rhs).lsb)
#define u64_le(lhs, rhs)    ((lhs).msb < (rhs).msb || ((lhs).msb == (rhs).msb && (lhs).lsb < (rhs).lsb))
#define u64_gr(lhs, rhs)    ((lhs).msb > (rhs).msb || ((lhs).msb == (rhs).msb && (lhs).lsb > (rhs).lsb))


#include <limits.h>


#ifndef PACK_STRUCT
#define PACK_STRUCT __attribute__((packed))
#endif

#ifndef WEAK_FUN
#define WEAK_FUN __attribute__((weak))
#endif

#endif //AES67_ARCH_H
