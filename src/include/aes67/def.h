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
 *
 * NOTE
 */

#ifndef AES67_DEF_H
#define AES67_DEF_H

/* arch.h might define NULL already */
#include "aes67/arch.h"
#include "aes67/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif


#if BYTE_ORDER == BIG_ENDIAN
#define aes67_htons(x) ((u16_t)(x))
#define aes67_ntohs(x) ((u16_t)(x))
#define aes67_htonl(x) ((u32_t)(x))
#define aes67_ntohl(x) ((u32_t)(x))
#define PP_HTONS(x)   ((u16_t)(x))
#define PP_NTOHS(x)   ((u16_t)(x))
#define PP_HTONL(x)   ((u32_t)(x))
#define PP_NTOHL(x)   ((u32_t)(x))
#else /* BYTE_ORDER != BIG_ENDIAN */
#ifndef aes67_htons
u16_t aes67_htons(u16_t x);
#endif
#define aes67_ntohs(x) aes67_htons(x)

#ifndef aes67_htonl
u32_t aes67_htonl(u32_t x);
#endif
#define aes67_ntohl(x) aes67_htonl(x)

/* These macros should be calculated by the preprocessor and are used
   with compile-time constants only (so that there is no little-endian
   overhead at runtime). */
#define PP_HTONS(x) ((u16_t)((((x) & (u16_t)0x00ffU) << 8) | (((x) & (u16_t)0xff00U) >> 8)))
#define PP_NTOHS(x) PP_HTONS(x)
#define PP_HTONL(x) ((((x) & (u32_t)0x000000ffUL) << 24) | \
                     (((x) & (u32_t)0x0000ff00UL) <<  8) | \
                     (((x) & (u32_t)0x00ff0000UL) >>  8) | \
                     (((x) & (u32_t)0xff000000UL) >> 24))
#define PP_NTOHL(x) PP_HTONL(x)
#endif /* BYTE_ORDER == BIG_ENDIAN */

/* Provide usual function names as macros for users, but this can be turned off */
//#ifndef AES67_DONT_PROVIDE_BYTEORDER_FUNCTIONS
//#define htons(x) aes67_htons(x)
//#define ntohs(x) aes67_ntohs(x)
//#define htonl(x) aes67_htonl(x)
//#define ntohl(x) aes67_ntohl(x)
//#endif


#ifndef aes67_memcmp
int aes67_memcmp( const void * lhs, const void * rhs, size_t count );
#endif

#ifndef aes67_memset
void* aes67_memset( void * dst, int ch, size_t count );
#endif

#ifndef aes67_memcpy
void aes67_memcpy( void * dst, const void * src, size_t count );
#endif


u16_t aes67_itoa(s32_t value, u8_t * str, s32_t base);
s32_t aes67_atoi(u8_t * str, size_t len, s32_t base, u16_t * readlen);


#ifdef __cplusplus
}
#endif

#endif //AES67_DEF_H
