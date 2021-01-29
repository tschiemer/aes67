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

#include <aes67/arch.h>
#include "aes67/def.h"


#if BYTE_ORDER == LITTLE_ENDIAN

#if !defined(aes67_htons)
/**
 * Convert an u16_t from host- to network byte order.
 *
 * @param n u16_t in host byte order
 * @return n in network byte order
 */
u16_t aes67_htons(u16_t n)
{
    return PP_HTONS(n);
}
#endif /* aes67_htons */

#if !defined(aes67_htonl)
/**
 * Convert an u32_t from host- to network byte order.
 *
 * @param n u32_t in host byte order
 * @return n in network byte order
 */
u32_t aes67_htonl(u32_t n)
{
    return PP_HTONL(n);
}
#endif /* aes67_htonl */



#ifndef aes67_memcpy
void aes67_memcpy( void * dst, const void * src, size_t count )
{
    for(size_t i = 0; i < count; i++){
        ((u8_t*)dst)[i] = ((u8_t*)src)[i];
    }
}
#endif //aes67_memcpy

#ifndef aes67_memset
void* aes67_memset( void * dst, int ch, size_t count )
{
    for(size_t i = 0; i < count; i++){
        *(u8_t*)&dst[i] = (u8_t)ch;
    }
    return dst;
}
#endif //aes67_memset

#ifndef aes67_memcmp
int aes67_memcmp( const void * lhs, const void * rhs, size_t count )
{
    for(size_t i = 0; i < count; i++){
        if (((u8_t*)lhs)[i] < ((u8_t*)rhs)[i]) return -1;
        if (((u8_t*)lhs)[i] > ((u8_t*)rhs)[i]) return 1;
    }
    return 0;
}
#endif //aes67_memcmp

#ifndef aes67_memmove
void * aes67_memmove(void* dest, const void* src, size_t count)
{
    if (dest == src){
        return dest;
    }
    // either start copying from start or from end depending on relative position in memory
    // (to allow for safe overlapping of memory regions)
    if (dest < src) {
        for (size_t i = 0; i < count; i++) {
            ((u8_t *) dest)[i] = ((u8_t *) src)[i];
        }
    } else {
        for (size_t i = count; 0 < i;) {
            i--;
            ((u8_t *) dest)[i] = ((u8_t *) src)[i];
        }
    }
    return dest;
}
#endif

#ifndef aes67_memchr
void * aes67_memchr( const void * ptr, int ch, size_t count )
{
    for(size_t i = 0; i < count; i++){
        if ( ((u8_t*)ptr)[i] == (u8_t)ch ){
            return (void*)&(((u8_t*)ptr)[i]);
        }
    }
    return NULL;
}
#endif //aes67_memchr


/**
 * Inspired by v0.3 from http://www.strudel.org.uk/itoa/
 * Returns length and does not null-terminate
 */
u16_t aes67_itoa(s32_t value, u8_t * str, s32_t base)
{
    u8_t *front = str;
    u8_t * back = str;
    s32_t sign, len;

    // Validate base
    if (base < 2 || base > 35){
//        *back = '\0';
        return 0;
    }

    // Take care of sign
    if ((sign=value) < 0) {
        value = -value;
    }

    // Conversion. Number is reversed.
    do {
        *back++ = "0123456789abcdefghijklmnopqrstuvwxyz"[value % base];
    } while(value /= base);

    if(sign < 0) {
        *back ++= '-';
    }
    len = back - front;
//    *back-- = '\0';
    back--;

    // reverse
    u8_t swap;
    while( back > front) {
        swap = *back;
        *back --= *front;
        *front++ = swap;
    }

    return len;
}

s32_t aes67_atoi(u8_t * str, size_t len, s32_t base, u16_t * readlen)
{
    if (base < 2 || 35 < base){
        if (readlen != NULL){
            *readlen = 0;
        }
        return 0;
    }

    s32_t result = 0;
    s32_t sign = str[0] == '-' ? -1 : 1;
    u16_t i;

    for(i = sign == -1 ? 1 : 0; i < len; i++){
        s32_t m;
        if ('0' <= str[i] && str[i] <= '9') m = str[i] - '0';
        else if ('a' <= str[i] && str[i] <= 'z') m = str[i] - 'a' + 10;
        else if ('A' <= str[i] && str[i] <= 'Z') m = str[i] - 'A' + 10;
        else break;

        // validate
        if (m >= base){
//            *readlen = 100;
//            exit(m);
            break;
        }

        result = result * base + m;
    }

    if (readlen != NULL){
        *readlen = i;
    }

    return  sign * result;
}


//#ifndef aes67_strcpy
//u16_t aes67_strcpy( u8_t * dst, const u8_t * src, u8_t bterminate  )
//{
//  u16_t i;
//  for(i = 0; src[i] != '\0'; i++){
//    dst[i] = src[i];
//  }
//  if (bterminate){
//    dst[i++] = '\0';
//  }
//  return i;
//}
//#endif

#endif /* BYTE_ORDER == LITTLE_ENDIAN */