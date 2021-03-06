/**
 * @file net.h
 * Networking utilities
 */

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

#ifndef AES67_NET_H
#define AES67_NET_H
#include "aes67/arch.h"
#include "aes67/def.h"

#ifdef __cplusplus
extern "C" {
#endif

#if AES67_USE_IPv6
#define AES67_NET_ADDR_SIZE 16
#define AES67_NET_ADDR_STR_MAX sizeof("[0102:0304:0506:0708:090a:0b0c:0d0e:0f10]:65535")
#else
#define AES67_NET_ADDR_SIZE 4
#define AES67_NET_ADDR_STR_MAX sizeof("123.123.123.123:65535")
#endif

// the value equals the size in bytes
enum aes67_net_ipver {
    aes67_net_ipver_undefined = 0,
    aes67_net_ipver_4    = 4,
    aes67_net_ipver_6    = 16
} PACK_STRUCT;

#define AES67_NET_IPVER_ISVALID( __ip__ ) ( \
    (__ip__) == aes67_net_ipver_4 ||\
    (__ip__) == aes67_net_ipver_6 \
    )

#define AES67_NET_IPVER_SIZE( __ipver__) ((u8_t)(__ipver__))

struct aes67_net_addr {
    enum aes67_net_ipver ipver;
    u16_t port;
    u8_t ip[AES67_NET_ADDR_SIZE];
};



s32_t aes67_net_str2ip(enum aes67_net_ipver * ipver, u8_t * addr, u16_t * port, u8_t * str, u16_t slen);
u16_t aes67_net_ip2str(u8_t * str, enum aes67_net_ipver ipver, u8_t * addr, u16_t port);

INLINE_FUN s32_t aes67_net_str2addr(struct aes67_net_addr * addr, u8_t * str, u16_t slen)
{
    return aes67_net_str2ip(&addr->ipver, addr->ip, &addr->port, str, slen);
}

INLINE_FUN u16_t aes67_net_addr2str(u8_t * str, struct aes67_net_addr * addr)
{
    return aes67_net_ip2str(str, addr->ipver, addr->ip, addr->port);
}

INLINE_FUN u8_t aes67_net_addr2mem(u8_t * to, const struct aes67_net_addr * from)
{
    if (from->ipver == aes67_net_ipver_4){
        ((u32_t*)to)[0] = ((u32_t*)from->ip)[0];
        return 4;
    } else if (from->ipver == aes67_net_ipver_6){
        ((u32_t*)to)[0] = ((u32_t*)from->ip)[0];
        ((u32_t*)to)[1] = ((u32_t*)from->ip)[1];
        ((u32_t*)to)[2] = ((u32_t*)from->ip)[2];
        ((u32_t*)to)[3] = ((u32_t*)from->ip)[3];
        return 16;
    }
    return 0;
}

INLINE_FUN void aes67_net_addrcp(struct aes67_net_addr * to, const struct aes67_net_addr * from)
{
    aes67_memcmp(to, from, sizeof(struct aes67_net_addr));
}


u8_t aes67_net_ipeq(const struct aes67_net_addr * lhs, const struct aes67_net_addr * rhs);

INLINE_FUN u8_t aes67_net_ismcastip(const enum aes67_net_ipver ipver, const u8_t * ip)
{
    if (ipver == aes67_net_ipver_4){
        // 224.0.0.0 - 239.255.255.255
        return (224 <= ip[0] && ip[0] < 240);
    } else if (ipver == aes67_net_ipver_6){
        // ff00::/8 prefix
        return (0xff == ip[0]);
    }
    return 0;
}

INLINE_FUN u8_t aes67_net_ismcastip_addr(const struct aes67_net_addr * addr)
{
    return aes67_net_ismcastip(addr->ipver, (u8_t *)addr->ip);
}

INLINE_FUN u8_t aes67_net_isallip(const enum aes67_net_ipver ipver, const u8_t * ip)
{
    if (ipver == aes67_net_ipver_4){
        return ((u32_t*)ip)[0] == 0;
    } else if (ipver == aes67_net_ipver_6){
        return ((u32_t*)ip)[0] == 0 && ((u32_t*)ip)[1] == 0 && ((u32_t*)ip)[2] == 0 && ((u32_t*)ip)[3] == 0;
    }
    return 0;
}
INLINE_FUN u8_t aes67_net_isallip_addr(const struct aes67_net_addr * addr)
{
    return aes67_net_isallip(addr->ipver, addr->ip);
}

INLINE_FUN u8_t aes67_net_addreq(const struct aes67_net_addr * lhs, const struct aes67_net_addr * rhs)
{
    if (aes67_net_ipeq(lhs, rhs) == false) return false;
    if (lhs->port != rhs->port) return false;

    return true;
}





#ifdef __cplusplus
}
#endif

#endif //AES67_NET_H
