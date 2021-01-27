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
#else
#define AES67_NET_ADDR_SIZE 4
#endif

enum aes67_net_ipver {
    aes67_net_ipver_4    = 4,
    aes67_net_ipver_6    = 6
} PACK_STRUCT;

#define AES67_NET_IPVER_ISVALID( __ip__ ) ( \
    (__ip__) == aes67_net_ipver_4 ||\
    (__ip__) == aes67_net_ipver_6 \
    )

struct aes67_net_addr {
    enum aes67_net_ipver ipver;
    u16_t port;
    u8_t addr[AES67_NET_ADDR_SIZE];
} PACK_STRUCT;




s32_t aes67_net_str2addr(struct aes67_net_addr * addr, u8_t * str, u16_t slen);
u16_t aes67_net_addr2str(u8_t * str, struct aes67_net_addr * addr);

u8_t aes67_net_ipeq(const struct aes67_net_addr * lhs, const struct aes67_net_addr * rhs);

u8_t aes67_net_ismcastip(const struct aes67_net_addr * addr);

inline u8_t aes67_net_addreq(const struct aes67_net_addr * lhs, const struct aes67_net_addr * rhs)
{
    if (aes67_net_ipeq(lhs, rhs) == false) return false;
    if (lhs->port != rhs->port) return false;

    return true;
}

inline void aes67_net_addrcp(struct aes67_net_addr * to, const struct aes67_net_addr * from)
{
    aes67_memcmp(to, from, sizeof(struct aes67_net_addr));
}

inline u8_t aes67_net_addr2mem(u8_t * to, const struct aes67_net_addr * from)
{
    aes67_memcpy(to, from->addr, (from->ipver == aes67_net_ipver_4) ? 4 : 16);
    return (from->ipver == aes67_net_ipver_4) ? 4 : 16;
}

#ifdef DEBUG
void aes67_dump_net_addr(struct aes67_net_addr * addr);
#endif


#ifdef __cplusplus
}
#endif

#endif //AES67_NET_H
