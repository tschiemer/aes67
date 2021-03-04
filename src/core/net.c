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

#include "aes67/net.h"

#include "aes67/debug.h"


s32_t aes67_net_str2ip(enum aes67_net_ipver * ipver, u8_t * ip, u16_t * port, u8_t * str, u16_t slen)
{
    AES67_ASSERT("ipver != NULL", ipver != NULL);
    AES67_ASSERT("ip != NULL", ip != NULL);
    AES67_ASSERT("port != NULL", port != NULL);
    AES67_ASSERT("str != NULL", str != NULL);

    u16_t ncolons = 0;
    s32_t last = -2;
    u32_t doublecolon = -1;
    for(s32_t i = 0; i < slen; i++){
        if (str[i] == ':'){
            if (last == i-1){
                // can not have more than one doublecolon
                if (doublecolon != -1){
                    return false;
                }
                doublecolon = ncolons;
            }
            ncolons++;
            last = i;
        }
    }

    // if more than one colon must be ipv6
    if (ncolons > 1){
#if AES67_USE_IPv6 == 1

        u16_t len = 0, end = slen, l;
        s32_t a;

        if (str[0] == '['){
            len++;

            if (str[end-1] != ']'){
                // assume port is given
                ncolons--;
            }
        }

        if (slen < len + 1) return false;
        a = aes67_atoi(&str[len], slen - len, 16, &l);
        if (l == 0 && str[len] == ':' && doublecolon == 1){
            ip[0] = 0;
            ip[1] = 0;
        }
        else if (l == 0 || l > 4 || (a & 0xffff0000)) return false;
        else {
            ip[0] = a >> 8;
            ip[1] = a & 0xff;
            len += l;
        }

        for (int i = 1; i < 8; i++){

            if (slen < len + 1 || str[len++] != ':') return false;

            if (i == doublecolon) {
                for (int j = 0; j < 8 - ncolons && i < 8; j++, i++){
                    ip[2*i] = 0;
                    ip[2*i+1] = 0;
                }
                if (slen <= len + 1 || str[len+1] == ']') {
                    ip[14] = 0;
                    ip[15] = 0;
//                    if (slen >= len + 2){

                        len++;
//                    }
                } else {
                    i--;
                }
                continue;
            }

            a = aes67_atoi(&str[len], slen - len, 16, &l);
            if (l == 0 || l > 4 || (a & 0xffff0000)) return false;
            ip[2*i] = a >> 8;
            ip[2*i+1] = a & 0xff;
            len += l;
        }

        if (len == slen || (slen == len + 1 && str[0] == '[' && str[len] == ']')) {
            *port = 0;
        } else {
            if (slen < len + 3 || str[len] != ']' || str[len+1] != ':'){
                return false;
            }
            a = aes67_atoi(&str[len+2], slen - len - 1, 10, &l);
            if (l == 0 || slen != len + 2 + l || (a & 0xffff0000)){
                return false;
            }
            *port = a;
            if (slen != len + 2 + l){
                return false;
            }
        }

        *ipver = aes67_net_ipver_6;

#else // AES67_USE_IPv6 != 1

        return false;

#endif
    } else {
        u16_t len = 0, l;
        s32_t a;

        a = aes67_atoi(&str[0], slen, 10, &l);
        if (l == 0 || l > 3 || (a & 0xffffff00)) return false;
        ip[0] = a;
        len = l;

        for (int i = 1; i < 4; i++) {
            if (slen < len + 1 || str[len++] != '.') return false;
            a = aes67_atoi(&str[len], slen - len, 10, &l);
            if (l == 0 || l > 3 || (a & 0xffffff00)) return false;
            ip[i] = a;
            len += l;
        }

        if (len == slen){
            *port = 0;
        } else if (slen < len + 2 || str[len] != ':') {
            return false;
        } else {
            a = aes67_atoi(&str[len+1], slen - len - 1, 10, &l);
            if (l == 0 || slen != len + 1 + l || (a & 0xffff0000)){
                return false;
            }
            *port = a;
        }

        *ipver = aes67_net_ipver_4;
    }

    return true;
}

u16_t aes67_net_ip2str(u8_t * str, enum aes67_net_ipver ipver, u8_t * addr, u16_t port)
{
    AES67_ASSERT("str != NULL", str != NULL);
//    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("addr != NULL", addr != NULL);

    if (ipver == aes67_net_ipver_undefined){
        return 0;
    }

#if AES67_USE_IPv6 == 1
    AES67_ASSERT("ipver == aes67_net_ipver_4 || ipver == aes67_net_ipver_6", ipver == aes67_net_ipver_4 || ipver == aes67_net_ipver_6);
#else
    AES67_ASSERT("ipver == aes67_net_ipver_4", ipver == aes67_net_ipver_4);
#endif

    u16_t len = 0;


#if AES67_USE_IPv6 == 1
    if (ipver == aes67_net_ipver_6){

        if (port > 0){
            str[len++] = '[';
        }

        u16_t val = (addr[0] << 8) | (addr[1]);
        len += aes67_itoa(val, &str[len], 16);

        for(int i = 1; i < 8; i++){
            str[len++] = ':';
            u16_t val = (addr[2*i] << 8) | (addr[2*i+1]);
            len += aes67_itoa(val, &str[len], 16);
        }

        if (port > 0){
            str[len++] = ']';
            str[len++] = ':';
            len += aes67_itoa(port, &str[len], 10);
        }

    } else {
#endif

    len += aes67_itoa(addr[0], str, 10);
    str[len++] = '.';
    len += aes67_itoa(addr[1], &str[len], 10);
    str[len++] = '.';
    len += aes67_itoa(addr[2], &str[len], 10);
    str[len++] = '.';
    len += aes67_itoa(addr[3], &str[len], 10);

    if (port > 0) {
        str[len++] = ':';
        len += aes67_itoa(port, &str[len], 10);
    }

#if AES67_USE_IPv6 == 1
    }
#endif

    return len;
}

u8_t aes67_net_ipeq(const struct aes67_net_addr * lhs, const struct aes67_net_addr * rhs)
{
    AES67_ASSERT("lhs != NULL", lhs != NULL);
    AES67_ASSERT("rhs != NULL", rhs != NULL);

    // valid ip version?
    if (lhs->ipver != aes67_net_ipver_4 && lhs->ipver != aes67_net_ipver_6) return false;

    if (lhs->ipver != rhs->ipver) return false;

    u16_t l = lhs->ipver == aes67_net_ipver_4 ? 4 : 16;

    return aes67_memcmp(lhs->addr, rhs->addr, l) == 0;
}

