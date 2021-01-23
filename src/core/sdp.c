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

#include "aes67/sdp.h"

#include "aes67/def.h"
#include "aes67/debug.h"


#define CR 13
#define NL 10
#define SP ' ';

#define IS_CRNL(x) ((x) == CR || (x) == NL)


u32_t aes67_sdp_origin_tostr( u8_t * str, u32_t maxlen, struct aes67_sdp_originator * origin)
{
    AES67_ASSERT("str != NULL", str != NULL);
    AES67_ASSERT("maxlen > 32", maxlen > 32);
    AES67_ASSERT("origin != NULL", origin != NULL);

    u32_t len = 0;

    //o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    str[len++] = 'o';
    str[len++] = '=';

    //<username>
#if 0 == AES67_SDP_MAXUSERNAME
    str[len++] = '-';

#elif 0 < AES67_SDP_MAXUSERNAME
    if (origin->username.length == 0) {
        str[len++] = '-';
    } else {
        aes67_memcpy(&str[len], origin->username.data, origin->username.length);
        len += origin->username.length;
    }
#endif // 0 < AES67_SDP_MAXUSERNAME

    // separator
    str[len++] = ' ';

    //<sess-id>
    aes67_memcpy(&str[len], origin->session_id.data, origin->session_id.length);
    len += origin->session_id.length;

    // separator
    str[len++] = ' ';

    //<sess-version>
    aes67_memcpy(&str[len], origin->session_version.data, origin->session_version.length);
    len += origin->session_version.length;

    // separator
    str[len++] = ' ';

    //<nettype>
    str[len++] = 'I';
    str[len++] = 'N';
    str[len++] = ' ';

    // <addrtype>

    str[len++] = 'I';
    str[len++] = 'P';
    if (origin->address_type == aes67_net_ipver_4){
        str[len++] = '4';
    } else {
        str[len++] = '6';
    }
    str[len++] = ' ';

    //<address>
    //TODO

    str[len++] = CR;
    str[len++] = NL;

    return len;
}

u32_t aes67_sdp_origin_fromstr(struct aes67_sdp_originator * origin, u8_t * str, u32_t len)
{
    return 0;
}


u8_t aes67_sdp_origin_cmp(struct aes67_sdp_originator * lhs, struct aes67_sdp_originator * rhs)
{
    AES67_ASSERT("lhs != NULL", lhs != NULL);
    AES67_ASSERT("rhs != NULL", rhs != NULL);

    // compare usename
    if (lhs->username.length < rhs->username.length) return 1;
    if (lhs->username.length > rhs->username.length) return 1;
    if (aes67_memcmp(lhs->username.data, rhs->username.data, lhs->username.length) != 0) return 1;

    // compare session_data id
    if (lhs->session_id.length < rhs->session_id.length) return 1;
    if (lhs->session_id.length > rhs->session_id.length) return 1;
    if (aes67_memcmp(lhs->session_id.data, rhs->session_id.data, lhs->session_id.length) != 0) return 1;

    // do NOT compare session_data version

    // do NOT compare nettype + addrtype (do implicitly through unicast address)

    // compare unicast address
    if (lhs->session_id.length < rhs->session_id.length) return 1;
    if (lhs->session_id.length > rhs->session_id.length) return 1;
    if (aes67_memcmp(lhs->session_id.data, rhs->session_id.data, lhs->session_id.length) != 0) return 1;

    // now we can assume it's the same stream

    return 0;
}

s32_t aes67_sdp_origin_cmpversion(struct aes67_sdp_originator * lhs, struct aes67_sdp_originator * rhs)
{
    AES67_ASSERT("lhs != NULL", lhs != NULL);
    AES67_ASSERT("rhs != NULL", rhs != NULL);

    // assuming the session_data version is given as integer, if the version differs in number of digits, the case is clear
    if (lhs->session_version.length < rhs->session_version.length) return -1;
    if (lhs->session_version.length > rhs->session_version.length) return 1;

    // otherwise do a bytewise comparison (which works because character representations of integers are in the right order)
    return aes67_memcmp(lhs->session_version.data, rhs->session_version.data, lhs->session_version.length);
}


u32_t aes67_sdp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp * sdp)
{
    AES67_ASSERT("str != NULL", str != NULL);
    AES67_ASSERT("maxlen > 32", maxlen > 32);
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    // length of sdp packet
    u32_t len = 0;


    //v=0
    str[len++] = 'v';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;

    // originator (o=..)
    len += aes67_sdp_origin_tostr(&str[len], maxlen - 5, &sdp->originator);

//    str[len++] = CR;
//    str[len++] = NL;


    //s=<session_data name>
    str[len++] = 's';
    str[len++] = '=';
    if (sdp->session_name.length == 0){
        str[len++] = ' '; // use single space if no meaningful name
    } else {
        aes67_memcpy(&str[len], sdp->session_name.data, sdp->session_name.length);
        len += sdp->session_name.length;
    }
    str[len++] = CR;
    str[len++] = NL;


    // i=<session_data info>
#if 0 < AES67_SDP_MASSESSIONINFO
    if (0 < sdp->session_info.length){
        aes67_memcpy(&str[len], sdp->session_info.data, sdp->session_info.length);
        len += sdp->session_info.length;

        str[len++] = CR;
        str[len++] = NL;
    }
#endif

    // c=<connection data> (0-N)
    for(int i = 0; i < sdp->connections.count; i++){
        str[len++] = 'c';
        str[len++] = '=';
        str[len++] = 'I';
        str[len++] = 'N';
        str[len++] = ' ';
        str[len++] = 'I';
        str[len++] = 'P';
        if (sdp->originator.address_type == aes67_net_ipver_4){
            str[len++] = '4';
        } else {
            str[len++] = '6';
        }
        str[len++] = ' ';

        //TODO write address

        //TODO TTL?

        //TODO layers?

        str[len++] = CR;
        str[len++] = NL;
    }

    // b=<bwtype>:<bandwidth>

    // t=<start-time> <stop-time>
    str[len++] = 't';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = ' ';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;

    return len;
}


u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len)
{
    return 0;
}

