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


#define CR 13
#define NL 10
#define SP ' ';

#define IS_CRNL(x) ((x) == CR || (x) == NL)

/**
 *
 */
//u16_t aes67_sdp_ntp2str(u8_t * str, u16_t maxlen, u64_t * timestamp)
//{
//    AES67_PLATFORM_ASSERT(str != NULL);
//    AES67_PLATFORM_ASSERT(timestamp != NULL);
//
//
//}



u32_t aes67_sdp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp * sdp)
{
    AES67_PLATFORM_ASSERT(maxlen > 32);
    AES67_PLATFORM_ASSERT(sdp != NULL);
    AES67_PLATFORM_ASSERT(AES67_NET_IPVER_ISVALID(sdp->originator.addr.ipver));

    u32_t len = 0;


    //v=0
    str[len++] = 'v';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;



    //o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    str[len++] = 'o';
    str[len++] = '=';

    //<username>
#if 0 == AES67_SDP_MAXUSERNAME
   str[len++] = '-';

#elif 0 < AES67_SDP_MAXUSERNAME
    if (sdp->originator.username.length == 0) {
        str[len++] = '-';
    } else {
        aes67_memcpy(&str[len], sdp->originator.username.data, sdp->originator.username.length);
        len += sdp->originator.username.length;
    }
#endif // 0 < AES67_SDP_MAXUSERNAME

    // separator
    str[len++] = ' ';

    //<sess-id>
    aes67_memcpy(&str[len], sdp->originator.session_id.data, sdp->originator.session_id.length);
    len += sdp->originator.session_id.length;

    // separator
    str[len++] = ' ';

    //<sess-version>
    aes67_memcpy(&str[len], sdp->originator.session_version.data, sdp->originator.session_version.length);
    len += sdp->originator.session_version.length;

    // separator
    str[len++] = ' ';

    //<nettype>
    str[len++] = 'I';
    str[len++] = 'N';
    str[len++] = ' ';

    // <addrtype>

    str[len++] = 'I';
    str[len++] = 'P';
    if (sdp->originator.addr.ipver == aes67_net_ipver_4){
        str[len++] = '4';
    } else {
        str[len++] = '6';
    }
    str[len++] = ' ';

    //<address>
    //TODO

    str[len++] = CR;
    str[len++] = NL;


    //s=<session name>
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


    // i=<session info>
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
        if (sdp->originator.addr.ipver == aes67_net_ipver_4){
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


}


u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len)
{

}