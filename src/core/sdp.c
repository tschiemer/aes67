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

static u16_t sdp_connections_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_connection_list * cons, aes67_sdp_flags flags){
    uint16_t len = 0;

    flags = (flags & ~AES67_SDP_FLAG_SET_MASK) | AES67_SDP_FLAG_SET_YES;

    for(int i = 0; i < cons->count; i++){
        // skip all unwanted context
        if ( cons->data[i].flags != flags ){
            continue;
        }

        str[len++] = 'c';
        str[len++] = '=';
        str[len++] = 'I';
        str[len++] = 'N';
        str[len++] = ' ';
        str[len++] = 'I';
        str[len++] = 'P';
        if (cons->data[i].address_type == aes67_net_ipver_4){
            str[len++] = '4';
        } else {
            str[len++] = '6';
        }
        str[len++] = ' ';

        // host
        aes67_memcpy(&str[len], &cons->data[i].address.data, cons->data[i].address.length);
        len += cons->data[i].address.length;

        // optional ttl for ipv4 multicast
        if (cons->data[i].address_type == aes67_net_ipver_4 && (cons->data[i].flags & AES67_SDP_FLAG_MCAST_MASK) == AES67_SDP_FLAG_MCAST_YES){
            str[len++] = '/';
            len += aes67_itoa(cons->data[i].ttl, &str[len], 10);
        }

        if (cons->data[i].naddr > 0){
            str[len++] = '/';
            len += aes67_itoa(cons->data[i].naddr, &str[len], 10);
        }


        str[len++] = CR;
        str[len++] = NL;
    }

    return len;
}

void aes67_sdp_origin_init(struct aes67_sdp_originator * origin)
{
    AES67_ASSERT("origin != NULL", origin != NULL);

    origin->username.length = 0;
    origin->session_id.length = 0;
    origin->session_version.length = 0;
    origin->address.length = 0;
}

void aes67_sdp_init(struct aes67_sdp * sdp)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    aes67_sdp_origin_init(&sdp->originator);

    sdp->ptp_domain = AES67_SDP_PTP_DOMAIN_UNDEF;
}

struct aes67_sdp_connection * aes67_sdp_get_connection(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    struct aes67_sdp_connection * session_level = NULL;

    for (int i = 0; i < AES67_SDP_MAXCONNECTIONS; i++){

        // if explicitly session level requested
        if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) == AES67_SDP_FLAG_DEFLVL_SESSION && (sdp->connections.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION) ) {
            return &sdp->connections.data[i];
        }
        // or if level unspecified (remember value)
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_STREAM && (sdp->connections.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION) ){
            session_level = &sdp->connections.data[i];
        }
        // but unless session level explicitly requested, always prioritize stream level
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_SESSION && (sdp->connections.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION | flags)){
            return &sdp->connections.data[i];
        }
    }

    return session_level;
}

struct aes67_sdp_attr_encoding * aes67_sdp_get_stream_encoding(struct aes67_sdp * sdp, u8_t si, u8_t ei)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("si < sdp->streams.count", si < sdp->streams.count);
    AES67_ASSERT("ei < sdp->encodings.count", ei < sdp->encodings.count);

    for(int i = 0, ec = 0; i < AES67_SDP_MAXENCODINGS; i++){
        // stream level attribute only
        if ((sdp->encodings.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION | si) ){
            if (ec == ei){
                return &sdp->encodings.data[i];
            }
            ec++;
        }
    }

    return NULL;
}

struct aes67_sdp_ptp * aes67_sdp_get_ptp(struct aes67_sdp * sdp, aes67_sdp_flags flags, u8_t pi)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("(flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count", (flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count);
    AES67_ASSERT("pi < sdp->ptps.count", pi < sdp->ptps.count);

//    struct aes67_sdp_ptp * session_level = NULL;

    for(int i = 0, pc = 0, found = 0; i < AES67_SDP_MAXPTPS; i++, found = 0){
        // if session level explicitly requested and found there
        if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) == AES67_SDP_FLAG_DEFLVL_SESSION &&  (sdp->ptps.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION)){
            found = 1;
        }
        // if stream level not explicitly requested and found on session level
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_STREAM && (sdp->ptps.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION) ){
            found = 1;
        }
        // if not session level explicitly requested and found on stream level
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_SESSION && (sdp->ptps.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION | flags)){
            found = 1;
        }
        if (found == 1){

            if (pc == pi){
                return &sdp->ptps.data[i];
            }

            pc++;
        }
    }

    return NULL;
}

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
    aes67_memcpy(&str[len], origin->address.data, origin->address.length);
    len += origin->address.length;

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
    u32_t len = 0, l;


    //v=0
    str[len++] = 'v';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;

    // originator (o=..)
    len += aes67_sdp_origin_tostr(&str[len], maxlen - 5, &sdp->originator);

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
#if 0 < AES67_SDP_MAXSESSIONINFO
    if (0 < sdp->session_info.length){
        aes67_memcpy(&str[len], sdp->session_info.data, sdp->session_info.length);
        len += sdp->session_info.length;

        str[len++] = CR;
        str[len++] = NL;
    }
#endif

    // c=<connection data> (0-N)
    len += sdp_connections_tostr(&str[len], maxlen - len, &sdp->connections, AES67_SDP_FLAG_DEFLVL_SESSION);

    // b=<bwtype>:<bandwidth>

    // t=<start-time> <stop-time>
    str[len++] = 't';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = ' ';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;

    // a=clock-domain:PTPv2 <domainNumber>
    // RAVENNA SHALL session level attribute
    if (sdp->ptp_domain != AES67_SDP_PTP_DOMAIN_UNDEF){
        str[len++] = 'a';
        str[len++] = '=';
        str[len++] = 'c';
        str[len++] = 'l';
        str[len++] = 'o';
        str[len++] = 'c';
        str[len++] = 'k';
        str[len++] = '-';
        str[len++] = 'd';
        str[len++] = 'o';
        str[len++] = 'm';
        str[len++] = 'a';
        str[len++] = 'i';
        str[len++] = 'n';
        str[len++] = ':';
        str[len++] = 'P';
        str[len++] = 'T';
        str[len++] = 'P';
        str[len++] = 'v';
        str[len++] = '2';
        str[len++] = ' ';
        str[len++] = '0' + sdp->ptp_domain;
        str[len++] = CR;
        str[len++] = NL;
    }

#if AES67_SDP_TOOL_ENABLED == 1
    // a=tool:
    str[len++] = 'a';
    str[len++] = '=';
    str[len++] = 't';
    str[len++] = 'o';
    str[len++] = 'o';
    str[len++] = 'l';
    aes67_memcpy(&str[len], AES67_SDP_TOOL, sizeof(AES67_SDP_TOOL)-1);
    len += sizeof(AES67_SDP_TOOL)-1;
    str[len++] = CR;
    str[len++] = NL;
#endif



    return len;
}


u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len)
{
    return 0;
}

