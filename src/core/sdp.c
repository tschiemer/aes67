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

#define IS_NL(x) ((x) == NL)
#define IS_CRNL(x) ((x) == CR || (x) == NL)


#define U8TOSTR(u8, str, len) \
    if (u8 >= 100){ str[len++] = '0' + (u8 / 100); } \
    if (u8 >= 10){ str[len++] = '0' + ((u8 % 100) / 10); } \
    str[len++] = '0' + (u8 % 10);

// ptp domain 0 - 127


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

//    aes67_memset()
}

struct aes67_sdp_connection * aes67_sdp_get_connection(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("not both session and stream req", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_MASK);
    AES67_ASSERT("stream level requested -> valid stream index", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_STREAM || ((flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count) );

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
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_SESSION && (sdp->connections.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | flags)){
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
        if ((sdp->encodings.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | si) ){
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
    AES67_ASSERT("pi < sdp->ptps.count", pi < sdp->ptps.count);
    AES67_ASSERT("valid session level index", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_SESSION || pi < sdp->nptp);
    AES67_ASSERT("valid stream level index", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_STREAM || (flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count);
    AES67_ASSERT("valid stream level index", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != 0 || (flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count + sdp->nptp);

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
        else if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) != AES67_SDP_FLAG_DEFLVL_SESSION && (sdp->ptps.data[i].flags & (AES67_SDP_FLAG_SET_MASK | AES67_SDP_FLAG_DEFLVL_MASK | AES67_SDP_FLAG_STREAM_INDEX_MASK)) == (AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | flags)){
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

u8_t aes67_sdp_origin_eq(struct aes67_sdp_originator * lhs, struct aes67_sdp_originator * rhs)
{
    AES67_ASSERT("lhs != NULL", lhs != NULL);
    AES67_ASSERT("rhs != NULL", rhs != NULL);

    // compare usename
    if (lhs->username.length != rhs->username.length) return 0;
    if (aes67_memcmp(lhs->username.data, rhs->username.data, lhs->username.length) != 0) return 0;

    // compare session_data id
    if (lhs->session_id.length != rhs->session_id.length) return 0;
    if (aes67_memcmp(lhs->session_id.data, rhs->session_id.data, lhs->session_id.length) != 0) return 0;

    // do NOT compare session_data version

    // do NOT compare nettype + addrtype (do implicitly through unicast address)

    // compare unicast address
    // TODO as hostnames are allowed, in principle we should resolve the name and compare but the ips
    if (lhs->address.length != rhs->address.length) return 0;
    if (aes67_memcmp(lhs->address.data, rhs->address.data, lhs->address.length) != 0) return 0;

    // now we can assume it's the same stream

    return 1;
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

u32_t aes67_sdp_connections_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_connection_list * cons, aes67_sdp_flags flags)
{
    AES67_ASSERT( "str != NULL", str != NULL );
    AES67_ASSERT("cons != NULL", cons != NULL );

    u32_t len = 0;

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
        if (cons->data[i].ipver == aes67_net_ipver_4){
            str[len++] = '4';
        } else {
            str[len++] = '6';
        }
        str[len++] = ' ';

        // host
        aes67_memcpy(&str[len], &cons->data[i].address.data, cons->data[i].address.length);
        len += cons->data[i].address.length;

        // optional ttl for ipv4 multicast (we assume ttl > 0 iff is multicast)
        if (cons->data[i].ipver == aes67_net_ipver_4 && 0 < cons->data[i].ttl){
            str[len++] = '/';
            len += aes67_itoa(cons->data[i].ttl, &str[len], 10);
        }

        if (cons->data[i].naddr > 1){
            str[len++] = '/';
            len += aes67_itoa(cons->data[i].naddr, &str[len], 10);
        }


        str[len++] = CR;
        str[len++] = NL;
    }

    return len;
}


u32_t aes67_sdp_ptp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_ptp_list * ptps, aes67_sdp_flags flags)
{
    AES67_ASSERT( "str != NULL", str != NULL );
    AES67_ASSERT("ptps != NULL", ptps != NULL );

    u32_t len = 0;

    flags = (flags & ~AES67_SDP_FLAG_SET_MASK) | AES67_SDP_FLAG_SET_YES;

    for(int i = 0; i < ptps->count; i++){
        // skip all unwanted context
        if ( ptps->data[i].flags != flags ){
            continue;
        }

        AES67_ASSERT("AES67_PTP_TYPE_ISVALID(ptps->data[i].ptp.type)", AES67_PTP_TYPE_ISVALID(ptps->data[i].ptp.type));

        str[len++] = 'a';
        str[len++] = '=';
        str[len++] = 't';
        str[len++] = 's';
        str[len++] = '-';
        str[len++] = 'r';
        str[len++] = 'e';
        str[len++] = 'f';
        str[len++] = 'c';
        str[len++] = 'l';
        str[len++] = 'k';
        str[len++] = ':';
        str[len++] = 'p';
        str[len++] = 't';
        str[len++] = 'p';
        str[len++] = '=';

        // add ptp variant
        if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2002){
            aes67_memcpy(&str[len], AES67_PTP_TYPE_STR_IEEE1588_2002, sizeof(AES67_PTP_TYPE_STR_IEEE1588_2002) - 1);
            len += sizeof(AES67_PTP_TYPE_STR_IEEE1588_2002) - 1;
        }
        else if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2008){
            aes67_memcpy(&str[len], AES67_PTP_TYPE_STR_IEEE1588_2008, sizeof(AES67_PTP_TYPE_STR_IEEE1588_2008) - 1);
            len += sizeof(AES67_PTP_TYPE_STR_IEEE1588_2008) - 1;
        }
        else if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2019){
            aes67_memcpy(&str[len], AES67_PTP_TYPE_STR_IEEE1588_2019, sizeof(AES67_PTP_TYPE_STR_IEEE1588_2019) - 1);
            len += sizeof(AES67_PTP_TYPE_STR_IEEE1588_2019) - 1;
        }
        else if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE802AS_2011){
            aes67_memcpy(&str[len], AES67_PTP_TYPE_STR_IEEE802AS_2011, sizeof(AES67_PTP_TYPE_STR_IEEE802AS_2011) - 1);
            len += sizeof(AES67_PTP_TYPE_STR_IEEE802AS_2011) - 1;
        }

        str[len++] = ':';

        //
        aes67_atohex(&ptps->data[i].ptp.gmid.u8[0], 1, &str[len]);
        len += 2;
        for(int j = 1; j < sizeof(union aes67_ptp_eui64); j++){
            str[len++] = '-';
            aes67_atohex(&ptps->data[i].ptp.gmid.u8[j], 1, &str[len]);
            len += 2;
        }

        // add PTP domain only if 2008 or 2019 version
        if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2008 || ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2019){
            // domain values 0 - 127
            str[len++] = ':';
            U8TOSTR(ptps->data[i].ptp.domain, str, len);
        }

        str[len++] = CR;
        str[len++] = NL;
    }

    return len;
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
    if (sdp->name.length == 0){
        str[len++] = ' '; // use single space if no meaningful name
    } else {
        aes67_memcpy(&str[len], sdp->name.data, sdp->name.length);
        len += sdp->name.length;
    }
    str[len++] = CR;
    str[len++] = NL;


    // i=<session_data info>
#if 0 < AES67_SDP_MAXSESSIONINFO
    if (0 < sdp->info.length){
        str[len++] = 'i';
        str[len++] = '=';

        aes67_memcpy(&str[len], sdp->info.data, sdp->info.length);
        len += sdp->info.length;

        str[len++] = CR;
        str[len++] = NL;
    }
#endif

    // c=<connection data> (0-N)
    len += aes67_sdp_connections_tostr(&str[len], maxlen - len, &sdp->connections, AES67_SDP_FLAG_DEFLVL_SESSION);

    // b=<bwtype>:<bandwidth>

    // t=<start-time> <stop-time>
    // ALWAYS t=0 0
    str[len++] = 't';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = ' ';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;


    //// session level-attributes

#if AES67_SDP_TOOL_ENABLED == 1
    // a=tool:
    str[len++] = 'a';
    str[len++] = '=';
    str[len++] = 't';
    str[len++] = 'o';
    str[len++] = 'o';
    str[len++] = 'l';
    str[len++] = ':';
    aes67_memcpy(&str[len], AES67_SDP_TOOL, sizeof(AES67_SDP_TOOL)-1);
    len += sizeof(AES67_SDP_TOOL)-1;
    str[len++] = CR;
    str[len++] = NL;
#endif

    // a=clock-domain:PTPv2 <domainNumber>
    // RAVENNA SHALL session level attribute
    if ((sdp->ptp_domain & AES67_SDP_PTP_DOMAIN_SET) == AES67_SDP_PTP_DOMAIN_SET){
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
        u8_t d = (AES67_SDP_PTP_DOMAIN_VALUE & sdp->ptp_domain);
        U8TOSTR(d, str, len);
        str[len++] = CR;
        str[len++] = NL;
    }

    len += aes67_sdp_ptp_tostr(&str[len], maxlen - len, &sdp->ptps, AES67_SDP_FLAG_DEFLVL_SESSION);

    for(u8_t s = 0; s < sdp->streams.count; s++){

        // m=audio port[/<no-of-ports>] RTP/AVP <fmt1> ..
        str[len++] = 'm';
        str[len++] = '=';
        str[len++] = 'a';
        str[len++] = 'u';
        str[len++] = 'd';
        str[len++] = 'i';
        str[len++] = 'o';
        str[len++] = ' ';

        len += aes67_itoa(sdp->streams.data[s].port, &str[len], 10);

        if (1 < sdp->streams.data[s].nports){
            str[len++] = '/';
            len += aes67_itoa(sdp->streams.data[s].nports, &str[len], 10);
        }

        str[len++] = ' ';
        str[len++] = 'R';
        str[len++] = 'T';
        str[len++] = 'P';
        str[len++] = '/';
        str[len++] = 'A';
        str[len++] = 'V';
        str[len++] = 'P';
        str[len++] = ' ';

        struct aes67_sdp_attr_encoding * attrenc = aes67_sdp_get_stream_encoding(sdp, s, 0);

        AES67_ASSERT("attrenc != NULL", attrenc != NULL);

        U8TOSTR(attrenc->payloadtype, str, len);

        for(u8_t e = 1; e < sdp->streams.data[s].nencodings; e++){
            str[len++] = ' ';
            attrenc = aes67_sdp_get_stream_encoding(sdp, s, e);
            U8TOSTR(attrenc->payloadtype, str, len);
        }

        str[len++] = CR;
        str[len++] = NL;

        // c=<connection data> (0-N)
        len += aes67_sdp_connections_tostr(&str[len], maxlen - len, &sdp->connections, AES67_SDP_FLAG_DEFLVL_STREAM | s);


#if 0 < AES67_SDP_MAXSTREAMINFO
        // optional stream/media information
        // i=<stream info>

        if (sdp->streams.data[s].info.length > 0){
            str[len++] = 'i';
            str[len++] = '=';

            aes67_memcpy(&str[len], sdp->streams.data[s].info.data, sdp->streams.data[s].info.length);
            len += sdp->streams.data[s].info.length;

            str[len++] = CR;
            str[len++] = NL;
        }

#endif //0 < AES67_SDP_MAXSTREAMINFO


        //// Media/stream attributes

        //a=(inactive|recvonly|sendonly)

        AES67_ASSERT("AES67_SDP_ATTR_MODE_ISVALID(sdp->streams.data[s].mode)", AES67_SDP_ATTR_MODE_ISVALID(sdp->streams.data[s].mode));

        str[len++] = 'a';
        str[len++] = '=';

        switch(sdp->streams.data[s].mode){
            case aes67_sdp_attr_mode_inactive:
                str[len++] = 'i';
                str[len++] = 'n';
                str[len++] = 'a';
                str[len++] = 'c';
                str[len++] = 't';
                str[len++] = 'i';
                str[len++] = 'v';
                str[len++] = 'e';
                break;
            case aes67_sdp_attr_mode_recvonly:
                str[len++] = 'r';
                str[len++] = 'e';
                str[len++] = 'c';
                str[len++] = 'v';
                str[len++] = 'o';
                str[len++] = 'n';
                str[len++] = 'l';
                str[len++] = 'y';
                break;
            case aes67_sdp_attr_mode_sendonly:
                str[len++] = 's';
                str[len++] = 'e';
                str[len++] = 'n';
                str[len++] = 'd';
                str[len++] = 'o';
                str[len++] = 'n';
                str[len++] = 'l';
                str[len++] = 'y';
                break;
            default:
                AES67_ASSERT("invalid mode", false);
                break;
        }

        str[len++] = CR;
        str[len++] = NL;

        // each possible encoding for a stream
        // a=rtpmap:<fmtX> (L16|L24)/<sample-rate>[/<nchannels>]
        for(u8_t e = 0; e < sdp->streams.data[s].nencodings; e++){

            attrenc = aes67_sdp_get_stream_encoding(sdp, s, e);

            str[len++] = 'a';
            str[len++] = '=';
            str[len++] = 'r';
            str[len++] = 't';
            str[len++] = 'p';
            str[len++] = 'm';
            str[len++] = 'a';
            str[len++] = 'p';
            str[len++] = ':';

            U8TOSTR(attrenc->payloadtype, str, len);

            str[len++] = ' ';

            AES67_ASSERT("AES67_AUDIO_ENCODING_ISVALID(attrenc->encoding)", AES67_AUDIO_ENCODING_ISVALID(attrenc->encoding));

            if (attrenc->encoding == aes67_audio_encoding_L16){
                str[len++] = 'L';
                str[len++] = '1';
                str[len++] = '6';
            } else { // L24
                str[len++] = 'L';
                str[len++] = '2';
                str[len++] = '4';
            }

            str[len++] = '/';

            AES67_ASSERT("attrenc->samplerate > 0",attrenc->samplerate > 0);

            len += aes67_itoa(attrenc->samplerate, &str[len], 10);

            if (attrenc->nchannels > 1){
                str[len++] = '/';
                len += aes67_itoa(attrenc->nchannels, &str[len], 10);
            }

            str[len++] = CR;
            str[len++] = NL;
        }


        //all possible ptimes
        //first (as currently configured): a=ptime:<millisec>[.<millisec decimal>]
        //more (as capabilities): a=acap:<N> ptime:<millisec>[.<millisec decimal>]

        AES67_ASSERT("sdp->streams.data[s].ptimes.count > 0", sdp->streams.data[s].ptimes.count > 0);

        str[len++] = 'a';
        str[len++] = '=';
        str[len++] = 'p';
        str[len++] = 't';
        str[len++] = 'i';
        str[len++] = 'm';
        str[len++] = 'e';
        str[len++] = ':';

        len += aes67_itoa(sdp->streams.data[s].ptimes.data[0].msec, &str[len], 10);

        if (sdp->streams.data[s].ptimes.data[0].msec_frac > 0){
            str[len++] = '.';
            len += aes67_itoa(sdp->streams.data[s].ptimes.data[0].msec_frac, &str[len], 10);
        }

        str[len++] = CR;
        str[len++] = NL;

        if ( (sdp->streams.data[s].ptimes.cfg & AES67_SDP_CAP_SET) != 0){

            // when proposing ptime capabilities, just list them
            if ( (sdp->streams.data[s].ptimes.cfg & AES67_SDP_CAP_PROPOSED) == AES67_SDP_CAP_PROPOSED && sdp->streams.data[s].ptimes.count > 1){

                for(u8_t p = 0; p < sdp->streams.data[s].ptimes.count; p++){

                    str[len++] = 'a';
                    str[len++] = '=';
                    str[len++] = 'p';
                    str[len++] = 'c';
                    str[len++] = 'a';
                    str[len++] = 'p';
                    str[len++] = ':';

                    U8TOSTR(sdp->streams.data[s].ptimes.data[p].cap, str, len);

                    str[len++] = ' ';
                    str[len++] = 'p';
                    str[len++] = 't';
                    str[len++] = 'i';
                    str[len++] = 'm';
                    str[len++] = 'e';
                    str[len++] = ':';

                    len += aes67_itoa(sdp->streams.data[s].ptimes.data[p].msec, &str[len], 10);

                    if (sdp->streams.data[s].ptimes.data[p].msec_frac > 0){
                        str[len++] = '.';
                        len += aes67_itoa(sdp->streams.data[s].ptimes.data[p].msec_frac, &str[len], 10);
                    }

                    str[len++] = CR;
                    str[len++] = NL;
                }

                // when multiple ptimes are possible maxptime is required..
                //a=maxptime:<millisec>[.<millisec frac>]
                str[len++] = 'a';
                str[len++] = '=';
                str[len++] = 'm';
                str[len++] = 'a';
                str[len++] = 'x';
                str[len++] = 'p';
                str[len++] = 't';
                str[len++] = 'i';
                str[len++] = 'm';
                str[len++] = 'e';
                str[len++] = ':';

                len += aes67_itoa(sdp->streams.data[s].maxptime.msec, &str[len], 10);

                if (sdp->streams.data[s].maxptime.msec_frac > 0){
                    str[len++] = '.';
                    len += aes67_itoa(sdp->streams.data[s].maxptime.msec_frac, &str[len], 10);
                }

                str[len++] = CR;
                str[len++] = NL;
            }

            // make sure to write which cfg is proposed/active
            str[len++] = 'a';
            str[len++] = '=';
            if ( (sdp->streams.data[s].ptimes.cfg & AES67_SDP_CAP_PROPOSED) == AES67_SDP_CAP_PROPOSED) {
                str[len++] = 'p';
            } else {
                str[len++] = 'a';
            }

            str[len++] = 'c';
            str[len++] = 'f';
            str[len++] = 'g';
            str[len++] = ':';

            len += aes67_itoa((sdp->streams.data[s].ptimes.cfg & AES67_SDP_CAP_VALUE), &str[len], 10);

            str[len++] = ' ';

            str[len++] = 'a';
            str[len++] = '=';

            AES67_ASSERT("valid cfg_a index", sdp->streams.data[s].ptimes.cfg_a < sdp->streams.data[s].ptimes.count);

            len += aes67_itoa(sdp->streams.data[s].ptimes.data[sdp->streams.data[s].ptimes.cfg_a].cap, &str[len], 10);

            str[len++] = CR;
            str[len++] = NL;


        }

        // add stream level ptps
        // ie a=ts-refclk:ptp=.....
        len += aes67_sdp_ptp_tostr(&str[len], maxlen - len, &sdp->ptps, AES67_SDP_FLAG_DEFLVL_STREAM | s);

        // a=mediaclk:direct=<offset>
        str[len++] = 'a';
        str[len++] = '=';
        str[len++] = 'm';
        str[len++] = 'e';
        str[len++] = 'd';
        str[len++] = 'i';
        str[len++] = 'a';
        str[len++] = 'c';
        str[len++] = 'l';
        str[len++] = 'k';
        str[len++] = ':';
        str[len++] = 'd';
        str[len++] = 'i';
        str[len++] = 'r';
        str[len++] = 'e';
        str[len++] = 'c';
        str[len++] = 't';
        str[len++] = '=';

        len += aes67_itoa(sdp->streams.data[s].mediaclock_offset, &str[len], 10);

        str[len++] = CR;
        str[len++] = NL;


    }

    return len;
}


u32_t aes67_sdp_origin_fromstr(struct aes67_sdp_originator * origin, u8_t * str, u32_t len)
{
    return 0;
}

//inline static u32_t connection_fromstr(struct aes67_sdp * sdp, u8_t * line, u32_t llen)
//{
//
//}

u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("str != NULL", str != NULL);

    // make sure SDP data starts with v=0
    if (len < 5 || str[0] != 'v' || str[1] != '=' || str[2] != '0'){
        return AES67_SDP_ERROR;
    }

    u32_t pos = 3;

    // abort if no line termination
    if (!IS_CRNL(str[pos])){
        return AES67_SDP_ERROR;
    }

    pos++;

    // if only NL skip (ie 2 chars for newline CRNL)
    if (IS_NL(str[pos])) {
        pos++;
    }

    aes67_sdp_flags context = AES67_SDP_FLAG_DEFLVL_SESSION;
    u8_t stream_index = 0;

#define SEEN_O  1
#define SEEN_S  2
#define SEEN_C  4
#define SEEN_M  8
#define SEEN_T  16
#define SEEN_MODE   0
#define SEEN_RTPMAP 0
#define SEEN_REFCLK 0
#define SEEN_PTIME 0
#define SEEN_MEDIACLK 0
#define SEEN_ALL (SEEN_O | SEEN_S | SEEN_C | SEEN_M | SEEN_T | SEEN_MODE | SEEN_RTPMAP | SEEN_REFCLK | SEEN_PTIME | SEEN_MEDIACLK)

    u16_t seen = 0; // for basic (but incomplete) checking if required fields have been seen
    size_t llen = 0; // line length

    // until end was reached
    while(pos < len){
        u8_t * line = &str[pos];
        llen = 0;

        // determine line length
        while (pos < len && line[llen] != NL){
            pos++;
            llen++;
        }

        // move position beyond newline
        pos++;

        // discard carriage return, if given
        if (line[llen-1] == CR){
            llen--;
        }

        // if line length is too short/invalid, abort or when second char not =
        if (llen < 3 || line[1] != '='){
            return AES67_SDP_ERROR;
        }

        // for comfort, let line start at actual data part
//        u8_t f = line[0];
//        line += 2;
//        llen -= 2;

        // now parse given line
        switch(line[0]){

            case 'o': // o=<user> <id> <version> IN (IP4|IP6) <originating-host>
                seen |= SEEN_O;
                break;

            case 's': //
                seen |= SEEN_S;

#if 0 < AES67_SDP_MAXSESSIONNAME
                if (llen == 3 && line[2] == ' '){
                    sdp->name.length = 0;
                } else {
                    u32_t min = AES67_SDP_MAXSESSIONNAME < llen - 2 ? AES67_SDP_MAXSESSIONNAME : llen - 2;
                    aes67_memcpy(sdp->name.data, &line[2], min);
                    sdp->name.length = min;
                }
#endif // 0 < AES67_SDP_MAXSESSIONNAME
                break;

            case 'i': // i=<session info>
#if 0 < AES67_SDP_MAXSESSIONINFO
                if (context == AES67_SDP_FLAG_DEFLVL_SESSION){
                    u32_t min = AES67_SDP_MAXSESSIONINFO < llen - 2 ? AES67_SDP_MAXSESSIONINFO : llen - 2;
                    aes67_memcpy(sdp->info.data, &line[2], min);
                    sdp->info.length = min;
                }
#if 0 < AES67_SDP_MAXSTREAMINFO
                else
#endif
#endif // 0 < AES67_SDP_MAXSESSIONNAME
#if 0 < AES67_SDP_MAXSTREAMINFO
                if (context == AES67_SDP_FLAG_DEFLVL_STREAM){
                    u32_t min = AES67_SDP_MAXSTREAMINFO < llen - 2 ? AES67_SDP_MAXSTREAMINFO : llen - 2;
                    aes67_memcpy(sdp->streams.data[stream_index].info.data, &line[2], min);
                    sdp->streams.data[stream_index].info.length = min;
                }
#endif // 0 < AES67_SDP_MAXSTREAMINFO
                break;

            case 'c':  // c=IN (IP4|IP6) <host>[/<ttl>][/<no-of-addresses>]
                seen |= SEEN_C;

                if (llen < sizeof("c=IN IP4 a")-1 || line[2] != 'I' || line[3] != 'N' || line[4] != ' ' ||
                    line[5] != 'I' || line[6] != 'P' || line[8] != ' ') {
                    //TODO report format error
                    return AES67_SDP_ERROR;
                }

                // enough poolspace for another connection?
                if (sdp->connections.count >= AES67_SDP_MAXCONNECTIONS){
                    //TODO report insufficient memory
                    return AES67_SDP_NOMEMORY;
                }

                // get new connection pointer and increase connection counter
                struct aes67_sdp_connection * con = &sdp->connections.data[sdp->connections.count++];

                // set context flag accordingly
                con->flags = AES67_SDP_FLAG_SET_YES | context;

                // default attributes
                con->address.length = 0;
                con->ttl = 0;
                con->naddr = 1;

                if (line[7] == '4') {
                    con->ipver = aes67_net_ipver_4;
                } else if (line[7] == '6') {
                    con->ipver = aes67_net_ipver_6;
                } else {
                    // unknown format
                    return AES67_SDP_ERROR;
                }

                // locate optional delimiter '/'
                u8_t * delim = aes67_memchr(&line[8], '/', llen - 9);

                size_t hostlen = llen-9;

                // if a delimiter found it is definitely a multicast address
                if (delim != NULL){
                    hostlen = delim - line - 9;

                    // move to beginning of first number
                    delim++;

                    // safety check
                    if (delim - line >= llen) {
                        //invalid format, ie missing number after delimiter ("<addr>/")
                        return AES67_SDP_ERROR;
                    }

                    u16_t readlen = 0;
                    s32_t v = aes67_atoi(delim, llen - (delim - line), 10, &readlen);

                    // if there is nothing else, it's either..
                    if (&delim[readlen] == &line[llen]) {

                        // the ipv4 required ttl or ipv6 number of addresses
                        if (con->ipver == aes67_net_ipver_4 ) {
                            con->ttl = v;
                        }

                    } else { // there is more data

                        //advance to /
                        delim += readlen;

                        // sanity check delimiter and at least one char
                        if (delim[0] != '/' || &delim[1] >= &line[llen]) {
                            return AES67_SDP_ERROR;
                        }

                        //a second delimiter can only be given when it is an ipv4 multicast address which requires
                        //a ttl value first
                        con->ttl = v;

                        v = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);

                    }

                    con->naddr = v;
                }

                aes67_memcpy(con->address.data, &line[8], hostlen);
                con->address.length = hostlen;

                break;


            case 't': // t=<start-time> <end-time>
                seen |= SEEN_T;

                u16_t readlen = 0;
                s32_t start = aes67_atoi(&line[2], llen-2, 10, &readlen);

                // check if there is the beginning of a second number
                if (3+readlen >= llen){
                    return AES67_SDP_ERROR;
                }

                s32_t end = aes67_atoi(&line[3+readlen], llen-3-readlen, 10, &readlen);

                // TODO note: this is just a basic format check, at the moment this is not used
                if (start != 0 || end != 0){
                    return AES67_SDP_NOTSUPPORTED;
                }

                break;


            case 'm':
                seen |= SEEN_M;
                break;

            case 'a':
                break;

            case 'u':
            case 'e':
            case 'p':
            case 'b':
            case 'z':
            case 'k':
            case 'r':
                // fall through to default, ie ignore

            default:
                break;
        }
    }



    return (seen & SEEN_ALL) == SEEN_ALL ? AES67_SDP_OK : AES67_SDP_INCOMPLETE;
}

