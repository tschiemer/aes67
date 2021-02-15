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


#define SUB1kTOSTR(sub1000, str, len) \
    if (sub1000 >= 100){ str[len++] = '0' + (sub1000 / 100); } \
    if (sub1000 >= 10){ str[len++] = '0' + ((sub1000 % 100) / 10); } \
    str[len++] = '0' + (sub1000 % 10);

#define DEC1kTOSTR(dec1000, str, len) \
    if (dec1000 < 100) { str[len++] = '0'; } \
    else { str[len++] = '0' + (dec1000 / 100); } \
    if (dec1000 < 10) {str[len++] = '0'; }  \
    else str[len++] = '0' + ((dec1000 % 100) / 10); \
    str[len++] = '0' + (dec1000 % 10);\
    if (str[len-1] == '0') { len--; }; \
    if (str[len-1] == '0') { len--; }; \

#define PTIMETOSTR(ptime, str, len) \
    u16_t ptime_tmp = (ptime) / 1000; \
    SUB1kTOSTR(ptime_tmp, str, len); \
    if ( (ptime_tmp = (ptime) % 1000) > 0) { \
        str[len++] = '.';          \
        DEC1kTOSTR(ptime_tmp, str, len);   \
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

#if 0 < AES67_SDP_MAXSESSIONNAME
    sdp->name.length = 0;
#endif

#if 0 < AES67_SDP_MAXSESSIONINFO
    sdp->info.length = 0;
#endif
    sdp->mode = aes67_sdp_attr_mode_undefined;

    sdp->connections.count = 0;

    sdp->streams.count = 0;

    sdp->encodings.count = 0;

    sdp->ptp_domain = 0;
    sdp->nptp = 0;
    sdp->ptps.count = 0;


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
//    AES67_ASSERT("maxlen > sizeof(\"o=    IN IP4 \\r\")", maxlen > sizeof("o=    IN IP4 \r"));
    AES67_ASSERT("origin != NULL", origin != NULL);

    // "o=<username> <id> <version> IN IP<ipver> <address>\r\n"
    if (maxlen < sizeof("o=   IN IP4 \r") + origin->username.length + origin->session_id.length + origin->session_version.length + origin->address.length){
        return 0;
    }

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
    if (origin->ipver == aes67_net_ipver_4){
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

        // "c=IN IP<ipver> <address>[/<ttl>][/<naddr>]\r\n"
        if (maxlen < len + sizeof("c=IN IP4 \r") + cons->data[i].address.length + 8){
            return -1;
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

        // compare to longest possible length
        if (maxlen < len + sizeof("a=ts-refclk:ptp=IEEE802.1AS-2011:01-02-03-04-05-06-07-08\r")){
            return -1;
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
        aes67_bintohex(&ptps->data[i].ptp.gmid.u8[0], 1, &str[len]);
        len += 2;
        for(int j = 1; j < sizeof(union aes67_ptp_eui64); j++){
            str[len++] = '-';
            aes67_bintohex(&ptps->data[i].ptp.gmid.u8[j], 1, &str[len]);
            len += 2;
        }

        // add PTP domain only if 2008 or 2019 version
        if (ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2008 || ptps->data[i].ptp.type == aes67_ptp_type_IEEE1588_2019){
            // domain values 0 - 127
            str[len++] = ':';
            SUB1kTOSTR(ptps->data[i].ptp.domain, str, len);
        }

        str[len++] = CR;
        str[len++] = NL;
    }

    return len;
}

u32_t aes67_sdp_attrmode_tostr( u8_t * str, u32_t maxlen, enum aes67_sdp_attr_mode mode)
{
    if (mode == aes67_sdp_attr_mode_undefined){
        return 0;
    }

    u32_t len = 0;

    // "a=(inactive|recvonly|sendonly|sendrecv)\r\n" (all have same length)
    if (maxlen < sizeof("a=inactive\r")){
        return -1;
    }

    AES67_ASSERT("AES67_SDP_ATTR_MODE_ISVALID(sdp->streams.data[s].mode)", AES67_SDP_ATTR_MODE_ISVALID(mode));

    str[len++] = 'a';
    str[len++] = '=';

    switch(mode){
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
        case aes67_sdp_attr_mode_sendrecv:
            str[len++] = 's';
            str[len++] = 'e';
            str[len++] = 'n';
            str[len++] = 'd';
            str[len++] = 'r';
            str[len++] = 'e';
            str[len++] = 'c';
            str[len++] = 'v';
            break;
        default:
            AES67_ASSERT("invalid mode", false);
            break;
    }

    str[len++] = CR;
    str[len++] = NL;

    return len;
}

u32_t aes67_sdp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp * sdp)
{
    AES67_ASSERT("str != NULL", str != NULL);
    AES67_ASSERT("maxlen > 5", maxlen > 5); // the length of a meaningful AES67-SDP packet
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    if (maxlen < 5){
        return 0;
    }

    // length of sdp packet
    u32_t len = 0, l;


    //v=0
    str[len++] = 'v';
    str[len++] = '=';
    str[len++] = '0';
    str[len++] = CR;
    str[len++] = NL;

    // originator (o=..)
    l = aes67_sdp_origin_tostr(&str[len], maxlen - 5, &sdp->originator);
    if (l == 0){
        return 0;
    }
    len += l;

    //s=<session_data name>
    if (maxlen < len + sizeof("s= \r") + sdp->name.length){
        return 0;
    }
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
        if (maxlen < len + sizeof("i=\r") + sdp->info.length){
            return 0;
        }
        str[len++] = 'i';
        str[len++] = '=';

        aes67_memcpy(&str[len], sdp->info.data, sdp->info.length);
        len += sdp->info.length;

        str[len++] = CR;
        str[len++] = NL;
    }
#endif

    // c=<connection data> (0-N)
    l = aes67_sdp_connections_tostr(&str[len], maxlen - len, &sdp->connections, AES67_SDP_FLAG_DEFLVL_SESSION);
    if (l == -1){
        return 0;
    }
    len += l;

    // b=<bwtype>:<bandwidth>

    // t=<start-time> <stop-time>
    // ALWAYS t=0 0
    if (maxlen < len + sizeof("t=0 0\r")){
        return 0;
    }
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
    if (maxlen < len + sizeof("a=tool:") + sizeof(AES67_SDP_TOOL)){
        return 0;
    }
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
        if (maxlen < len + sizeof("a=clock-domain:PTPv2 127\r")){
            return 0;
        }
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
        SUB1kTOSTR(d, str, len);
        str[len++] = CR;
        str[len++] = NL;
    }

    // add session level reference clocks ts-refclk
    l = aes67_sdp_ptp_tostr(&str[len], maxlen - len, &sdp->ptps, AES67_SDP_FLAG_DEFLVL_SESSION);
    if (l == -1){
        return 0;
    }
    len += l;

    // add session level mode
    l = aes67_sdp_attrmode_tostr(&str[len], maxlen - len, sdp->mode);
    if (l == -1){
        return 0;
    }
    len += l;


    for(u8_t s = 0; s < sdp->streams.count; s++){

        struct aes67_sdp_stream * stream = &sdp->streams.data[s];

        // roughly
        if (maxlen < len + sizeof("a=audio 65535/100 RTP/AVP ")  + stream->nencodings * sizeof("127")){
            return 0;
        }

        // m=audio port[/<no-of-ports>] RTP/AVP <fmt1> ..
        str[len++] = 'm';
        str[len++] = '=';
        str[len++] = 'a';
        str[len++] = 'u';
        str[len++] = 'd';
        str[len++] = 'i';
        str[len++] = 'o';
        str[len++] = ' ';

        len += aes67_itoa(stream->port, &str[len], 10);

        if (1 < stream->nports){
            str[len++] = '/';
            len += aes67_itoa(stream->nports, &str[len], 10);
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

        SUB1kTOSTR(attrenc->payloadtype, str, len);

        for(u8_t e = 1; e < stream->nencodings; e++){
            str[len++] = ' ';
            attrenc = aes67_sdp_get_stream_encoding(sdp, s, e);
            SUB1kTOSTR(attrenc->payloadtype, str, len);
        }

        str[len++] = CR;
        str[len++] = NL;

        // c=<connection data> (0-N)
        l = aes67_sdp_connections_tostr(&str[len], maxlen - len, &sdp->connections, AES67_SDP_FLAG_DEFLVL_STREAM | s);
        if (l == -1){
            return 0;
        }
        len += l;

#if 0 < AES67_SDP_MAXSTREAMINFO
        // optional stream/media information
        // i=<stream info>

        if (stream->info.length > 0){
            if (maxlen < len + sizeof("i=\r") + stream->info.length){
                return 0;
            }
            str[len++] = 'i';
            str[len++] = '=';

            aes67_memcpy(&str[len], stream->info.data, stream->info.length);
            len += stream->info.length;

            str[len++] = CR;
            str[len++] = NL;
        }

#endif //0 < AES67_SDP_MAXSTREAMINFO

        //// Media/stream attributes

        // add media level mode
        l = aes67_sdp_attrmode_tostr(&str[len], maxlen - len, stream->mode);
        if (l == -1){
            return 0;
        }
        len += l;


        // each possible encoding for a stream
        // a=rtpmap:<fmtX> (L16|L24)/<sample-rate>[/<nchannels>]
        for(u8_t e = 0; e < stream->nencodings; e++){

            // just roughly
            if (maxlen < len + sizeof("a=rtpmap:127 L32/192000/64\r")){
                return 0;
            }

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

            SUB1kTOSTR(attrenc->payloadtype, str, len);

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

        // if ptime is set, write it out
        if ((stream->ptime & AES67_SDP_PTIME_SET) == AES67_SDP_PTIME_SET){

            if (maxlen < len - sizeof("a=ptime:0.123\r")){
                return 0;
            }

            str[len++] = 'a';
            str[len++] = '=';
            str[len++] = 'p';
            str[len++] = 't';
            str[len++] = 'i';
            str[len++] = 'm';
            str[len++] = 'e';
            str[len++] = ':';

            PTIMETOSTR((stream->ptime & AES67_SDP_PTIME_VALUE), str, len);

            str[len++] = CR;
            str[len++] = NL;
        }

        // only process ptime capabilities (and maxptime) when capabilities have necessary space..
#if 0 < AES67_SDP_MAXPTIMECAPS
        // when several ptime propositions are given, list them
        if ((stream->ptime_cap.cfg & AES67_SDP_CAP_SET) == AES67_SDP_CAP_PROPOSED && stream->ptime_cap.count > 1){

            if (maxlen < len + stream->ptime_cap.count * sizeof("a=pcap:12 ptime:0.123\r") + sizeof("a=maxptime:0.123\r")){
                return 0;
            }

            for(u8_t p = 0; p < stream->ptime_cap.count; p++){

                str[len++] = 'a';
                str[len++] = '=';
                str[len++] = 'p';
                str[len++] = 'c';
                str[len++] = 'a';
                str[len++] = 'p';
                str[len++] = ':';

                SUB1kTOSTR(stream->ptime_cap.data[p].cap, str, len);

                str[len++] = ' ';
                str[len++] = 'p';
                str[len++] = 't';
                str[len++] = 'i';
                str[len++] = 'm';
                str[len++] = 'e';
                str[len++] = ':';

                PTIMETOSTR(stream->ptime_cap.data[p].ptime & AES67_SDP_PTIME_VALUE, str, len);

                str[len++] = CR;
                str[len++] = NL;
            }

            // when multiple ptime_cap are possible maxptime is required..
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

            PTIMETOSTR(stream->maxptime & AES67_SDP_PTIME_VALUE, str, len);

            str[len++] = CR;
            str[len++] = NL;
        }


        // when proposing or accepting a ptime value, communicate accordingly
        if ( (stream->ptime_cap.cfg & AES67_SDP_CAP_SET) != 0 ){

            if (maxlen < len + sizeof("a=pcfg:12 a=12\r")){
                return 0;
            }

            // make sure to write which cfg is proposed/active
            str[len++] = 'a';
            str[len++] = '=';
            if ((stream->ptime_cap.cfg & AES67_SDP_CAP_SET) == AES67_SDP_CAP_PROPOSED) {
                str[len++] = 'p';
            } else {
                str[len++] = 'a';
            }

            str[len++] = 'c';
            str[len++] = 'f';
            str[len++] = 'g';
            str[len++] = ':';

            len += aes67_itoa((stream->ptime_cap.cfg & AES67_SDP_CAP_VALUE), &str[len], 10);

            str[len++] = ' ';

            str[len++] = 'a';
            str[len++] = '=';

            len += aes67_itoa(stream->ptime_cap.cfg_a, &str[len], 10);

            str[len++] = CR;
            str[len++] = NL;
        }
#endif //0 < AES67_SDP_MAXPTIMECAPS



        // add stream level ptps
        // ie a=ts-refclk:ptp=.....
        l = aes67_sdp_ptp_tostr(&str[len], maxlen - len, &sdp->ptps, AES67_SDP_FLAG_DEFLVL_STREAM | s);
        if (l == -1){
            return 0;
        }
        len += l;

        // a=mediaclk:direct=<offset>
        if (maxlen < len + sizeof("a=mediaclock:direct=4294967295\r")){
            return 0;
        }
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

        len += aes67_itoa(stream->mediaclock_offset, &str[len], 10);

        str[len++] = CR;
        str[len++] = NL;


    }

    return len;
}


u32_t aes67_sdp_origin_fromstr(struct aes67_sdp_originator * origin, u8_t * str, u32_t len)
{
    AES67_ASSERT("origin != NULL", origin != NULL);
    AES67_ASSERT("str != NULL", str != NULL);

    if (len < sizeof("o=- 1 1 IN IP4 a")-1 || str[0] != 'o' || str[1] != '='){
        return AES67_SDP_ERROR;
    }

    u8_t * pos = &str[2];
    u8_t * delim = NULL;

    // username
    if (pos[0] == '-'){
        origin->username.length = 0;
        pos += 2;
    } else {
        delim = aes67_memchr(pos, ' ', len-2);

        if (delim == NULL || delim == pos){
            return AES67_SDP_ERROR;
        }

        origin->username.length = delim - pos;
        aes67_memcpy(origin->username.data, pos, delim - pos);

        // move past delimiter
        pos = delim + 1;
    }

    // session id
    if (pos >= &str[len]){
        return AES67_SDP_ERROR;
    }

    delim = aes67_memchr(pos, ' ', &str[len] - pos);

    if (delim == NULL || delim == pos){
        return AES67_SDP_ERROR;
    }

    origin->session_id.length = delim - pos;
    aes67_memcpy(origin->session_id.data, pos, delim - pos);

    // move past delimiter
    pos = delim + 1;


    // session version
    if (pos >= &str[len]){
        return AES67_SDP_ERROR;
    }

    delim = aes67_memchr(pos, ' ', &str[len] - pos);

    if (delim == NULL || delim == pos){
        return AES67_SDP_ERROR;
    }

    origin->session_version.length = delim - pos;
    aes67_memcpy(origin->session_version.data, pos, delim - pos);

    // move past delimiter
    pos = delim + 1;


    if (pos + (sizeof("IN IP4 a")-1) >= &str[len] || pos[0] != 'I' || pos[1] != 'N' || pos[2] != ' ' || pos[3] != 'I' || pos[4] != 'P' || pos[6] != ' '){
        return AES67_SDP_ERROR;
    }

    if (pos[5] == '4'){
        origin->ipver = aes67_net_ipver_4;
    } else if (pos[6] == '6'){
        origin->ipver = aes67_net_ipver_6;
    } else {
        return AES67_SDP_ERROR;
    }

    pos += sizeof("IN IP4 ")-1;

    if (pos >= &str[len]){
        return AES67_SDP_ERROR;
    }

    origin->address.length = &str[len] - pos;
    aes67_memcpy(origin->address.data, pos, &str[len] - pos);

    return AES67_SDP_OK;
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

    // reset
    aes67_sdp_init(sdp);

    aes67_sdp_flags context = AES67_SDP_FLAG_DEFLVL_SESSION;
    struct aes67_sdp_stream * stream = NULL;

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

#if 0 < AES67_SDP_MAXPTIMECAPS
    // remember if unsupported capabilities/configurations were detected
    u8_t unsupported_caps = false;
#endif

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

        // skip empty lines
        if (llen == 0){
            continue;
        }

        // if line length is too short/invalid, abort or when second char not =
        if (llen < 3 || line[1] != '='){
            return AES67_SDP_ERROR;
        }

        // now parse given line
        switch(line[0]){

            case 'o': // o=<user> <id> <version> IN (IP4|IP6) <originating-host>
                seen |= SEEN_O;

                u32_t r = aes67_sdp_origin_fromstr(&sdp->originator, line, llen);

                if (r != AES67_SDP_OK){
                    return r;
                }

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
                if ((context & AES67_SDP_FLAG_DEFLVL_STREAM) == AES67_SDP_FLAG_DEFLVL_STREAM){
                    u32_t min = AES67_SDP_MAXSTREAMINFO < llen - 2 ? AES67_SDP_MAXSTREAMINFO : llen - 2;
                    aes67_memcpy(stream->info.data, &line[2], min);
                    stream->info.length = min;
                }
#endif // 0 < AES67_SDP_MAXSTREAMINFO
                break;

            case 'c': { // c=IN (IP4|IP6) <host>[/<ttl>][/<no-of-addresses>]
                seen |= SEEN_C;

                if (llen < sizeof("c=IN IP4 a") - 1 || line[2] != 'I' || line[3] != 'N' || line[4] != ' ' ||
                    line[5] != 'I' || line[6] != 'P' || line[8] != ' ') {
                    //TODO report format error
                    return AES67_SDP_ERROR;
                }

                // enough poolspace for another connection?
                if (sdp->connections.count >= AES67_SDP_MAXCONNECTIONS) {
                    //TODO report insufficient memory
                    return AES67_SDP_NOMEMORY;
                }

                // get new connection pointer and increase connection counter
                struct aes67_sdp_connection *con = &sdp->connections.data[sdp->connections.count++];

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
                u8_t *delim = aes67_memchr(&line[9], '/', llen - 9);

                size_t hostlen = llen - 9;

                // if a delimiter found it is definitely a multicast address
                if (delim != NULL) {
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
                        if (con->ipver == aes67_net_ipver_4) {
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

                aes67_memcpy(con->address.data, &line[9], hostlen);
                con->address.length = hostlen;
            }
                break;


            case 't': {// t=<start-time> <end-time>
                seen |= SEEN_T;

                u16_t readlen = 0;
                s32_t start = aes67_atoi(&line[2], llen - 2, 10, &readlen);

                // check if there is the beginning of a second number
                if (3 + readlen >= llen) {
                    return AES67_SDP_ERROR;
                }

                s32_t end = aes67_atoi(&line[3 + readlen], llen - 3 - readlen, 10, &readlen);

                // TODO note: this is just a basic format check, at the moment this is not used
                if (start != 0 || end != 0) {
                    return AES67_SDP_NOTSUPPORTED;
                }
            }
                break;


            case 'm': {
                seen |= SEEN_M;

                if (llen < sizeof("m=audio 0 RTP/AVP 96") - 1) {
                    return AES67_SDP_ERROR;
                }

                // only audio formats are supported
                // TODO in principle we could just skip this media/stream instead of aborting
                if (line[2] != 'a' || line[3] != 'u' || line[4] != 'd' || line[5] != 'i' || line[6] != 'o' ||
                    line[7] != ' ') {
                    return AES67_SDP_NOTSUPPORTED;
                }

                u16_t readlen = 0;

                u8_t * pos = &line[8];

                // get port and validate
                s32_t port = aes67_atoi(pos, llen - 8, 10, &readlen);

                if (port == 0) {
                    return AES67_SDP_ERROR;
                }

                pos += readlen;

                //check for optional number of ports
                s32_t nports = 2;
                if (pos[0] == '/') {

                    nports = aes67_atoi(&pos[1], llen - 9 - readlen, 10, &readlen);
                    if (nports == 0) {
                        return AES67_SDP_ERROR;
                    }
                    pos += 1 + readlen;
                }

                // check format and profile type
                if (pos[0] != ' ' || pos[1] != 'R' || pos[2] != 'T' || pos[3] != 'P' || pos[4] != '/' || pos[5] != 'A' || pos[6] != 'V' || pos[7] != 'P' || pos[8] != ' '){
                    return AES67_SDP_NOTSUPPORTED;
                }

                // move beyond profile type
                pos += 9;

                u8_t nenc = 0;
                while (pos < &line[llen]){
                    s32_t e = aes67_atoi(pos, &line[llen] - pos, 10, &readlen);
                    if (readlen == 0){
                        return AES67_SDP_ERROR;
                    }
                    pos += 1 + readlen;
                    if (e < AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START || AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_END < e){
                        return AES67_SDP_NOTSUPPORTED;
                    }
                    //TODO remember encoding indices (?) possibly just for validation
                    nenc++;
                }

                if (nenc == 0){
                    return AES67_SDP_ERROR;
                }

                if (sdp->streams.count >= AES67_SDP_MAXSTREAMS) {
                    return AES67_SDP_NOMEMORY;
                }


                context = AES67_SDP_FLAG_DEFLVL_STREAM | sdp->streams.count;
                stream = &sdp->streams.data[sdp->streams.count];

                sdp->streams.count++;

                // init stream
                stream->info.length = 0;
                stream->port = port;
                stream->nports = nports;
                stream->nencodings = 0;
                stream->nptp = 0;
                stream->mode = aes67_sdp_attr_mode_undefined;
                stream->ptime = 0;
                stream->ptime_cap.count = 0;
                stream->ptime_cap.cfg = 0;
                stream->mediaclock_offset = 0;
            }
                break;

            case 'a':{

                u8_t * delim = aes67_memchr(line, ':', llen);

                // just check that after the delimiter always is some data
                // (checking here instead of in each case..)
                // (will also be true if delim == NULL ;)
                if (delim >= &line[llen]){
                    return AES67_SDP_ERROR;
                }

                u8_t processed = true;

                // if we're in stream level context, check stream/media level only attributes
                // likewise, session level only attributes
                // if not processed afterwards, check for flexible attributes
                // if still not processed, do whatever

                if ((context & AES67_SDP_FLAG_DEFLVL_STREAM) == AES67_SDP_FLAG_DEFLVL_STREAM){

                    if (delim - line == sizeof("a=rtpmap")-1 &&
                        line[2] == 'r' &&
                        line[3] == 't' &&
                        line[4] == 'p' &&
                        line[5] == 'm' &&
                        line[6] == 'a' &&
                        line[7] == 'p'){

                        // sanity check
                        if (llen < sizeof("a=rtpmap:9")-1){
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;

                        // read encoding format index
                        u8_t pt = aes67_atoi(&line[9], llen - 9, 10, &readlen);

                        // AES67 is intended to use dynamic payloads (as defined in this currently parse line) only
                        if (pt < AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START || AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_END < pt){
                            return AES67_SDP_ERROR;
                        }

                        // move past index (to supposed space)
                        delim += 1 + readlen;

                        if (&delim[sizeof(" L16/1000")-1] >= &line[llen] || delim[0] != ' '){
                            return AES67_SDP_ERROR;
                        }

                        enum aes67_audio_encoding enc;

                        if (delim[1] == 'L' &&
                            delim[2] == '8'){

                            enc = aes67_audio_encoding_L8;
                        }
                        else if (delim[1] == 'L' &&
                                delim[2] == '1' &&
                                delim[3] == '6'){

                            enc = aes67_audio_encoding_L16;
                        }
                        else if (delim[1] == 'L' &&
                                 delim[2] == '2' &&
                                 delim[3] == '4'){

                            enc = aes67_audio_encoding_L24;
                        }
                        else if (delim[1] == 'L' &&
                                 delim[2] == '3' &&
                                 delim[3] == '2'){

                            enc = aes67_audio_encoding_L32;
                        }
                        else {
                            // encoding is not supported, skip this one
                            continue;
                        }

                        // move pointer past encoding type
                        delim += enc == aes67_audio_encoding_L8 ? 3 : 4;

                        if (&delim[sizeof("/1000")-1] > &line[llen] || delim[0] != '/'){
                            return AES67_SDP_ERROR;
                        }

                        // get clock frequency / sample rate
                        s32_t sr = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);

                        if (readlen == 0 || sr == 0){
                            return AES67_SDP_ERROR;
                        }

                        // optionally get channel count (default = 1)
                        s32_t ch = 1;

                        delim += 1+readlen;

                        if (&delim[1] < &line[llen] && delim[0] == '/'){
                            ch = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);

                            // sanity check (support of upto a max of 256 channels (which should be fine.....)
                            if (readlen == 0 || ch < 1 || ch > UINT8_MAX){
                                return AES67_SDP_ERROR;
                            }
                        }

                        if (sdp->encodings.count >= AES67_SDP_MAXENCODINGS){
                            return AES67_SDP_NOMEMORY;
                        }

                        struct aes67_sdp_attr_encoding * encoding = &sdp->encodings.data[sdp->encodings.count++];

                        stream->nencodings++;
                        encoding->flags = AES67_SDP_FLAG_SET_YES | context;
                        encoding->payloadtype = pt;
                        encoding->encoding = enc;
                        encoding->samplerate = sr;
                        encoding->nchannels = ch;

                    }
                    else if (delim - line == sizeof("a=ptime")-1 &&
                        line[2] == 'p' &&
                        line[3] == 't' &&
                        line[4] == 'i' &&
                        line[5] == 'm' &&
                        line[6] == 'e' ){

                        if (llen < sizeof("a=ptime:0")-1){
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;

                        stream->ptime = 1000 * aes67_atoi(&line[8], llen - 8, 10, &readlen);

                        delim = line + 8 + readlen;

                        // check if (optional) millisec fractional part is set
                        if (delim == &line[llen]){
                            // ok
                        } else if ( &delim[2] > &line[llen]  || delim[0] != '.'){
                            return AES67_SDP_ERROR;
                        } else {
                            u16_t pt = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);
                            if (pt < 10) { pt *= 100; }
                            else if (pt < 100) { pt *= 10;}

                            stream->ptime += pt;

                            if (readlen == 0){
                                return AES67_SDP_ERROR;
                            }
                        }

                        stream->ptime |= AES67_SDP_PTIME_SET;

                    }
                    else if (delim - line == sizeof("a=maxptime")-1 &&
                        line[2] == 'm' &&
                        line[3] == 'a' &&
                        line[4] == 'x' &&
                        line[5] == 'p' &&
                        line[6] == 't' &&
                        line[7] == 'i' &&
                        line[8] == 'm' &&
                        line[9] == 'e'){

                        if (llen < sizeof("a=maxptime:0")-1){
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;

                        stream->maxptime = 1000*aes67_atoi(&line[11], llen - 11, 10, &readlen);

                        delim = line + 11 + readlen;

                        // check if (optional) millisec fractional part is set
                        if (delim == &line[llen]){
                            // ok
                        } else if ( &delim[2] > &line[llen]  || delim[0] != '.'){
                            return AES67_SDP_ERROR;
                        } else {
                            u16_t pt = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);
                            if (pt < 10) { pt *= 100; }
                            else if (pt < 100) { pt *= 10;}

                            stream->maxptime += pt;

                            if (readlen == 0){
                                return AES67_SDP_ERROR;
                            }
                        }

                        stream->maxptime |= AES67_SDP_PTIME_SET;
                    }
#if 0 < AES67_SDP_MAXPTIMECAPS
                    else if (delim - line == sizeof("a=pcap") - 1 &&
                        line[2] == 'p' &&
                        line[3] == 'c' &&
                        line[4] == 'a' &&
                        line[5] == 'p'){

                        if (unsupported_caps == true){
                            continue;
                        }

                        if (llen < sizeof("a=pcap:1 ptime:1")-1){
                            unsupported_caps = true;
                            continue;
                        }

                        u16_t readlen = 0;

                        u8_t capi = aes67_atoi(&line[7], llen - 7, 10, &readlen);

                        if (readlen == 0 || 9+readlen > llen || line[7+readlen] != ' '){
                            return AES67_SDP_ERROR;
                        }

                        u8_t * opt = &line[8+readlen];

                        delim = aes67_memchr(opt, ':', &line[llen] - opt);

                        if (delim - opt != sizeof("ptime")-1 ||
                            opt[0] != 'p' ||
                            opt[1] != 't' ||
                            opt[2] != 'i' ||
                            opt[3] != 'm' ||
                            opt[4] != 'e'){

                            unsupported_caps = true;
                            continue;
                        }

                        if (&delim[1] > &line[llen]){
                            return AES67_SDP_ERROR;
                        }

                        if (stream->ptime_cap.count >= AES67_SDP_MAXPTIMECAPS){
                            return AES67_SDP_NOMEMORY;
                        }

                        struct aes67_sdp_attr_ptimecap * ptimecap = &stream->ptime_cap.data[stream->ptime_cap.count++];

                        ptimecap->cap = capi;
                        ptimecap->ptime = 1000 * aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);

                        delim += 1+readlen;

                        // check if (optional) millisec fractional part is set
                        if (delim == &line[llen]){
                            // ok
                        } else if ( &delim[2] > &line[llen]  || delim[0] != '.'){
                            return AES67_SDP_ERROR;
                        } else {
                            u16_t pt = aes67_atoi(&delim[1], &line[llen] - &delim[1], 10, &readlen);
                            if (pt < 10) { pt *= 100; }
                            else if (pt < 100) { pt *= 10;}

                            ptimecap->ptime += pt;

                            if (readlen == 0){
                                return AES67_SDP_ERROR;
                            }
                        }
                    }

                    else if (delim - line == sizeof("a=pcfg") - 1 &&
                        (line[2] == 'p' || line[2] == 'a') &&
                         line[3] == 'c' &&
                         line[4] == 'f' &&
                         line[5] == 'g'){

                        if (unsupported_caps == true){
                            continue;
                        }

                        // sanity check
                        if (llen < sizeof("a=pcfg:1 a=1")-1){
                            return AES67_SDP_ERROR;
                        }

                        // sanity check (can not handle multiple pcfg)
                        if (stream->ptime_cap.cfg != 0){
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;
                        stream->ptime_cap.cfg = aes67_atoi(&line[7], llen - 7, 10, &readlen);

                        stream->ptime_cap.cfg |= line[2] == 'p' ? AES67_SDP_CAP_PROPOSED : AES67_SDP_CAP_ACTIVE;

                        delim = &line[8+readlen];

                        // sanity check (delim = "a=1...")
                        if (delim + 3 > &line[llen] || delim[0] != 'a' || delim[1] != '='){
                            return AES67_SDP_ERROR;
                        }

                        stream->ptime_cap.cfg_a = aes67_atoi(&delim[2], &line[llen] - &delim[2], 10, &readlen);

                        if (readlen == 0){
                            return AES67_SDP_ERROR;
                        }

                    }
#endif //0 < AES67_SDP_MAXPTIMECAPS
                    else if (delim - line == sizeof("a=mediaclk")-1 &&
                        line[2] == 'm' &&
                        line[3] == 'e' &&
                        line[4] == 'd' &&
                        line[5] == 'i' &&
                        line[6] == 'a' &&
                        line[7] == 'c' &&
                        line[8] == 'l' &&
                        line[9] == 'k'){

                        // sanity check
                        if (llen < sizeof("a=mediaclk:direct=0")-1 ||
                            line[11] != 'd' ||
                            line[12] != 'i' ||
                            line[13] != 'r' ||
                            line[14] != 'e' ||
                            line[15] != 'c' ||
                            line[16] != 't' ||
                            line[17] != '='
                        ){
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;
                        stream->mediaclock_offset = aes67_atoi(&line[18], llen - 18, 10, &readlen);

                        if (readlen == 0){
                            return AES67_SDP_ERROR;
                        }
                    }
                    // no matching attribute
                    else {
                        processed = false;
                    }

                } else {
                    // session level only attributes

                    if (delim - line == sizeof("a=ptp-domain")-1 &&
                        line[2] == 'p' &&
                        line[3] == 't' &&
                        line[4] == 'p' &&
                        line[5] == '-' &&
                        line[6] == 'd' &&
                        line[7] == 'o' &&
                        line[8] == 'm' &&
                        line[9] == 'a' &&
                        line[10] == 'i' &&
                        line[11] == 'n'){

                        // sanity check
                        if (llen < sizeof("a=ptp-domain:PTPv2 0")-1 ||
                            line[13] != 'P' ||
                            line[14] != 'T' ||
                            line[15] != 'P' ||
                            line[16] != 'v' ||
                            line[17] != '2' ||
                            line[18] != ' ') {
                            return AES67_SDP_ERROR;
                        }

                        u16_t readlen = 0;
                        s32_t t = aes67_atoi(&line[19], llen - 19, 10, &readlen);

                        // sanity check
                        if (readlen == 0 || t > 127){
                            return AES67_SDP_ERROR;
                        }

                        sdp->ptp_domain = AES67_SDP_PTP_DOMAIN_SET | (AES67_SDP_PTP_DOMAIN_VALUE & t);
                    }
                    // no matching attribute
                    else {
                        processed = false;
                    }
                }

                // if not processed so far it can be a session OR media/stream level attribute
                if (processed == false){


                    if (llen == sizeof("a=recvonly") - 1 &&
                        line[2] == 'r' &&
                        line[3] == 'e' &&
                        line[4] == 'c' &&
                        line[5] == 'v' &&
                        line[6] == 'o' &&
                        line[7] == 'n' &&
                        line[8] == 'l' &&
                        line[9] == 'y'){
                        if (context == AES67_SDP_FLAG_DEFLVL_SESSION){
                            sdp->mode = aes67_sdp_attr_mode_recvonly;
                        } else {
                            stream->mode = aes67_sdp_attr_mode_recvonly;
                        }
                    }
                    else if (llen == sizeof("a=sendrecv") - 1 &&
                             line[2] == 's' &&
                             line[3] == 'e' &&
                             line[4] == 'n' &&
                             line[5] == 'd' &&
                             line[6] == 'r' &&
                             line[7] == 'e' &&
                             line[8] == 'c' &&
                             line[9] == 'v'){
                        if (context == AES67_SDP_FLAG_DEFLVL_SESSION){
                            sdp->mode = aes67_sdp_attr_mode_sendrecv;
                        } else {
                            stream->mode = aes67_sdp_attr_mode_sendrecv;
                        }
                    }
                    else if (llen == sizeof("a=sendonly") - 1 &&
                             line[2] == 's' &&
                             line[3] == 'e' &&
                             line[4] == 'n' &&
                             line[5] == 'd' &&
                             line[6] == 'o' &&
                             line[7] == 'n' &&
                             line[8] == 'l' &&
                             line[9] == 'y'){
                        if (context == AES67_SDP_FLAG_DEFLVL_SESSION){
                            sdp->mode = aes67_sdp_attr_mode_sendonly;
                        } else {
                            stream->mode = aes67_sdp_attr_mode_sendonly;
                        }
                    }
                    else if (llen == sizeof("a=inactive") - 1 &&
                             line[2] == 'i' &&
                             line[3] == 'n' &&
                             line[4] == 'a' &&
                             line[5] == 'c' &&
                             line[6] == 't' &&
                             line[7] == 'i' &&
                             line[8] == 'v' &&
                             line[9] == 'e'){
                        if (context == AES67_SDP_FLAG_DEFLVL_SESSION){
                            sdp->mode = aes67_sdp_attr_mode_inactive;
                        } else {
                            stream->mode = aes67_sdp_attr_mode_inactive;
                        }
                    }
                    else if (delim - line == sizeof("a=ts-refclk")-1 && line[2] == 't' && line[3] == 's' && line[4] == '-' &&  line[5] == 'r' && line[6] == 'e' && line[7] == 'f' && line[8] == 'c' && line[9] == 'l' && line[10] == 'k'){

                        // basic sanity check
                        if (llen < sizeof("a=ts-refclk:ptp=IEEE1588-2002:01-02-03-04-05-06-07-08")-1 ||
                                delim[1] != 'p' ||
                                delim[2] != 't' ||
                                delim[3] != 'p' ||
                                delim[4] != '=' ||
                                delim[5] != 'I' ||
                                delim[6] != 'E' ||
                                delim[7] != 'E' ||
                                delim[8] != 'E'){

                            // seemingly the refclk is not ptp=IEEE based, so it might be another, unknown type
                            processed = false;
                        } else {

                            if (sdp->ptps.count >= AES67_SDP_MAXPTPS){
                                return AES67_SDP_NOMEMORY;
                            }

                            struct aes67_sdp_ptp * clk = &sdp->ptps.data[sdp->ptps.count++];

                            // init and don't forget to set flags
                            clk->flags =AES67_SDP_FLAG_SET_YES | context;
                            clk->ptp.type = aes67_ptp_type_undefined;
                            clk->ptp.domain = 0;

                            if ( context == AES67_SDP_FLAG_DEFLVL_SESSION ){
                                sdp->nptp++;
                            } else {
                                sdp->streams.data[ context & AES67_SDP_FLAG_STREAM_INDEX_MASK ].nptp++;
                            }

                            delim += 9;

                            // 1588-20XX:
                            if (delim[0] == '1' &&
                                delim[1] == '5' &&
                                delim[2] == '8' &&
                                delim[3] == '8' &&
                                delim[4] == '-' &&
                                delim[5] == '2' &&
                                delim[6] == '0' &&

                                delim[9] == ':'){

                                if (delim[7] == '0' && delim[8] == '2'){
                                    clk->ptp.type = aes67_ptp_type_IEEE1588_2002;
                                } else if (delim[7] == '0' && delim[8] == '8'){
                                    clk->ptp.type = aes67_ptp_type_IEEE1588_2008;
                                } else if (delim[7] == '1' && delim[8] == '9'){
                                    clk->ptp.type = aes67_ptp_type_IEEE1588_2019;
                                }

                            }
                            // 802.1AS-2011
                            else if (delim[0] == '8' &&
                                     delim[1] == '0' &&
                                     delim[2] == '2' &&
                                     delim[3] == '.' &&
                                     delim[4] == '1' &&
                                     delim[5] == 'A' &&
                                     delim[6] == 'S' &&
                                     delim[7] == '-' &&
                                     delim[8] == '2' &&
                                     delim[9] == '0' &&
                                     delim[10] == '1' &&
                                     delim[11] == '1' &&
                                     delim[12] == ':') {

                                clk->ptp.type = aes67_ptp_type_IEEE802AS_2011;
                            }

                            // only process further if type properly detected
                            if (clk->ptp.type != aes67_ptp_type_undefined){

                                // set pointer to beginning of EUI64
                                delim += (clk->ptp.type == aes67_ptp_type_IEEE802AS_2011) ? 13 : 10;

                                for(u16_t i = 0, h; i < 8; i++, delim += 3){
                                    h  = aes67_hextobyte(delim);

                                    // if invalid hexdata -> abort
                                    if (h == 0xffff){
                                        return AES67_SDP_ERROR;
                                    };

                                    clk->ptp.gmid.u8[i] = h;
                                }

                                // only PTPv2 & PTPv2.1 have a domain
                                switch(clk->ptp.type){
                                    case aes67_ptp_type_IEEE1588_2008:
                                    case aes67_ptp_type_IEEE1588_2019:
                                        if (delim  >= &line[llen]){
                                            return AES67_SDP_ERROR;
                                        }
                                        u16_t readlen = 0;
                                        s32_t t = aes67_atoi(delim, &line[llen] - delim, 10, &readlen);
                                        if (readlen == 0 || t > 127){
                                            return AES67_SDP_ERROR;
                                        }
                                        clk->ptp.domain = t;
                                        break;

                                    default:
                                        if (delim != &line[llen]){
                                            return AES67_SDP_ERROR;
                                        }
                                        break;
                                }
                            }

                        }
                    } // a=ts-refclk
                }

                if (processed == false){
                    //TODO what todo? generic callback?
                    // ex aes67_sdp_fromstr_unknown(context, line, llen)
                }
            }
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

#if 0 < AES67_SDP_MAXPTIMECAPS
    // in case of unsupported capabilities, reset capability options
    // because parsing will stop -> better no options than incomplete options
    if (unsupported_caps == true){
        for(u8_t i = 0; i < sdp->streams.count; i++){
            sdp->streams.data[i].ptime_cap.cfg = 0;
            sdp->streams.data[i].ptime_cap.count = 0;
        }
    }
#endif


    return (seen & SEEN_ALL) == SEEN_ALL ? AES67_SDP_OK : AES67_SDP_INCOMPLETE;
}

