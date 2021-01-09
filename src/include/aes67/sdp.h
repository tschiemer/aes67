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

#ifndef AES67_SDP_H
#define AES67_SDP_H

#include "aes67/arch.h"
#include "aes67/net.h"

#define AES67_PTP_TYPE_IEEE1588_2002    "IEEE1588-2002"
#define AES67_PTP_TYPE_IEEE1588_2008    "IEEE1588-2008"
#define AES67_PTP_TYPE_IEEE1588_2019    "IEEE1588-2019"
#define AES67_PTP_TYPE_IEEE802AS_2011   "IEEE802.1AS-2011"

enum aes67_ptp_type {
    aes67_ptp_IEEE1588_2002 = 1,
    aes67_ptp_IEEE1588_2008 = 2,
    aes67_ptp_IEEE1588_2019 = 3,
    aes67_ptp_IEEE802AS_2011 = 4,
};

union aes67_eu64 {
    u8_t u8[8];
    u32_t u32[2];
//    u64_t u64;
};

struct aes67_ptp {
    enum aes67_ptp_type type;
    union aes67_eu64 gmid;
    u8_t domain;
};

struct aes67_sdp_connection_data {
    struct aes67_net_addr addr;
    u8_t ttl;
    u8_t layers;
};


/**
 * Note: RFC 4566 suggests using NTP format timestamps for originator session id and version to guarantee uniqueness.
 * But NTPv3 timestamps are 64bit  * integers (NTPv4 timestamps are even 128bit integers).
 * This is not very friendly for 32bit architectures. So let's use strings.
 */
struct aes67_sdp {
    // leave out version
    // always assume v=0
    struct {
#if 0 < AES67_SDP_MAXUSERNAME
        AES67_STRING(AES67_SDP_MAXUSERNAME) username;
#endif
        AES67_STRING(AES67_SDP_MAXSESSIONID) session_id;
        AES67_STRING(AES67_SDP_MAXSESSIONVERSION) session_version;
        struct aes67_net_addr addr;
    } originator;
#if 0 < AES67_SDP_MAXSESSIONNAME
    AES67_STRING(AES67_SDP_MAXSESSIONNAME) session_name;
#endif

#if 0 < AES67_SDP_MASSESSIONINFO
    AES67_STRING(AES67_SDP_MASSESSIONINFO) session_info;
#endif

    // TODO are several connections required or is just one enough?
    struct {
        u8_t count;
        struct aes67_sdp_connection_data data[AES67_SDP_MAXCONNECTIONDATA];
    } connections;


    // for the moment being, just forget about bandwidth ("b=.."), timing ("t=", assume "t=0 0"),
    // repeat times ("r="), time zones ("z="), encryption keys ("k=")

    struct aes67_ptp ptp;

};

//u16_t aes67_sdp_ntp2str(u8_t * str, u16_t maxlen, u64_t * timestamp);

u32_t aes67_sdp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp * sdp);
u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len);

#endif //AES67_SDP_H
