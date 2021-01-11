/**
 * @file sdp.h
 * Minimal (partial) Session Description Protocol (SDP) implementation as
 * required for AES67.
 *
 * References:
 * Session Description Protocol (SDP) https://tools.ietf.org/html/rfc4566
 * RTP Clock Source Signalling https://tools.ietf.org/html/rfc7273
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

#ifndef AES67_SDP_H
#define AES67_SDP_H

#include "aes67/arch.h"
#include "aes67/net.h"

#define AES67_PTP_TYPE_IEEE1588_2002    "IEEE1588-2002"
#define AES67_PTP_TYPE_IEEE1588_2008    "IEEE1588-2008"
#define AES67_PTP_TYPE_IEEE1588_2019    "IEEE1588-2019"
#define AES67_PTP_TYPE_IEEE802AS_2011   "IEEE802.1AS-2011"

/**
 * PTP clock type
 */
enum aes67_ptp_type {
    aes67_ptp_type_IEEE1588_2002 = 1,
    aes67_ptp_type_IEEE1588_2008 = 2,
    aes67_ptp_type_IEEE1588_2019 = 3,
    aes67_ptp_type_IEEE802AS_2011 = 4,
};

/**
 * EUI64 as used for PTP clock identifiers
 */
union aes67_eui64 {
    u8_t u8[8];
    u32_t u32[2];
//    u64_t u64;
};

/**
 * PTP clock datastruct
 */
struct aes67_ptp {
    enum aes67_ptp_type type;
    union aes67_eu64 gmid;
    u8_t domain;
};

/**
 *
 */
struct aes67_sdp_connection_data {
    struct aes67_net_addr addr;
    u8_t ttl;
    u8_t layers;
};


/**
 * A session description struct.
 *
 * Serves as container for programmatic handling of SDP strings.
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
        AES67_STRING(AES67_SDP_MAXADDRESS) address;
    } originator;
#if 0 < AES67_SDP_MAXSESSIONNAME
    AES67_STRING(AES67_SDP_MAXSESSIONNAME) session_name;
#endif

#if 0 < AES67_SDP_MAXSESSIONINFO
    AES67_STRING(AES67_SDP_MAXSESSIONINFO) session_info;
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

/**
 * Generate SDP string from struct.
 */
u32_t aes67_sdp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp * sdp);

/**
 * Parse SDP string into struct.
 */
u32_t aes67_sdp_fromstr(struct aes67_sdp * sdp, u8_t * str, u32_t len);

/**
 * Compares two SDP structs w.r.t. originator (not considering the (ever increasing) session version)
 *
 * If the originator is identical       -> 0
 * If the originator is NOT identical   -> 1
 *
 * Note: the unicast address is compared bytewise, ie if one is given as IP and the other as hostname it will
 * not be considered equal even if it may indeed be the same device.
 *
 * Also see aes67_sdp_cmpversion
 */
u8_t aes67_sdp_cmporigin(struct aes67_sdp * lhs, struct aes67_sdp * rhs);

/**
 * Compares two SDP structs denoting the same originator w.r.t. the version.
 *
 * If the version is less       -> -1
 * If the version is identical  -> 0
 * If the version is later      -> 1
 *
 * Note: only compares version. Requires prior originator match (see aes67_sdp_cmporigin)
 */
s32_t aes67_sdp_cmpversion(struct aes67_sdp * lhs, struct aes67_sdp * rhs);

#endif //AES67_SDP_H
