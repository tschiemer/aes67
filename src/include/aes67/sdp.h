/**
 * @file sdp.h
 * Minimal (partial) Session Description Protocol (SDP) implementation as
 * required for AES67.
 *
 * Also see avp.h
 *
 * References:
 * Session Description Protocol (SDP) https://tools.ietf.org/html/rfc4566
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc3551
 * RTP Clock Source Signalling https://tools.ietf.org/html/rfc7273
 * Session Description Protocol (SDP) Capability Negotiation https://tools.ietf.org/html/rfc5939
 * An Offer/Answer Model with the Session Description Protocol (SDP) https://tools.ietf.org/html/rfc3264
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
#include "aes67/ptp.h"


#ifdef __cplusplus
extern "C" {
#endif

#define AES67_SDP_MIMETYPE "application/sdp"

#define AES67_SDP_FLAG_SET_MASK         0b1000000000000000
#define AES67_SDP_FLAG_DEFLVL_MASK      0b0100000000000000
#define AES67_SDP_FLAG_STATE_MASK       0b0011000000000000
#define AES67_SDP_FLAG_MCAST_MASK       0b0000100000000000
#define AES67_SDP_FLAG_INDEX_MASK       0b0000000011111111

#define AES67_SDP_FLAG_SET_YES          0b1000000000000000
#define AES67_SDP_FLAG_SET_NO           0b0000000000000000

#define AES67_SDP_FLAG_DEFLVL_SESSION   0b1000000000000000
#define AES67_SDP_FLAG_DEFLVL_MEDIA     0b0000000000000000

#define AES67_SDP_FLAG_STATE_INACTIVE   0b0000000000000000
#define AES67_SDP_FLAG_STATE_RECVONLY   0b0001000000000000
#define AES67_SDP_FLAG_STATE_SENDONLY   0b0010000000000000
#define AES67_SDP_FLAG_STATE_SENDRECV   0b0011000000000000

#define AES67_SDP_FLAG_MCAST_YES        0b0000000000000000
#define AES67_SDP_FLAG_MCAST_NO         0b0000100000000000

#define AES67_SDP_PTP_DOMAIN_UNDEF  255

typedef u16_t aes67_sdp_flags;

struct aes67_sdp_originator {
#if 0 < AES67_SDP_MAXUSERNAME
    AES67_STRING(AES67_SDP_MAXUSERNAME) username;
#endif
    AES67_STRING(AES67_SDP_MAXSESSIONID) session_id;
    AES67_STRING(AES67_SDP_MAXSESSIONVERSION) session_version;
//    u8_t nettype; // only IN type used
    enum aes67_net_ipver address_type;
    AES67_STRING(AES67_SDP_MAXADDRESS) address;
};

/**
 *
 */
struct aes67_sdp_connection_data {
    aes67_sdp_flags flags;
    u8_t ttl;
    u8_t naddr;
    enum aes67_net_ipver address_type;
    AES67_STRING(AES67_SDP_MAXADDRESS) address;
};

struct aes67_sdp_connection_data_list {
    u8_t count;
    struct aes67_sdp_connection_data data[AES67_SDP_MAXCONNECTIONS];
};

struct aes67_sdp_ptp_data {
    aes67_sdp_flags flags;
    struct aes67_ptp ptp;
};

struct aes67_sdp_ptp_data_list {
    u8_t count;
    struct aes67_sdp_ptp_data data[AES67_SDP_MAXPTPS];
};

struct aes67_sdp_attr_ptime {
    u16_t msec;
    u16_t msec_frac;
} PACK_STRUCT;

struct aes67_sdp_attr_enc {
    aes67_sdp_flags flags;
    u8_t payloadtype;
    u8_t nchannels;
    u32_t samplerate;
};

struct aes67_sdp_attr_enc_list {
    u8_t count;
    struct aes67_sdp_attr_enc data[AES67_SDP_MAXENCODINGS];
};

struct aes67_sdp_media_data {
    u16_t port;
    u8_t nports;
    u8_t nencodings;
    u32_t mediaclock_offset; // TODO
    struct {
        u8_t count;
        struct aes67_sdp_attr_ptime data[AES67_SDP_MAXPTIME];
    } ptime;
    struct aes67_sdp_attr_ptime maxptime;
};

struct aes67_sdp_media_data_list {
    u8_t count;
    struct aes67_sdp_media_data data[AES67_SDP_MAXMEDIA];
};

/**
 * A session description struct.
 *
 * Serves as container for programmatic handling of SDP strings.
 */
struct aes67_sdp {

    struct aes67_sdp_originator originator;

#if 0 < AES67_SDP_MAXSESSIONNAME
    AES67_STRING(AES67_SDP_MAXSESSIONNAME) session_name;
#endif

#if 0 < AES67_SDP_MAXSESSIONINFO
    AES67_STRING(AES67_SDP_MAXSESSIONINFO) session_info;
#endif

    u8_t ptp_domain; // session level ptp domain attribute (RAVENNA)

    struct aes67_sdp_connection_data_list connections;

    // for the moment being, just forget about bandwidth ("b=.."), timing ("t=", assume "t=0 0"),
    // repeat times ("r="), time zones ("z="), encryption keys ("k=")

    struct aes67_sdp_ptp_data_list ptps;

    struct aes67_sdp_media_data_list media;

    struct aes67_sdp_attr_enc_list encodings;
};

void aes67_sdp_origin_init(struct aes67_sdp_originator * origin);
void aes67_sdp_init(struct aes67_sdp * sdp);

/**
 * Writes originator line to given memory.
 *
 * NOTE does not add CRNL
 */
u32_t aes67_sdp_origin_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_originator * origin);


u32_t aes67_sdp_origin_fromstr(struct aes67_sdp_originator * origin, u8_t * str, u32_t len);


/**
 * Compares two SDP structs w.r.t. originator (not considering the (ever increasing) session version)
 *
 * If the originator is identical       -> 0
 * If the originator is NOT identical   -> 1
 *
 * Note: the unicast address is compared bytewise, ie if one is given as IP and the other as hostname it will
 * not be considered equal even if it may indeed be the same device.
 *
 * Also see aes67_sdp_origin_cmpversion
 */
u8_t aes67_sdp_origin_cmp(struct aes67_sdp_originator *lhs, struct aes67_sdp_originator *rhs);

/**
 * Compares two SDP structs denoting the same originator w.r.t. the version.
 *
 * If the version is less       -> -1
 * If the version is identical  -> 0
 * If the version is later      -> 1
 *
 * Note: only compares version. Requires prior originator match (see aes67_sdp_origin_cmp)
 */
s32_t aes67_sdp_origin_cmpversion(struct aes67_sdp_originator *lhs, struct aes67_sdp_originator *rhs);


/**
 * Generate SDP string from struct.
 */
u32_t aes67_sdp_tostr(u8_t *str, u32_t maxlen, struct aes67_sdp *sdp);



/**
 * Parse SDP string into struct.
 */
u32_t aes67_sdp_fromstr(struct aes67_sdp *sdp, u8_t *str, u32_t len);


#ifdef __cplusplus
}
#endif


#endif //AES67_SDP_H
