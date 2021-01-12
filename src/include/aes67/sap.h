/**
 * @file sap.h
 * Utilities for Session Announcement Protocol (SAP) handling.
 *
 * References:
 * Session Announcement Protocol https://tools.ietf.org/html/rfc2974
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

#ifndef AES67_SAP_H
#define AES67_SAP_H

#include "aes67/arch.h"
#include "aes67/net.h"


#ifdef __cplusplus
extern "C" {
#endif


// IP TTL value that SHOULD be used
#define AES67_SAP_TTL   255

// IP/UDP port that MUST be used
#define AES67_SAP_PORT  9875

#define AES67_SAP_IPv4       {224,2,127,254}
#define AES67_SAP_IPv4_STR   "224.2.127.254"

/**
 * IPv6 sessions are announced on the address FF0X:0:0:0:0:0:2:7FFE where X
 * is the 4-bit scope value.
 * ff02 := link local (identical to mdns multicast scope)
 */
#define AES67_SAP_IPv6_LL       {0xff02, 0, 0, 0, 0, 0, 2, 0x7ffe}
#define AES67_SAP_IPv6_LL_STR   "FF02:0:0:0:0:0:2:7FFE"


// Bandwidth in bits per seconds (SHOULD value)
#ifndef AES67_SAP_BANDWITH
#define AES67_SAP_BANDWITH  4000
#endif


#define AES67_SAP_STATUS_VERSION_MASK       0b11100000
#define AES67_SAP_STATUS_ADDRTYPE_MASK      0b00010000
#define AES67_SAP_STATUS_RESERVED_MASK      0b00001000
#define AES67_SAP_STATUS_MSGTYPE_MASK       0b00000100
#define AES67_SAP_STATUS_ENCRYPTED_MASK     0b00000010
#define AES67_SAP_STATUS_COMPRESSED_MASK    0b00000001

#define AES67_SAP_STATUS_VERSION_1          0b00000000
#define AES67_SAP_STATUS_VERSION_2          0b00100000

#define AES67_SAP_STATUS_ADDRTYPE_IPv4      0b00000000
#define AES67_SAP_STATUS_ADDRTYPE_IPv6      0b00010000

#define AES67_SAP_STATUS_MSGTYPE_ANNOUNCE   0b00000100
#define AES67_SAP_STATUS_MSGTYPE_DELETE     0b00000000

#define AES67_SAP_STATUS_ENCRYPTED_YES      0b00000010
#define AES67_SAP_STATUS_ENCRYPTED_NO       0b00000010

#define AES67_SAP_STATUS_COMPRESSED_ZLIB    0b00000001
#define AES67_SAP_STATUS_COMPRESSED_NONE    0b00000000

//#define AES67_SAP_PACKET_STATUS         0
//struct aes67_sap_packet {
//    u8_t status;
//    u8_t auth_len;
//    u16_t msg_id_hash;
//    u8_t ip[16];
//
//} PACK_STRUCT;

#define AES67_SAP_AUTH_VERSION_MASK         0b11100000
#define AES67_SAP_AUTH_PADDING_MASK         0b00010000
#define AES67_SAP_AUTH_TYPE_MASK            0b00001111

#define AES67_SAP_AUTH_TYPE_PGP             0b00000000
#define AES67_SAP_AUTH_TYPE_CMS             0b00000001

#define AES67_SAP_AUTH_TYPE_IS_VALID( __type__ ) ( \
    (__type__) == AES67_SAP_AUTH_TYPE_PGP |    \
    (__type__) == AES67_SAP_AUTH_TYPE_CMS \
)

//struct aes67_sap_auth_hdr {
//    u8_t hdr;
//    u8_t subhdr[];
//};

enum aes67_sap_event {
    aes67_sap_event_new,
    aes67_sap_event_refreshed,
    aes67_sap_event_deleted
};

typedef void (*aes67_sap_event_callback)(enum aes67_sap_event event, u16_t hash, u8_t * payloadtype, u16_t payloadtypelen, u8_t * payload, u16_t payloadlen);

// TODO
typedef u16_t (*aes67_sap_zlib_compress_callback)(u8_t ** dst, u8_t * src, u16_t len);
typedef u16_t (*aes67_sap_zlib_uncompress_callback)(u8_t ** dst, u8_t * src, u16_t len);

enum aes67_auth_result {
    aes67_auth_ok = 0,
    aes67_auth_not_ok = ~aes67_auth_ok
};

// TODO proper authenticator (if needed)
typedef enum aes67_auth_result (*aes67_sap_auth_validate_callback)(void);
typedef u16_t (*aes67_sap_auth_enticate_callback)(void);


struct aes67_sap_service {
    u16_t hash_table_sz;
    u16_t * hash_table;

    aes67_sap_event_callback event_callback;

    aes67_sap_zlib_compress_callback compress_callback;
    aes67_sap_zlib_uncompress_callback uncompress_callback;

    aes67_sap_auth_validate_callback auth_validate_callback;
    aes67_sap_auth_enticate_callback auth_enticate_callback;
};


void aes67_sap_service_init(
        struct aes67_sap_service * sap,

        u16_t hash_table_sz,
        u16_t * hash_table,

        aes67_sap_event_callback event_callback
);


void aes67_sap_service_parse(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen);

// TODO how to add authentication info? -> callback?
// TODO how to compress? -> callback?
u16_t aes67_sap_service_msg(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, struct aes67_net_addr * ip, struct aes67_sdp * sdp);

#ifdef __cplusplus
}
#endif


#endif //AES67_SAP_H
