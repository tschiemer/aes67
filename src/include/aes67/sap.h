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
#include "aes67/sdp.h"
#include "aes67/host/timer.h"
#include "aes67/host/time.h"


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
#define AES67_SAP_IPv6_LL       {0xff,0x02, 0,0, 0,0, 0,0, 0,0, 0,0, 0,2, 0x7f,0xfe}
#define AES67_SAP_IPv6_LL_STR   "FF02:0:0:0:0:0:2:7FFE"


// Bandwidth in bits per seconds (SHOULD value)
#ifndef AES67_SAP_BANDWITH
#define AES67_SAP_BANDWITH  4000
#endif

#define AES67_SAP_STATUS                    0
#define AES67_SAP_AUTH_LEN                  1
#define AES67_SAP_MSG_ID_HASH               2
#define AES67_SAP_ORIGIN_SRC                4

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

#if AES67_SAP_AUTH_ENABLED == 1

enum aes67_sap_auth_result {
    aes67_sap_auth_result_ok = 0,
    aes67_sap_auth_result_not_ok = ~aes67_sap_auth_result_ok
};

#endif //AES67_SAP_AUTH_ENABLED

enum aes67_sap_event {
    aes67_sap_event_new,
    aes67_sap_event_refreshed,
    aes67_sap_event_deleted,
    aes67_sap_event_timeout
};


struct aes67_sap_session {
    u16_t hash;
    struct aes67_net_addr src;
    aes67_timestamp_t last_announcement;

#if AES67_SAP_AUTH_ENABLED == 1
    // these are not quite thought through yet, but show an the idea
    enum aes67_sap_auth_result authenticated;
#endif

    void * data;
};

struct aes67_sap_session_table {
    u16_t active; // no_of_ads (used for interval computation)
    u16_t size;
    struct aes67_sap_session * table;
};


typedef void (*aes67_sap_event_callback)(enum aes67_sap_event event, struct aes67_sap_session * session, u8_t * payloadtype, u16_t payloadtypelen, u8_t * payload, u16_t payloadlen);


struct aes67_sap_service {

    struct aes67_sap_session_table session_table;

    u16_t announcement_size; // ad_size (used for interval computation)
    struct aes67_timer announcement_timer;

    u32_t timeout_interval;
    struct aes67_timer timeout_timer;

    aes67_sap_event_callback event_callback;
};


/**
 * Initializes service data
 */
void aes67_sap_service_init(
        struct aes67_sap_service * sap,
        u16_t session_table_size,
        struct aes67_sap_session * session_table,
        aes67_sap_event_callback event_callback
);

/**
 * Deinitalizes service data
 */
void aes67_sap_service_deinit(struct aes67_sap_service * sap);



/**
 * Sets and enables announcement timer to trigger when next announcement can/should be sent.
 *
 * TODO static?
 */
void aes67_sap_service_set_announcement_timer(struct aes67_sap_service * sap);

/**
 * Query service wether an announcement can or should be done now.
 *
 * Assumes the announcement timer was triggered.
 * (Comfort) function does not have to be used, but rather can if timer handler does not already handle everything.
 */
inline uint8_t aes67_sap_service_announce_now(struct aes67_sap_service * sap)
{
    return sap->announcement_timer.state == aes67_timer_state_expired;
}

/**
 * TODO static?
 */
void aes67_sap_service_set_timeout_timer(struct aes67_sap_service * sap);

/**
 * Query wether at least one registered session has (or should have) timed out.
 *
 * (Comfort) function does not have to be used, but rather can if timer handler does not already handle everything.
 */
inline uint8_t aes67_sap_service_timeout_now(struct aes67_sap_service * sap)
{
    return sap->timeout_timer.state == aes67_timer_state_expired;
}

void aes67_sap_service_timeout_clear(struct aes67_sap_service * sap);

/**
 * Handles incoming SAP message and triggers event callback accordingly.
 */
void aes67_sap_service_handle(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen);

/**
 *
 */
u16_t aes67_sap_service_msg(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, struct aes67_net_addr * ip, struct aes67_sdp * sdp);


#if AES67_SAP_AUTH_ENABLED == 1

/**
 * (Optionally) validates messages
 *
 * Note: ALL messages are passed to this function, thus the validator may choose to allow for authenticated and/or
 * non-authenticated messages.
 *
 * SECURITY NOTICE (if authenticated AND non-authenticated messages are accepted)
 * Attackers could flood the device with enough SAP announcements as to fill up the (limited) session memory BEFORE any
 * actually authenticated messages are received, thus the session would not be remembered as to having been authenticated.
 * Following up, attackers might change set up and authenticated sessions by simply leaving out authentication data.
 */
extern enum aes67_sap_auth_result aes67_sap_service_auth_validate(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen);

#endif //AES67_SAP_AUTH_ENABLED == 1


#if AES67_SAP_AUTH_SELF == 1

/**
 * (optionally) Adds authentication data to message and return total msg length
 *
 * NOTE function is responsible for
 * - respecting maximum msg length
 * - inserting the authentication data between the header and the payload (ie, moving the payload accordingly)
 * - setting the <auth_len> header field correctly (from which the total msglen will be deduced)
 *
 * Return value: 0 on success, error otherwise
 */
extern u8_t aes67_sap_service_auth_add(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen, u16_t maxlen);

#endif //AES67_SAP_AUTH_SELF == 1


#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

/**
 * Decompress payload.
 *
 * NOTE in case function uses dynamic memory allocation, make sure to also implement aes67_sap_zlib_decompress_free()
 *
 * Return value:
 *  - pointer to decompressed payload -> set payloadlen to decompressed payload length
 *  - NULL on error -> set payloadlen to 0
 */
extern u8_t * aes67_sap_zlib_decompress(struct aes67_sap_service * sap, u8_t * payload, u16_t * payloadlen);

extern void aes67_sap_zlib_decompress_free(u8_t * payload);

#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 1


#if AES67_SAP_COMPRESS_ENABLED == 1

/**
 * (optionally) Compresses payload data with given length.
 *
 * NOTE function is responsible for writing the compressed data to the exact same location and returning the final
 * payload length. It may make use of the maxlen - payloadlen bytes available, use stack memory, or whatever.
 *
 * NOTE when enabling compression there is no guarantee that all recipients can actually decompress packets (well, the
 * standard considers compression a feature, but you know, skipping the implementation might be meaningful and if no
 * implementation actually uses compression there's no loss - but you never know!
 *
 * Return value: 0 on error, (new) length of payload on success
 */
extern u16_t aes67_sap_zlib_compress(struct aes67_sap_service * sap, u8_t * payload, u16_t payloadlen, u16_t maxlen);

#endif //AES67_SAP_COMPRESS_ENABLED == 1



#ifdef __cplusplus
}
#endif


#endif //AES67_SAP_H
