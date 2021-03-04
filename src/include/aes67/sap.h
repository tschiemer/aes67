/**
 * @file sap.h
 * Utilities for Session Announcement Protocol (SAP) handling.
 *
 * References:
 * Session Announcement Protocol: Version 2 https://tools.ietf.org/html/rfc2974
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
#include "aes67/opt.h"
#include "aes67/net.h"
#include "aes67/sdp.h"
#include "aes67/host/timer.h"
#include "aes67/host/time.h"


// sanity checks
#if AES67_SAP_MEMORY != AES67_MEMORY_POOL && AES67_SAP_MEMORY != AES67_MEMORY_DYNAMIC
#error Please specify valid memory strategy for SAP (AES67_SAP_MEMORY)
#endif
#if AES67_SAP_MEMORY_MAX_SESSIONS > UINT16_MAX
#error AES67_SAP_MEMORY_MAX_SESSIONS too big!
#endif


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

#define AES67_SAP_STATUS_VERSION_0          0b00000000
#define AES67_SAP_STATUS_VERSION_1          0b00100000
#define AES67_SAP_STATUS_VERSION_2          AES67_SAP_STATUS_VERSION_1

#define AES67_SAP_STATUS_ADDRTYPE_IPv4      0b00000000
#define AES67_SAP_STATUS_ADDRTYPE_IPv6      0b00010000

#define AES67_SAP_STATUS_MSGTYPE_ANNOUNCE   0b00000000
#define AES67_SAP_STATUS_MSGTYPE_DELETE     0b00000100

#define AES67_SAP_STATUS_ENCRYPTED_YES      0b00000010
#define AES67_SAP_STATUS_ENCRYPTED_NO       0b00000000

#define AES67_SAP_STATUS_COMPRESSED_ZLIB    0b00000001
#define AES67_SAP_STATUS_COMPRESSED_NONE    0b00000000

#define AES67_SAP_AUTH_VERSION_MASK         0b11100000
#define AES67_SAP_AUTH_PADDING_MASK         0b00010000
#define AES67_SAP_AUTH_TYPE_MASK            0b00001111

#define AES67_SAP_AUTH_TYPE_PGP             0b00000000
#define AES67_SAP_AUTH_TYPE_CMS             0b00000001

#define AES67_SAP_AUTH_TYPE_IS_VALID( __type__ ) ( \
    (__type__) == AES67_SAP_AUTH_TYPE_PGP |    \
    (__type__) == AES67_SAP_AUTH_TYPE_CMS \
)


#if AES67_SAP_AUTH_ENABLED == 1

enum aes67_sap_auth_result {
    aes67_sap_auth_result_ok = 0,
    aes67_sap_auth_result_not_ok = ~aes67_sap_auth_result_ok
};

#endif //AES67_SAP_AUTH_ENABLED

/**
 * Event trigger by message handler
 * @see aes67_sap_service_event(..)
 */
enum aes67_sap_event {
    aes67_sap_event_undefined = 0,
    aes67_sap_event_new,
    aes67_sap_event_updated,
    aes67_sap_event_deleted,
    aes67_sap_event_timeout,
    aes67_sap_event_announcement_request
};

#define AES67_SAP_EVENT_IS_VALID(__e__) ( \
    (__e__) == aes67_sap_event_new || \
    (__e__) == aes67_sap_event_updated || \
    (__e__) == aes67_sap_event_deleted || \
    (__e__) == aes67_sap_event_timeout  || \
    (__e__) == aes67_sap_event_announcement_request \
)

// internal status bits
#define AES67_SAP_SESSION_STAT_CLEAR        0

#define AES67_SAP_SESSION_STAT_SET          0x1000
#define AES67_SAP_SESSION_STAT_SRC_IS_SELF  0x2000

#define AES67_SAP_SESSION_STAT_XOR8_HASH    0x00ff

/**
 * Structure of internal session data
 */
struct aes67_sap_session {
    u16_t stat; // for internal use

    u16_t hash;
    struct aes67_net_addr src;
    aes67_time_t last_announcement;

#if AES67_SAP_AUTH_ENABLED == 1
    // these are not quite thought through yet, but show an the idea
    enum aes67_sap_auth_result authenticated;
#endif

#if AES67_SAP_FILTER_XOR8 == 1

#endif

#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    struct aes67_sap_session * next;
#endif

//    void * data; // optional user data
};


/**
 * Basic SAP service struct
 */
struct aes67_sap_service {

    /**
     * ad_size (used for interval computation)
     */
    u16_t announcement_size;

    u32_t announcement_sec;

    /**
     * Timer functionality for approximating the next time to announce own packets
     * (optionally used)
     */
    struct aes67_timer announcement_timer;

    /**
     * Last computed timeout interval
     */
    u32_t timeout_sec;

    /**
     * Timer functionality for approximating the next time a session times out
     */
    struct aes67_timer timeout_timer;

    /**
     * Counter of active packets
     * used for interval computation but also interesting otherwise
     */
    u16_t no_of_ads; //

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && 0 < AES67_SAP_MEMORY_MAX_SESSIONS
    struct aes67_sap_session sessions[AES67_SAP_MEMORY_MAX_SESSIONS];
#elif AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    struct aes67_sap_session * first_session; // first session of linked list
#endif
};

/**
 * Initializes service data
 *
 * @param sap
 */
void aes67_sap_service_init(struct aes67_sap_service *sap);

/**
 * Deinitalizes service data
 *
 * @param sap
 */
void aes67_sap_service_deinit(struct aes67_sap_service * sap);


/**
 * See wether given session has ben registered prior and return related pointer.
 */
#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
struct aes67_sap_session * aes67_sap_service_find(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip);
#else
#define aes67_sap_service_find(sap, hash, ipver, ip) NULL
#endif

/**
 * Computes announcement and timeout time (in sec)
 *
 * @param no_of_ads
 * @param announcement_size
 * @param announce_sec          (nullable)
 * @param timeout_sec           (nullable)
 * @return
 */
void aes67_sap_compute_times_sec(s32_t no_of_ads, s32_t announcement_size, u32_t *announce_sec, u32_t *timeout_sec);


/**
 * Get announcement timer state
 *
 * (Comfort) function does not have to be used, but rather can if timer handler does not already handle everything.
 *
 * @param sap
 * @return true iff announcement may/should occur now
 */
inline enum aes67_timer_state aes67_sap_service_announcement_timer_state(struct aes67_sap_service * sap)
{
    return aes67_timer_getstate(&sap->announcement_timer);
}


#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
/**
 * Sets and enables announcement timer to trigger when next announcement can/should be sent.
 *
 * @param sap
 */
void aes67_sap_service_set_announcement_timer(struct aes67_sap_service * sap);


/**
 * Get timeout timer state
 *
 * (Comfort) function does not have to be used, but rather can if timer handler does not already handle everything.
 *
 * @param sap
 * @return true iff the timeout timer expired
 */
inline enum aes67_timer_state aes67_sap_service_timeout_timer_state(struct aes67_sap_service * sap)
{
    return aes67_timer_getstate(&sap->timeout_timer);
}

void aes67_sap_service_announcement_check(struct aes67_sap_service *sap, void *user_data);

/**
 * Sets timeout timer to when first/next session will timeout.
 *
 * Relies on aes67_sap_service_get_timeout_sec().
 * Note: Does NOT set timeout timer if there are not ads registered
 * Suggestion: could be called after a new/refreshed event
 *
 * @param sap
 */
void aes67_sap_service_set_timeout_timer(struct aes67_sap_service * sap);

/**
 * Deletes timed out sessions
 *
 * Calls aes67_sap_service_event(..) with the timeout event.
 *
 * @param sap
 */
void aes67_sap_service_timeouts_cleanup(struct aes67_sap_service *sap, void *user_data);


void aes67_sap_service_process(struct aes67_sap_service *sap, void * user_data);
#endif // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS


/**
 * Handles incoming SAP message and triggers event callback accordingly.
 *
 * @param sap
 * @param msg
 * @param msglen
 */
void aes67_sap_service_handle(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, void *user_data);

/**
 * Generates an SAP packet according to arguments.
 * To be sent by external methods.
 *
 * @param sap
 * @param msg       buffer to write to
 * @param maxlen    maxlen of buffer msg
 * @param opt       SAP status byte options. only accepts:
 *                      AES67_SAP_STATUS_MSGTYPE_ANNOUNCE
 *                      AES67_SAP_STATUS_MSGTYPE_DELETE
 *                      AES67_SAP_STATUS_COMPRESSED_ZLIB (iff compression available)
 *                      AES67_SAP_STATUS_COMPRESSED_NONE
 * @param hash      session identifier (SHOULD be unique in combination with originating source/ip)
 * @param ipver
 * @param ip        ipv4/6 raw data
 * @param payload       payload (including payload type)
 * @param payloadlen
 * @return
 */
u16_t aes67_sap_service_msg(struct aes67_sap_service *sap, u8_t *msg, u16_t maxlen, u8_t opt, u16_t hash,
                            enum aes67_net_ipver ipver, u8_t *ip, u8_t *payload, u16_t payloadlen, void *user_data);

/**
 * Generates an SAP packet according to arguments.
 * To be sent by external methods.
 * (Convenience version for use of internal SDP packet descriptions only)
 *
 * @param sap
 * @param msg       buffer to write to
 * @param maxlen    maxlen of buffer msg
 * @param opt       SAP status byte options. only accepts:
 *                      AES67_SAP_STATUS_MSGTYPE_ANNOUNCE
 *                      AES67_SAP_STATUS_MSGTYPE_DELETE
 *                      AES67_SAP_STATUS_COMPRESSED_ZLIB (iff compression available)
 *                      AES67_SAP_STATUS_COMPRESSED_NONE
 * @param hash      session identifier (SHOULD be unique in combination with originating source/ip)
 * @param ip        ipv4/ipv6 to use as originating source
 * @param sdp       SDP data to add to packet
 */
u16_t aes67_sap_service_msg_sdp(struct aes67_sap_service *sap, u8_t *msg, u16_t maxlen, u8_t opt, u16_t hash,
                                struct aes67_net_addr *ip, struct aes67_sdp *sdp, void *user_data);


/**
 *
 * @param event
 * @param hash
 * @param payloadtype       Payload type string if given. Will ALWAYS be NULL iff the payload type is "application/sdp"
 * @param payloadtypelen    Length of payload type string if given. Will ALWAYS be 0 iff the payload type is "application/sdp".
 * @param payload
 * @param payloadlen
 * @param user_data         As set in aes67_sap_service_init(..)
 */
extern void
aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                        enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype, u16_t payloadtypelen,
                        u8_t *payload, u16_t payloadlen, void *user_data);



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
 *
 * @param sap
 * @param msg
 * @param msglen
 * @param user_data         As set in aes67_sap_service_init(..)
 * @return                  Wether the message contains valid authentication data (or does not contain validation data)
 */
extern enum aes67_sap_auth_result aes67_sap_service_auth_validate(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, void *user_data);

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
 * @param msg
 * @param msglen
 * @param maxlen        The maximum msg length to be respected (ie msglen + length of auth data may not exceed this limit)
 * @param user_data     As set in aes67_sap_service_init(..)
 * @return  0 on success, error otherwise
 */
extern u8_t aes67_sap_service_auth_add(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, u16_t maxlen, void *user_data);

#endif //AES67_SAP_AUTH_SELF == 1


#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

/**
 * Decompress payload.
 *
 * NOTE in case function uses dynamic memory allocation, make sure to also implement aes67_sap_zlib_decompress_free()
 *
 * @param payload       start of the data to decompress
 * @param payloadlen    length of the data to decompress (must be set by the function to reflect the decrompressed length)
 * @param user_data     As set in aes67_sap_service_init(..)
 * @return
 *  - pointer to decompressed payload -> set payloadlen to decompressed payload length
 *  - NULL on error -> set payloadlen to 0
 */
extern u8_t * aes67_sap_zlib_decompress(u8_t * payload, u16_t * payloadlen, void * user_data);

#ifndef aes67_sap_zlib_decompress_free
extern void aes67_sap_zlib_decompress_free(u8_t * payload);
#endif

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
 * @param payload       start of the data to compress
 * @param payloadlen    current length of the data to compress
 * @param maxlen        maximum length of available space for free use from start of data
 * @param user_data     As set in aes67_sap_service_init(..)
 * @return  0 on error, (new) length of payload on success
 */
extern u16_t aes67_sap_zlib_compress(u8_t * payload, u16_t payloadlen, u16_t maxlen, void * user_data);

#endif //AES67_SAP_COMPRESS_ENABLED == 1


#ifdef __cplusplus
}
#endif


#endif //AES67_SAP_H
