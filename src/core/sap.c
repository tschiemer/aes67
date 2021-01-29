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

#include "aes67/sap.h"

#include "aes67/sdp.h"
#include "aes67/debug.h"


#define EMPTY_HASH 0



/**
 * See wether given session has ben registered prior and return related pointer.
 */
static struct aes67_sap_session * aes67_sap_service_find(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip);

/**
 * Add a specific session to the session table.
 *
 * To be used directly (most likely) only when registering sessions sent from this device (to let them count towards
 * the total announcement count).
 */
static struct aes67_sap_session *  aes67_sap_service_register(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip);

/**
 * To remove a specific session from the session table.
 */
static void aes67_sap_service_unregister(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip);




void aes67_sap_service_init(struct aes67_sap_service * sap, void * user_data)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    sap->user_data = user_data;

    sap->announcement_size = 0;
    sap->timeout_interval = 0;

    // init timers
    aes67_timer_init(&sap->announcement_timer);
    aes67_timer_init(&sap->timeout_timer);

    sap->no_of_ads = 0;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    aes67_memset(sap->sessions, 0, sizeof(sap->sessions));
#else
    sap->first_session = NULL;
#endif
}

void aes67_sap_service_deinit(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    aes67_timer_deinit(&sap->announcement_timer);
    aes67_timer_deinit(&sap->timeout_timer);

#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    struct aes67_sap_session * current = sap->first_session;

    sap->first_session = NULL;

    while(current != NULL){
        struct aes67_sap_session * previous = current;
        current = current->next;
        previous->next = NULL; // not needed really

        AES67_SAP_FREE(previous);
    }
#endif
}

struct aes67_sap_session * aes67_sap_service_find(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        if (sap->sessions[i].hash == hash && sap->sessions[i].src.ipver == ipver && 0 == aes67_memcmp(sap->sessions[i].src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16))){
            return &sap->sessions[i];
        }
    }
#else //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    struct aes67_sap_session * current = sap->first_session;

    while(current != NULL){
        if (current->hash == hash && current->src.ipver == ipver && 0 == aes67_memcmp(current->src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16))){
            return current;
        }
    }
#endif

    return NULL;
}

struct aes67_sap_session *  aes67_sap_service_register(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        if (sap->sessions[i].hash == 0){
            sap->sessions[i].hash = hash;
            sap->sessions[i].src.ipver = ipver;
            aes67_memcpy(sap->sessions[i].src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16));

            // never let overflow
            if (sap->no_of_ads < AES67_SAP_MEMORY_MAX_SESSIONS){
                sap->no_of_ads++;
            }

            return &sap->sessions[i];
        }
    }

    // TODO should only reach here if we've run out of memory (ie, table entries)

    return NULL;

#else //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    if (sap->no_of_ads >= AES67_SAP_MEMORY_MAX_SESSIONS){

        // TODO we've run out of (allowed) memory

        return NULL;
    }

    struct aes67_sap_session * session = (struct aes67_sap_session *)AES67_SAP_CALLOC(sizeof(struct aes67_sap_session));

    session->hash = hash;
    session->src.ipver = ipver;
    aes67_memcpy(session->src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16));

    // never let overflow
    if (sap->no_of_ads < UINT16_MAX - 1){
        sap->no_of_ads++;
    }

    // insert at beginning of linked list
    session->next = sap->first_session;
    sap->first_session = session;

    return session;

#endif
}


inline static void session_unregister(struct aes67_sap_service * sap, struct aes67_sap_session * session){

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    session->hash = 0;
#else
    AES67_SAP_FREE(session);
#endif

    // never let underflow
    if (sap->no_of_ads > 0){
        sap->no_of_ads--;
    }
}


void aes67_sap_service_unregister(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, ip);

    if (session == NULL){
        return;
    }

    // decrease active session count
    if (sap->no_of_ads > 1){
        sap->no_of_ads--;
    }

    session_unregister(sap, session);
}

u32_t aes67_sap_service_get_announcement_time_ms(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // if no message was generated, then no message has yet been sent
    // set timer to trigger next possible time.
    if (sap->announcement_size == 0){
        return AES67_TIMER_NOW;
    }

    s32_t no_of_ads = sap->no_of_ads;

    // min 1
    if (no_of_ads == 0){
        no_of_ads = 1;
    }

    s32_t i = (8 * sap->announcement_size * no_of_ads) / AES67_SAP_BANDWITH;

    s32_t interval_sec = i > 300 ? i : 300;

    s32_t offset_sec = (AES67_RAND() % (2*interval_sec/3) ) - interval_sec/3;

    u32_t next_tx = interval_sec + offset_sec;

    // remember the timeout interval (as used in time out computations)
    sap->timeout_interval = interval_sec;

    return next_tx * 1000;
}


void aes67_sap_service_set_announcement_timer(struct aes67_sap_service * sap)
{
    u32_t ms = aes67_sap_service_get_announcement_time_ms(sap);

    // actually set timer
    aes67_timer_set(&sap->announcement_timer, ms);
}

u32_t aes67_sap_service_get_timeout_sec(struct aes67_sap_service * sap)
{
    // max(3600, 10 * ad_interval)
    return 10 * (sap->timeout_interval > 360 ? sap->timeout_interval : 360);
}

void aes67_sap_service_set_timeout_timer(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // do NOT set timer if there are not sessions registered in the first place
    if (sap->no_of_ads == 0) {
        return;
    }

    aes67_time_t now;

    aes67_time_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = 1000 * aes67_sap_service_get_timeout_sec(sap);

    // get age of oldest announcement
    u32_t oldest = 0;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){

        if (sap->sessions[i].hash != 0){

            u32_t age = aes67_time_diffmsec(&now, &sap->sessions[i].last_announcement);

            if (age > oldest){
                oldest = age;

                // in case there is at least one that has timed out already,
                // set timer and stop further processing
                if (oldest > timeout_after){
                    aes67_timer_set(&sap->timeout_timer, AES67_TIMER_NOW);

                    return;
                }
            }
        }
    }

#else // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    struct aes67_sap_session * current = sap->first_session;

    for(;current != NULL; current = current->next){

        u32_t age = aes67_time_diffmsec(&now, &current->last_announcement);

        if (age > oldest){
            oldest = age;

            // in case there is at least one that has timed out already,
            // set timer and stop further processing
            if (oldest > timeout_after){
                aes67_timer_set(&sap->timeout_timer, AES67_TIMER_NOW);

                return;
            }
        }
    }

#endif

    aes67_timer_set(&sap->timeout_timer, (timeout_after - oldest + 1) * 1000);
}

void aes67_sap_service_timeouts_cleanup(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    aes67_time_t now;

    aes67_time_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = 1000 * aes67_sap_service_get_timeout_sec(sap);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){

        if (sap->sessions[i].hash != 0){

            u32_t age = aes67_time_diffmsec(&sap->sessions[i].last_announcement, &now);

            if (timeout_after < age){

                aes67_sap_service_event(aes67_sap_event_timeout, &sap->sessions[i], NULL, 0, NULL, 0, sap->user_data);

                session_unregister(sap, &sap->sessions[i]);
            }
        }
    }

#else // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    struct aes67_sap_session * current = sap->first_session;

    for(;current != NULL; current = current->next) {

        u32_t age = aes67_time_diffmsec(&current->last_announcement, &now);

        if (timeout_after < age){

            aes67_sap_service_event(aes67_sap_event_timeout, current, NULL, 0, NULL, 0, sap->user_data);

            session_unregister(current);
        }
    }

#endif

}


void aes67_sap_service_handle(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("msg != NULL", msg != NULL);
    AES67_ASSERT("msglen > 0", msglen > 0);

    // make sure basic header is there
    if (msglen < 4){
        return;
    }

    // discard SAPv0 packets
    // (as msg hash is always zero, it would be discarded further down anyway
//    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_RESERVED_MASK) == AES67_SAP_STATUS_VERSION_0 ){
//        return;
//    }

    // to be strict, check that the reserved bit is actually zero
    if ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_RESERVED_MASK) != 0){
        return;
    }

    u16_t hash = aes67_ntohs( *(u16_t*)&msg[AES67_SAP_MSG_ID_HASH] );

    // we may silently discard the SAP message if the message hash value is 0
    // (which is the value we use for empty hashes)
    if (hash == 0){
        return;
    }

    // TODO encrypted messages are not handled at this point in time.
    // the RFC actually recommends not to use encryption
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ENCRYPTED_MASK) == AES67_SAP_STATUS_ENCRYPTED_YES ) {
        return;
    }

    enum aes67_net_ipver ipver = ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4) ? aes67_net_ipver_4 : aes67_net_ipver_6;
    u8_t ip_len = ipver == aes67_net_ipver_4 ? 4 : 16;

    // position of payload
    u16_t pos = 4 + ip_len + 4 * msg[AES67_SAP_AUTH_LEN];

    // make sure there is enough data there that we're going to check
    if (msglen < pos + 3){
        return;
    }


    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, &msg[4]);


#if AES67_SAP_AUTH_ENABLED == 1

    // if new session or authenticated session pass through validator
    //
    // Note: even if message does not contain any auth data it will be passed. Thus the implementation may choose
    // to require authentication or not

    if ( (session == NULL) || session->authenticated == aes67_sap_auth_result_ok){

        if (aes67_sap_auth_result_ok != aes67_sap_service_auth_validate(msg, msglen, sap->user_data)){
            return;
        }
    }

#endif //AES67_SAP_AUTH_ENABLED == 1

    // introduce new variable that can be modified by zlib uncompressor
    u8_t * data = &msg[pos];
    u16_t datalen = msglen - pos;

    // reset position according actual payload data
    pos = 0;

    // uncompress content
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ) {

#if AES67_SAP_DECOMPRESS_AVAILABLE == 0
        // discard message - it is compressed but there's no decompression available
        return;
#else // AES67_SAP_DECOMPRESS_AVAILABLE == 1
        data = aes67_sap_zlib_decompress(data, &datalen, sap->user_data);
#endif


        // treat a NULL pointer as error
        if (data == NULL || datalen == 0){
            return;
        }
    }


    u8_t * type = NULL;
    u16_t typelen = 0;




    if ((data[0] == 'v' && data[1] == '=' && data[2] == '0')){
        // SAPv1 announce packets have no payload type (transport SDP only), but start with "v=0"
        // (some implementation might send it in deletion packet also)
    } else if (((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_DELETE) && (data[0] == 'o' && data[1] == '=')){
        // SAPv1 delete packets have no payload type (transport SDP only), but start with "o="
    } else {

        // set payload type string start to current position
        type = data;

        //search for NULL-termination of payload-type string
        for (; pos < datalen && data[pos] != '\0'; pos++){
            // pogo logo
        }

        // (silently) discard message if no payload type termination found until end of msg
        if ( pos + 1 >= datalen ){
            return;
        }

        typelen = pos;

        // if the sdp mimetype ("application/sdp") is given, just set the type as NULL with a zero length to keep
        // things simple
        if ( (typelen == sizeof(AES67_SDP_MIMETYPE) - 1) && 0 == aes67_memcmp(AES67_SDP_MIMETYPE, type, sizeof(AES67_SDP_MIMETYPE)) ) {
            type = NULL;
            typelen = 0;
        }

        // move position past NULL-byte of type
        pos++;
    }


    u8_t * payload = &data[pos];
    u16_t payloadlen = datalen - pos;

    enum aes67_sap_event event;

    // update internal session table according to
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){

        if (session == NULL){

            session = aes67_sap_service_register(sap, hash, ipver, &msg[4]);

            event = aes67_sap_event_new;

        } else {

            event = aes67_sap_event_refreshed;
        }

        // safety guard
        if (session != NULL){

#if AES67_SAP_AUTH_ENABLED == 1
            // remember that the session was authenticated at some point and will require authentication in the
            // future
            session->authenticated = msg[AES67_SAP_AUTH_LEN] > 0 ? aes67_sap_auth_result_ok : aes67_sap_auth_result_not_ok;
#endif

            aes67_time_now(&session->last_announcement);
        }

    } else {

        event = aes67_sap_event_deleted;
    }

    // publish event
    // NOTE if we've run out of memory when adding new sessions, session will be NULL!
    aes67_sap_service_event(event, session, type, typelen, payload, payloadlen, sap->user_data);

    // when deleting a session, do so after publishing the event to make the session data available for the callback
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_DELETE ){
        if (session != NULL){
            session_unregister(sap, session);
        }
    }

#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

    // don' forget to free payload memory if was decompressed (well, however the function may be implemented)
    if ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB){
        aes67_sap_zlib_decompress_free(data);
    }

#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 1

    // Note: we could update the timeout timer here accordingly, but let's not do this here but expect any implementation
    // to do this otherwise.
//    if ( sap->timeout_timer.state == aes67_timer_state_set){
//        if (sap->no_of_ads){
//            aes67_timer_unset(&sap->timeout_timer);
//        } else {
//            // hmm
//        }
//    }
}

u16_t aes67_sap_service_msg(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip, u8_t * payload, u16_t payloadlen)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("msg != NULL", msg != NULL);
    AES67_ASSERT("maxlen > 64", maxlen > 64); // a somewhat meaningful min size
    AES67_ASSERT("(opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0", (opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0); // only allowed options
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);
    AES67_ASSERT("payload != NULL", payload != NULL);
    AES67_ASSERT("payloadlen > 0", payloadlen >0);

    u8_t is_ipv4 = (ipver == aes67_net_ipver_4);

    msg[AES67_SAP_STATUS] = AES67_SAP_STATUS_VERSION_2;

#if AES67_SAP_COMPRESS_ENABLED == 1
    msg[AES67_SAP_STATUS] |= (opt & (AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK));
#else
    msg[AES67_SAP_STATUS] |= (opt & AES67_SAP_STATUS_MSGTYPE_MASK);
#endif

    msg[AES67_SAP_STATUS] |= is_ipv4 ? AES67_SAP_STATUS_ADDRTYPE_IPv4 : AES67_SAP_STATUS_ADDRTYPE_IPv6;


    *(u16_t*)&msg[AES67_SAP_MSG_ID_HASH] = aes67_htons(hash);

    aes67_memcpy(&msg[AES67_SAP_ORIGIN_SRC], ip, (is_ipv4 ? 4 : 16));

    u16_t headerlen = AES67_SAP_ORIGIN_SRC + (is_ipv4 ? 4 : 16);
    u16_t len = headerlen;

    // safe move payload
    aes67_memmove(&msg[len], payload, payloadlen);
    len += payloadlen;

    // figure out we our own session was registered prior
    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, ip);

    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE  && session == NULL){

        // if own session was not registered prior, register now
        aes67_sap_service_register(sap, hash, ipver, ip);

    } else if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_DELETE  && session != NULL) {

        // if own session was registered prior, unregister now
        aes67_sap_service_unregister(sap, hash, ipver, ip);
    }

#if AES67_SAP_COMPRESS_ENABLED == 1

    // only compress when explicitly requested
    if ( (opt & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ){

        u16_t l = aes67_sap_zlib_compress(&msg[headerlen], len - headerlen, maxlen - headerlen, sap->user_data);

        // on error, abort
        if (l == 0){
            return 0;
        }

        len = headerlen + l;
    }

#endif //AES67_SAP_COMPRESS_ENABLED == 1


    // auth data len = 0 for now
    msg[AES67_SAP_AUTH_LEN] = 0;

#if AES67_SAP_AUTH_ENABLED == 1

    // if returns other value than 0 is an error
    if (aes67_sap_service_auth_add(msg, len, maxlen, sap->user_data) != 0){

        // but we are ment to return the msglen, ie 0 indicates an error.
        return 0;
    }

    AES67_ASSERT("auth_len isset", msg[AES67_SAP_AUTH_LEN] > 0);

    // add authentication data len to total message length
    len += 4 * msg[AES67_SAP_AUTH_LEN];

#endif

    sap->announcement_size = len;

    return len;
}


u16_t aes67_sap_service_msg_sdp(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, struct aes67_net_addr * ip, struct aes67_sdp * sdp)
{
    // now, this is kind of cool: we know exactly where the payload will end up (before compression and authentication)
    // so we just write all the payload exactly there, thus the actual packet writer will not have to move anything and
    // in particular no additional memory is required ;)

    u16_t offset = (AES67_SAP_ORIGIN_SRC + sizeof(AES67_SDP_MIMETYPE)) + (ip->ipver == aes67_net_ipver_4 ? 4 : 16);

    AES67_ASSERT("offset < maxlen", offset < maxlen);

    u16_t payloadlen = 0;

    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ) {
        payloadlen = aes67_sdp_tostr(&msg[offset], maxlen - offset, sdp);
    } else {
        // when deleting a session, just add first line (after version) of SDP message
        payloadlen = aes67_sdp_origin_tostr(&msg[offset], maxlen - offset, &sdp->originator);
    }

    if (payloadlen == 0){
        return 0;
    }

    // always add payload type which MUST be supported by all SAPv2 capable recipients
    offset -= sizeof(AES67_SDP_MIMETYPE);
    msg[offset++] = 'a';
    msg[offset++] = 'p';
    msg[offset++] = 'p';
    msg[offset++] = 'l';
    msg[offset++] = 'i';
    msg[offset++] = 'c';
    msg[offset++] = 'a';
    msg[offset++] = 't';
    msg[offset++] = 'i';
    msg[offset++] = 'o';
    msg[offset++] = 'n';
    msg[offset++] = '/';
    msg[offset++] = 's';
    msg[offset++] = 'd';
    msg[offset++] = 'p';
    msg[offset++] = '\0'; // null termination

    offset -= sizeof(AES67_SDP_MIMETYPE);
    payloadlen += sizeof(AES67_SDP_MIMETYPE);

    return aes67_sap_service_msg(sap, msg, maxlen, opt, hash, ip->ipver, ip->addr, &msg[offset], payloadlen);
}