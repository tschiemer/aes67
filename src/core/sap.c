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




void aes67_sap_service_init(
        struct aes67_sap_service * sap,
        u16_t session_table_size,
        struct aes67_sap_session * session_table,
        aes67_sap_event_callback event_callback
)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash_table_sz == 0 || hash_table != NULL", session_table_size == 0 || session_table != NULL);
    AES67_ASSERT("event_callback != NULL", event_callback != NULL);

    sap->session_table.active = 0;
    sap->session_table.size = session_table_size;
    sap->session_table.table = session_table;

    sap->event_callback = event_callback;

    sap->announcement_size = 0;
    sap->timeout_interval = 0;


    // make sure to clear session table
    aes67_memset(session_table, 0, session_table_size * sizeof(struct aes67_sap_session));

    // init timers
    aes67_timer_init(&sap->announcement_timer);
    aes67_timer_init(&sap->timeout_timer);
}

void aes67_sap_service_deinit(struct aes67_sap_service * sap)
{
    // do nothing at this point in time
}

struct aes67_sap_session * aes67_sap_service_find(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);

    for(u16_t i = 0; i < sap->session_table.size; i++){
        if (sap->session_table.table[i].hash == hash && sap->session_table.table[i].src.ipver == ipver && 0 == aes67_memcmp(sap->session_table.table[i].src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16))){
            return &sap->session_table.table[i];
        }
    }

    return NULL;
}

struct aes67_sap_session *  aes67_sap_service_register(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);

    for(u16_t i = 0; i < sap->session_table.size; i++){
        if (sap->session_table.table[i].hash == 0){
            sap->session_table.table[i].hash = hash;
            sap->session_table.table[i].src.ipver = ipver;
            aes67_memcpy(sap->session_table.table[i].src.addr, ip, (ipver == aes67_net_ipver_4 ? 4 : 16));

            // never let overflow
            if (sap->session_table.active < UINT16_MAX - 1){
                sap->session_table.active++;
            }

            return &sap->session_table.table[i];
        }
    }

    // TODO should only reach here if we've run out of memory (ie, table entries)

    return NULL;
}


inline static void session_unregister(struct aes67_sap_session * session){
    session->hash = 0;
}


void aes67_sap_service_unregister(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, ip);

    if (session == NULL){
        return;
    }

    // decrease active session count
    if (sap->session_table.active > 1){
        sap->session_table.active--;
    }

    session_unregister(session);
}

void aes67_sap_service_set_announcement_timer(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // if no message was generated, then no message has yet been sent
    // set timer to trigger next possible time.
    if (sap->announcement_size == 0){
        aes67_timer_enable(&sap->announcement_timer, AES67_TIMER_NOW);
        return;
    }

    s32_t no_of_ads = sap->session_table.active;

    // min 1
    if (no_of_ads == 0){
        no_of_ads = 1;
    }

    s32_t i = (8 * sap->announcement_size * no_of_ads) / AES67_SAP_BANDWITH;

    s32_t interval_sec = i > 300 ? i : 300;

    s32_t offset_sec = (AES67_RAND() % (2*interval_sec/3) ) - interval_sec/3;

    u32_t next_tx = interval_sec + offset_sec;

    // remember the timeout interval
    sap->timeout_interval = interval_sec;

    // actually set timer
    aes67_timer_enable(&sap->announcement_timer, next_tx * 1000);
}

void aes67_sap_service_set_timeout_timer(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    aes67_timestamp_t now;

    aes67_timestamp_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = 10 * (sap->timeout_interval > 360 ? sap->timeout_interval : 360);

    // get age of oldest announcement
    u32_t oldest = 0;

    for(u16_t i = 0; i < sap->session_table.size; i++){

        if (sap->session_table.table[i].hash != 0){

            u32_t age = aes67_timestamp_diffsec(&now, &sap->session_table.table[i].last_announcement);

            if (age > oldest){
                oldest = age;

                // in case there is at least one that has timed out already,
                // set timer and stop further processing
                if (oldest > timeout_after){
                    aes67_timer_enable(&sap->timeout_timer, AES67_TIMER_NOW);

                    return;
                }
            }
        }
    }

    aes67_timer_enable(&sap->timeout_timer, (timeout_after - oldest + 1) *1000);
}

void aes67_sap_service_timeout_clear(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    aes67_timestamp_t now;

    aes67_timestamp_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = 10 * (sap->timeout_interval > 360 ? sap->timeout_interval : 360);


    for(u16_t i = 0; i < sap->session_table.size; i++){

        if (sap->session_table.table[i].hash != 0){

            u32_t age = aes67_timestamp_diffsec(&now, &sap->session_table.table[i].last_announcement);

            if (age > timeout_after){

                if (sap->event_callback != NULL){

                    sap->event_callback(aes67_sap_event_timeout, &sap->session_table.table[i], NULL, 0, NULL, 0);
                }

                session_unregister(&sap->session_table.table[i]);
            }
        }
    }
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

        if (aes67_sap_auth_result_ok != aes67_sap_service_auth_validate(sap, msg, msglen)){
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

#endif

        data = aes67_sap_zlib_decompress(sap, data, &datalen);

        // treat a NULL pointer as error
        if (data == NULL || datalen == 0){
            return;
        }
    }


    u8_t * type = NULL;
    u16_t typelen = 0;

    // check if there is a SDP content start ("v=0") because if there is, there will not be a mimetype payload
    // apparently, older SAP versions did not specify payload types but required SDP payloads
    if ( ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_VERSION_MASK) == AES67_SAP_STATUS_VERSION_1) | (data[0] != 'v' && data[1] != '=' && data[2] != '0')){

        // set payload type string start to current position
        type = data;

        //search for NULL-termination of payload-type string
        for (; pos < datalen && data[pos] != '\0'; pos++, typelen++){
            // pogo logo
        }

        // (silently) discard message if no payload type termination found until end of msg
        if ( pos + 1 < datalen ){
            return;
        }

        // if the sdp mimetype ("applicatin/sdp") is given, just set the type as NULL with a zero length to keep
        // things simple
        if ( (typelen == sizeof(AES67_SDP_MIMETYPE) - 1) && aes67_memcmp(AES67_SDP_MIMETYPE, type, sizeof(AES67_SDP_MIMETYPE)) ) {
            type = NULL;
            typelen = 0;
        }
    }


    u8_t * payload = &data[pos + 1];
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

            aes67_timestamp_now(&session->last_announcement);
        }

    } else {

        event = aes67_sap_event_deleted;
    }

    // publish event
    // NOTE if we've run out of memory when adding new sessions, session will be NULL!
    sap->event_callback(event, session, type, typelen, payload, payloadlen);

    // when deleting a session, do so after publishing the event to make the session data available for the callback
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){
        if (session != NULL){
            session_unregister(session);
        }
    }

#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

    // don' forget to free payload memory if was decompressed (well, however the function may be implemented)
    if ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB){
        aes67_sap_zlib_decompress_free(payload);
    }

#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 1
}


u16_t aes67_sap_service_msg(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, struct aes67_net_addr * ip, struct aes67_sdp * sdp)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("msg != NULL", msg != NULL);
    AES67_ASSERT("maxlen > 64", maxlen > 64); // a somewhat meaningful min size
    AES67_ASSERT("(opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0", (opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0); // only allowed options
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("ip != NULL", ip != NULL);
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    u8_t is_ipv4 = (ip->ipver == aes67_net_ipver_4);

    msg[AES67_SAP_STATUS] = AES67_SAP_STATUS_VERSION_2;

#if AES67_SAP_COMPRESS_ENABLED == 1
    msg[AES67_SAP_STATUS] |= (opt & (AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK));
#else
    msg[AES67_SAP_STATUS] |= (opt & AES67_SAP_STATUS_MSGTYPE_MASK);
#endif

    msg[AES67_SAP_STATUS] |= is_ipv4 ? AES67_SAP_STATUS_ADDRTYPE_IPv4 : AES67_SAP_STATUS_ADDRTYPE_IPv6;


    *(u16_t*)&msg[AES67_SAP_MSG_ID_HASH] = aes67_htons(hash);

    aes67_memcpy(&msg[AES67_SAP_ORIGIN_SRC], ip->addr, (is_ipv4 ? 4 : 16));

    u16_t headerlen = 4 + (is_ipv4 ? 4 : 16);
    u16_t len = headerlen;

    // always add payload type which MUST be supported by all SAPv2 capable recipients
    msg[len++] = 'a';
    msg[len++] = 'p';
    msg[len++] = 'p';
    msg[len++] = 'l';
    msg[len++] = 'i';
    msg[len++] = 'c';
    msg[len++] = 'a';
    msg[len++] = 't';
    msg[len++] = 'i';
    msg[len++] = 'o';
    msg[len++] = 'n';
    msg[len++] = '/';
    msg[len++] = 's';
    msg[len++] = 'd';
    msg[len++] = 'p';
    msg[len++] = '0';

    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ip->ipver, ip->addr);

    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){

        u16_t l = aes67_sdp_tostr(&msg[len], maxlen - len, sdp);

        if (l == 0){
            // error
            return 0;
        }
        len += l;

        // if own session was not registered prior, register now
        if (session == NULL){
            aes67_sap_service_register(sap, hash, ip->ipver, ip->addr);
        }

    } else { // AES67_SAP_STATUS_MSGTYPE_DELETE

        // when deleting a session, just add first line (after version) of SDP message
        u16_t l = aes67_sdp_origin_tostr(&msg[len], maxlen - len, &sdp->originator);

        if (l == 0){
            // error
            return 0;
        }
        len += l;

        // above function does not add line termination
        msg[len++] = '\r';
        msg[len++] = '\n';

        // if own session was registered prior, unregister now
        if (session != NULL){
            aes67_sap_service_register(sap, hash, ip->ipver, ip->addr);
        }
    }

#if AES67_SAP_COMPRESS_ENABLED == 1

    // only compress when explicitly requested
    if ( (opt & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ){

        u16_t payloadlen = aes67_sap_zlib_compress(sap, &msg[headerlen], len - headerlen, maxlen - headerlen);

        // on error, abort
        if (payloadlen == 0){
            return 0;
        }

        len = headerlen + payloadlen;
    }

#endif //AES67_SAP_COMPRESS_ENABLED == 1


    // auth data len = 0 for now
    msg[AES67_SAP_AUTH_LEN] = 0;

#if AES67_SAP_AUTH_ENABLED == 1

    // if returns other value than 0 is an error
    if (aes67_sap_service_auth_add(sap, msg, len, maxlen) != 0){

        // but we are ment to return the msglen, ie 0 indicates an error.
        return 0;
    }

    // add authentication data len to total message length
    len += 4 * msg[AES67_SAP_AUTH_LEN];

#endif

    sap->announcement_size = len;

    return len;
}
