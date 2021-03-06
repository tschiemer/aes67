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
#include "aes67/def.h"



/**
 * Add a specific session to the session table.
 *
 * To be used directly (most likely) only when registering sessions sent from this device (to let them count towards
 * the total announcement count).
 */
#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
static struct aes67_sap_session *
aes67_sap_service_register(struct aes67_sap_service *sap, u16_t hash, enum aes67_net_ipver ipver, u8_t *ip, u16_t src);
#else
#define aes67_sap_service_register(sap, hash, ipver, ip, src) NULL
#endif



#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
static u32_t get_timeout_sec(struct aes67_sap_service *sap, u16_t stat, u32_t timeout_after_sec);
#endif



void aes67_sap_service_init(struct aes67_sap_service *sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

//    sap->user_data = user_data;

    sap->announcement_sec = 0;
    sap->announcement_size = 0;
    sap->timeout_sec = 3600;

    // init timers
    aes67_timer_init(&sap->announcement_timer);
    aes67_timer_init(&sap->timeout_timer);

    sap->no_of_ads_other = 0;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && 0 < AES67_SAP_MEMORY_MAX_SESSIONS
    aes67_memset(sap->sessions, 0, sizeof(sap->sessions));
#elif AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
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

#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
struct aes67_sap_session * aes67_sap_service_find(struct aes67_sap_service * sap, u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        if ((sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SET) && sap->sessions[i].hash == hash && sap->sessions[i].src.ipver == ipver && 0 == aes67_memcmp(sap->sessions[i].src.ip, ip, AES67_NET_IPVER_SIZE(ipver))){
            return &sap->sessions[i];
        }
    }
#else //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    struct aes67_sap_session * current = sap->first_session;

    while(current != NULL){
        if ((current->stat & AES67_SAP_SESSION_STAT_SET) && current->hash == hash && current->src.ipver == ipver && 0 == aes67_memcmp(current->src.ip, ip, AES67_NET_IPVER_SIZE(ipver))){
            return current;
        }
        current = current->next;
    }
#endif

    return NULL;
}

struct aes67_sap_session * aes67_sap_service_register(struct aes67_sap_service *sap, u16_t hash, enum aes67_net_ipver ipver, u8_t *ip, u16_t src)
{
    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);
    AES67_ASSERT("AES67_SAP_SESSION_STAT_SRC_ISVALID(src)", AES67_SAP_SESSION_STAT_SRC_ISVALID(src));

#if 0 < AES67_SAP_MEMORY_MAX_SESSIONS
    if (sap->no_of_ads_other + sap->no_of_ads_self >= AES67_SAP_MEMORY_MAX_SESSIONS){

        // TODO we've run out of (allowed) memory

        return NULL;
    }
#endif

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    struct aes67_sap_session * session = NULL;

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        if (sap->sessions[i].stat == AES67_SAP_SESSION_STAT_CLEAR){

            session = &sap->sessions[i];
//            sap->sessions[i].stat = AES67_SAP_SESSION_STAT_SET;
//            sap->sessions[i].hash = hash;
//            sap->sessions[i].src.ipver = ipver;
//            aes67_memcpy(sap->sessions[i].src.addr, ip, AES67_NET_IPVER_SIZE(ipver));
//
//            // never let overflow
//            if (sap->no_of_ads_other + sap->no_of_ads_self < AES67_SAP_MEMORY_MAX_SESSIONS){
//                sap->no_of_ads++;
//            }
//
//            return &sap->sessions[i];
        }
    }

#else //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

// if equal 0, no limit

    struct aes67_sap_session * session = (struct aes67_sap_session *)AES67_SAP_MALLOC(sizeof(struct aes67_sap_session));

#endif

    // shouldn't happen,technically speaking
    if (session == NULL){
        return NULL;
    }

    session->stat = AES67_SAP_SESSION_STAT_SET | (src & AES67_SAP_SESSION_STAT_SRC);
    session->hash = hash;
    session->src.ipver = ipver;
    aes67_memcpy(session->src.ip, ip, AES67_NET_IPVER_SIZE(ipver));

    // never let overflow
    if ((src & AES67_SAP_SESSION_STAT_SRC) == AES67_SAP_SESSION_STAT_SRC_IS_SELF) {
        if (sap->no_of_ads_self < UINT16_MAX){
            sap->no_of_ads_self++;
        }
    } else {
        if (sap->no_of_ads_other < UINT16_MAX){
            sap->no_of_ads_other++;
        }
    }

#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    session->next = NULL;

    // insert at beginning of linked list
    session->next = sap->first_session;
    sap->first_session = session;
#endif

    return session;

}

void aes67_sap_service_unregister(struct aes67_sap_service * sap, struct aes67_sap_session * session)
{
    AES67_ASSERT("session != NULL", session!=NULL);

    session->stat = AES67_SAP_SESSION_STAT_CLEAR;

    if ((session->stat & AES67_SAP_SESSION_STAT_SRC) == AES67_SAP_SESSION_STAT_SRC_IS_SELF){
        sap->no_of_ads_self--;
    } else {
        sap->no_of_ads_other--;
    }

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL


#else //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    if (sap->first_session == session) {
        sap->first_session = session->next;
    } else {
        struct aes67_sap_session * before = sap->first_session;

        while(before->next != session) {

            AES67_ASSERT("next != NULL", before->next != NULL);

            before = before->next;
        }

        before->next = session->next;
    }

    AES67_SAP_FREE(session);

#endif
}
#endif //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS


void aes67_sap_compute_times_sec(s32_t no_of_ads, s32_t announcement_size, u32_t *announce_sec, u32_t *timeout_sec)
{
    // announcement size likely is 0 if no announcement has been sent yet.
    if (announcement_size == 0 || no_of_ads == 0) {

        if (announce_sec != NULL) {
            *announce_sec = 0;
        }

        if (timeout_sec != NULL) {
            // max(3600, 10 * ad_interval)
            *timeout_sec = (u32_t)AES67_SAP_MIN_TIMEOUT_SEC;
        }

        return;
    }

    s32_t i = (8 * announcement_size * no_of_ads) / AES67_SAP_BANDWITH;

    s32_t interval_sec = i > AES67_SAP_MIN_INTERVAL_SEC ? i : AES67_SAP_MIN_INTERVAL_SEC;

    s32_t offset_sec = (AES67_RAND() % ((2*interval_sec)/3) ) - interval_sec/3;

    u32_t next_tx = interval_sec + offset_sec;

    if (announce_sec != NULL) {
        *announce_sec = next_tx;
    }

    if (timeout_sec != NULL) {
        // max(3600, 10 * ad_interval)
        interval_sec *= 10;
        *timeout_sec = (u32_t)(interval_sec > AES67_SAP_MIN_TIMEOUT_SEC ? interval_sec : AES67_SAP_MIN_TIMEOUT_SEC);
    }
}


#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
u32_t get_timeout_sec(struct aes67_sap_service *sap, u16_t stat, u32_t timeout_after_sec)
{
    // we are comparing msec
    timeout_after_sec *= 1000;

    aes67_time_t now;

    aes67_time_now(&now);

    // get age of oldest announcement
    u32_t oldest = 0;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){

        // only check session not coming from this service
        if ( (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SET) && (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) == stat){

            u32_t age = aes67_time_diffmsec(&now, &sap->sessions[i].last_announcement);

            if (age > oldest){
                oldest = age;

                // in case there is at least one that has timed out already,
                // set timer and stop further processing
                if (oldest > timeout_after_sec){
//                    aes67_timer_set(&sap->timeout_timer, AES67_TIMER_NOW);

                    return AES67_TIMER_NOW;
                }
            }
        }
    }

#else // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    struct aes67_sap_session * current = sap->first_session;

    for(;current != NULL; current = current->next){

        // only check session not coming from this service
        if ((current->stat & AES67_SAP_SESSION_STAT_SET) && (current->stat & AES67_SAP_SESSION_STAT_SRC) == (stat & AES67_SAP_SESSION_STAT_SRC)){

            u32_t age = aes67_time_diffmsec(&now, &current->last_announcement);

            if (age > oldest){
                oldest = age;

                // in case there is at least one that has timed out already,
                // set timer and stop further processing
                if (oldest > timeout_after_sec){
                    return AES67_TIMER_NOW;
                }
            }
        }
    }

#endif

    return (timeout_after_sec - oldest)/1000;
}


void aes67_sap_service_set_announcement_timer(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // do NOT set timer if there are not sessions registered in the first place
    if (sap->no_of_ads_self == 0 || sap->announcement_size == 0) {
        return;
    }

    // if the timer is set, do not set again. (note: when expired should be handled first)
    if (aes67_timer_getstate(&sap->announcement_timer) != aes67_timer_state_unset) {
        return;
    }


    aes67_sap_compute_times_sec(sap->no_of_ads_other+sap->no_of_ads_self, sap->announcement_size, &sap->announcement_sec, NULL);

    u32_t timeout_after_sec = sap->announcement_sec;

    timeout_after_sec = get_timeout_sec(sap, AES67_SAP_SESSION_STAT_SRC_IS_SELF, timeout_after_sec);

    // actually set timer
//    printf("atimer = %d\n", timeout_after_sec);
    aes67_timer_set(&sap->announcement_timer, 1000 * timeout_after_sec);
}


void aes67_sap_service_announcement_check(struct aes67_sap_service *sap, void *user_data)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // don't act if not expired
    if (aes67_timer_getstate(&sap->announcement_timer) != aes67_timer_state_expired) {
        return;
    }

    aes67_time_t now;

    aes67_time_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = sap->announcement_sec;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){

        // only check session not coming from this service
        if ( (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SET) && (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) == AES67_SAP_SESSION_STAT_SRC_IS_SELF){

            u32_t age = aes67_time_diffmsec(&sap->sessions[i].last_announcement, &now);

            if (timeout_after < age){

                aes67_sap_service_event(sap, aes67_sap_event_announcement_request, sap->sessions[i].hash,
                                        sap->sessions[i].src.ipver, sap->sessions[i].src.ip, NULL, 0, NULL, 0,
                                        user_data);
            }
        }
    }

#else // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    struct aes67_sap_session * current = sap->first_session;

    for(;current != NULL; current = current->next) {

        // only check session not coming from this service
        if ((current->stat & AES67_SAP_SESSION_STAT_SET) && (current->stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) == AES67_SAP_SESSION_STAT_SRC_IS_SELF){

            u32_t age = aes67_time_diffmsec(&current->last_announcement, &now);

            if (timeout_after < age){

                aes67_sap_service_event(sap, aes67_sap_event_announcement_request, current->hash, current->src.ipver, current->src.ip, NULL, 0, NULL, 0, user_data);

            }
        }
    }

#endif

    aes67_timer_unset(&sap->announcement_timer);
}


void aes67_sap_service_set_timeout_timer(struct aes67_sap_service * sap)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // do NOT set timer if there are not sessions registered in the first place
    if (sap->no_of_ads_other == 0) {
        return;
    }

    // if the timer is set, do not set again.
    if (aes67_timer_getstate(&sap->timeout_timer) != aes67_timer_state_unset) {
        return;
    }


    aes67_sap_compute_times_sec(sap->no_of_ads_other+sap->no_of_ads_self, sap->announcement_size, NULL, &sap->timeout_sec);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after_sec = 1000 * sap->timeout_sec;

    timeout_after_sec = get_timeout_sec(sap, AES67_SAP_SESSION_STAT_SRC_IS_OTHER, timeout_after_sec);

//    printf("ttimer = %d\n", timeout_after_sec);
    aes67_timer_set(&sap->timeout_timer, 1000*timeout_after_sec);
}

void aes67_sap_service_timeouts_cleanup(struct aes67_sap_service *sap, void *user_data)
{
    AES67_ASSERT("sap != NULL", sap != NULL);

    // don't act if not expired
    if (aes67_timer_getstate(&sap->timeout_timer) != aes67_timer_state_expired) {
        return;
    }

    aes67_time_t now;

    aes67_time_now(&now);

    // max(3600, 10 * ad_interval)
    u32_t timeout_after = 1000 * sap->timeout_sec;

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL

    for(u16_t i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){

        // only check session not coming from this service
        if ( (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SET) && (sap->sessions[i].stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) != AES67_SAP_SESSION_STAT_SRC_IS_SELF){

            u32_t age = aes67_time_diffmsec(&sap->sessions[i].last_announcement, &now);

            if (timeout_after < age){

                aes67_sap_service_event(sap, aes67_sap_event_timeout, sap->sessions[i].hash,
                                        sap->sessions[i].src.ipver, sap->sessions[i].src.ip, NULL, 0, NULL, 0,
                                        user_data);

                aes67_sap_service_unregister(sap, &sap->sessions[i]);
            }
        }
    }

#else // AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC

    struct aes67_sap_session * current = sap->first_session;

    for(;current != NULL; current = current->next) {

        // only check session not coming from this service
        if ((current->stat & AES67_SAP_SESSION_STAT_SET) && (current->stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) != AES67_SAP_SESSION_STAT_SRC_IS_SELF){

            u32_t age = aes67_time_diffmsec(&current->last_announcement, &now);

            if (timeout_after < age){

                aes67_sap_service_event(sap, aes67_sap_event_timeout, current->hash, current->src.ipver, current->src.ip, NULL, 0, NULL, 0, user_data);

                aes67_sap_service_unregister(sap, current);
            }
        }
    }

#endif

    // make sure to reset/unset timer state
    aes67_timer_unset(&sap->timeout_timer);
}


void aes67_sap_service_process(struct aes67_sap_service *sap, void * user_data)
{
    aes67_sap_service_timeouts_cleanup(sap, user_data);
    // set timer AFTER handling of expired to set directly again if necessary
    aes67_sap_service_set_timeout_timer(sap);

    aes67_sap_service_announcement_check(sap, user_data);
    // set timer AFTER handling of expired to set directly again if necessary
    aes67_sap_service_set_announcement_timer(sap);
}
#endif //#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS


void aes67_sap_service_handle(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, void *user_data)
{
//    AES67_ASSERT("sap != NULL", sap != NULL);
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

#if AES67_SAP_FILTER_ZEROHASH == 1
    // we may silently discard the SAP message if the message hash value is 0
    if (hash == 0){
        return;
    }
#endif

    // TODO encrypted messages are not handled at this point in time.
    // the RFC actually recommends not to use encryption
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ENCRYPTED_MASK) == AES67_SAP_STATUS_ENCRYPTED_YES ) {
        return;
    }

    enum aes67_net_ipver ipver = ((msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4) ? aes67_net_ipver_4 : aes67_net_ipver_6;

    // position of payload
    u16_t pos = AES67_SAP_ORIGIN_SRC + AES67_NET_IPVER_SIZE(ipver) + 4 * msg[AES67_SAP_AUTH_LEN];

    // make sure there is enough data there that we're going to check
    if (msglen < pos + 3){
        return;
    }


    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, &msg[AES67_SAP_ORIGIN_SRC]);

    // ignore if it is a message sent by us
    if (session != NULL && (session->stat & AES67_SAP_SESSION_STAT_SRC_IS_SELF) == AES67_SAP_SESSION_STAT_SRC_IS_SELF){
        return;
    }

#if AES67_SAP_AUTH_ENABLED == 1

    // if new session or authenticated session pass through validator
    //
    // Note: even if message does not contain any auth data it will be passed. Thus the implementation may choose
    // to require authentication or not

    if ( (session == NULL) || session->authenticated == aes67_sap_auth_result_ok){

        if (aes67_sap_auth_result_ok != aes67_sap_service_auth_validate(sap, msg, msglen, user_data)){
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
        data = aes67_sap_zlib_decompress(data, &datalen, user_data);
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
        } else {
#if AES67_SAP_FILTER_SDP == 1
            // as we're not dealing with an sdp payload, discard
            return;
#endif
        }


        // move position past NULL-byte of type
        pos++;
    }


    u8_t * payload = &data[pos];
    u16_t payloadlen = datalen - pos;

    enum aes67_sap_event event = aes67_sap_event_undefined;

    // update internal session table according to
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){

        if (session == NULL){

            session = aes67_sap_service_register(sap, hash, ipver, &msg[4], AES67_SAP_SESSION_STAT_SRC_IS_OTHER);

#if AES67_SAP_MEMORY_HARD_LIMIT == 1
            // if no session was gotten, the session limit was reached, ignore any unknown SAP messages
            // primarily makes sense with high enough limits, thus trying to limit memory usage by potential attackers
            if (session == NULL){
                return;
            }
#endif
            event = aes67_sap_event_new;

        } else {

            event = aes67_sap_event_updated;
        }


        // safety guard
        if (session != NULL){

#if AES67_SAP_AUTH_ENABLED == 1
            // remember that the session was authenticated at some point and will require authentication in the
            // future
            session->authenticated = msg[AES67_SAP_AUTH_LEN] > 0 ? aes67_sap_auth_result_ok : aes67_sap_auth_result_not_ok;
#endif

            aes67_time_now(&session->last_announcement);

#if AES67_SAP_FILTER_XOR8 == 1
            u8_t xor8 = aes67_xor8(msg, msglen);

            if (event == aes67_sap_event_new){
                session->stat |= xor8;
            } else { // updated
                // if nothing has changed, abort
                if ( (session->stat & AES67_SAP_SESSION_STAT_XOR8_HASH) == xor8){
                    return;
                }
            }
#endif
        }

    } else {

        event = aes67_sap_event_deleted;

#if AES67_SAP_MEMORY_HARD_LIMIT == 1
        // if no session was gotten, the session limit was reached before, ignore any unknown SAP messages
            // primarily makes sense with high enough limits, thus trying to limit memory usage by potential attackers
            if (session == NULL){
                return;
            }
#endif
    }

    // publish event
    // NOTE if we've run out of memory when adding new sessions, session will be NULL!
    aes67_sap_service_event(sap, event, hash, ipver, &msg[AES67_SAP_ORIGIN_SRC], type, typelen, payload, payloadlen,
                            user_data);

    // when deleting a session, do so after publishing the event to make the session data available for the callback
    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_DELETE ){
        if (session != NULL){
            aes67_sap_service_unregister(sap, session);
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

WEAK_FUN void
aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                        enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype, u16_t payloadtypelen,
                        u8_t *payload, u16_t payloadlen, void *user_data)
{

}

u16_t aes67_sap_service_msg(struct aes67_sap_service *sap, u8_t *msg, u16_t maxlen, u8_t opt, u16_t hash,
                            enum aes67_net_ipver ipver, u8_t *ip, u8_t *payload, u16_t payloadlen, void *user_data)
{
//    AES67_ASSERT("sap != NULL", sap != NULL);
    AES67_ASSERT("msg != NULL", msg != NULL);
    AES67_ASSERT("maxlen > 64", maxlen > 64); // a somewhat meaningful min size
    AES67_ASSERT("(opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0", (opt & ~(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0); // only allowed options
    AES67_ASSERT("hash != 0", hash != 0);
    AES67_ASSERT("AES67_NET_IPVER_ISVALID(ipver)", AES67_NET_IPVER_ISVALID(ipver));
    AES67_ASSERT("ip != NULL", ip != NULL);
    AES67_ASSERT("payload != NULL", payload != NULL);
    AES67_ASSERT("payloadlen > 0", payloadlen >0);

    if (user_data == NULL){
        user_data = sap;
    }

    msg[AES67_SAP_STATUS] = AES67_SAP_STATUS_VERSION_2;

#if AES67_SAP_COMPRESS_ENABLED == 1
    msg[AES67_SAP_STATUS] |= (opt & (AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK));
#else
    msg[AES67_SAP_STATUS] |= (opt & AES67_SAP_STATUS_MSGTYPE_MASK);
#endif

    msg[AES67_SAP_STATUS] |= (ipver == aes67_net_ipver_4) ? AES67_SAP_STATUS_ADDRTYPE_IPv4 : AES67_SAP_STATUS_ADDRTYPE_IPv6;


    *(u16_t*)&msg[AES67_SAP_MSG_ID_HASH] = aes67_htons(hash);

    aes67_memcpy(&msg[AES67_SAP_ORIGIN_SRC], ip, AES67_NET_IPVER_SIZE(ipver));

    u16_t headerlen = AES67_SAP_ORIGIN_SRC + AES67_NET_IPVER_SIZE(ipver);
    u16_t len = headerlen;

    // safe move payload
    aes67_memmove(&msg[len], payload, payloadlen);
    len += payloadlen;

    // figure out we our own session was registered prior
    struct aes67_sap_session * session = aes67_sap_service_find(sap, hash, ipver, ip);

    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE  && session == NULL){

        // if own session was not registered prior, register now
        session = aes67_sap_service_register(sap, hash, ipver, ip, AES67_SAP_SESSION_STAT_SRC_IS_SELF);

    } else if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_DELETE  && session != NULL) {

        // if own session was registered prior, unregister now
        aes67_sap_service_unregister(sap, session);

        session = NULL;
    }

    // so, if this service's session exists and it is being announced, update the timestamp
    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE && session != NULL){
        aes67_time_now(&session->last_announcement);
    }

#if AES67_SAP_COMPRESS_ENABLED == 1

    // only compress when explicitly requested
    if ( (opt & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ){

        u16_t l = aes67_sap_zlib_compress(&msg[headerlen], len - headerlen, maxlen - headerlen, user_data);

        // on error, abort
        if (l == 0){
            return 0;
        }

        len = headerlen + l;
    }

#endif //AES67_SAP_COMPRESS_ENABLED == 1


    // auth data len = 0 for now
    msg[AES67_SAP_AUTH_LEN] = 0;

#if AES67_SAP_AUTH_SELF == 1

    // if returns other value than 0 is an error
    if (aes67_sap_service_auth_add(sap, msg, len, maxlen, user_data) != 0){

        // but we are ment to return the msglen, ie 0 indicates an error.
        return 0;
    }

    // if the auth_len can be zero, the auth_add can selectively add authentication data
//    AES67_ASSERT("auth_len isset", msg[AES67_SAP_AUTH_LEN] > 0);

    // add authentication data len to total message length
    len += 4 * msg[AES67_SAP_AUTH_LEN];

#endif

    if (sap != NULL) {
        sap->announcement_size = len;
    }

    return len;
}


u16_t aes67_sap_service_msg_sdp(struct aes67_sap_service *sap, u8_t *msg, u16_t maxlen, u8_t opt, u16_t hash,
                                struct aes67_net_addr *ip, struct aes67_sdp *sdp, void *user_data)
{
    // now, this is kind of cool: we know exactly where the payload will end up (before compression and authentication)
    // so we just write all the payload exactly there, thus the actual packet writer will not have to move anything and
    // in particular no additional memory is required ;)

    u16_t offset = (AES67_SAP_ORIGIN_SRC + sizeof(AES67_SDP_MIMETYPE)) + AES67_NET_IPVER_SIZE(ip->ipver);

    AES67_ASSERT("offset < maxlen", offset < maxlen);

    u16_t payloadlen = 0;

    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ) {
        payloadlen = aes67_sdp_tostr(&msg[offset], maxlen - offset, sdp, NULL);
    } else {
        // when deleting a session, just add first line (after version) of SDP message
        payloadlen = aes67_sdp_origin_tostr(&msg[offset], maxlen - offset, &sdp->originator);
    }

    if (payloadlen == 0){
        return 0;
    }

    // always add payload type which MUST be supported by all SAPv2 capable recipients
    // "application/sdp" (added in reverse)

    msg[--offset] = '\0'; // null termination
    msg[--offset] = 'p';
    msg[--offset] = 'd';
    msg[--offset] = 's';
    msg[--offset] = '/';
    msg[--offset] = 'n';
    msg[--offset] = 'o';
    msg[--offset] = 'i';
    msg[--offset] = 't';
    msg[--offset] = 'a';
    msg[--offset] = 'c';
    msg[--offset] = 'i';
    msg[--offset] = 'l';
    msg[--offset] = 'p';
    msg[--offset] = 'p';
    msg[--offset] = 'a';

    payloadlen += sizeof(AES67_SDP_MIMETYPE);

    return aes67_sap_service_msg(sap, msg, maxlen, opt, hash, ip->ipver, ip->ip, &msg[offset], payloadlen, user_data);
}
