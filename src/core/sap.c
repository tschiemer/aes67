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


#define EMPTY_HASH 0

#define KNOWN   1
#define UNKNOWN 0

#define ADDED   0
#define ERROR   1

static u8_t hash_is_known(struct aes67_sap_service * sap, u16_t hash);
static u8_t hash_add(struct aes67_sap_service * sap, u16_t hash);
static void hash_clear(struct aes67_sap_service * sap, u16_t hash);


u8_t hash_is_known(struct aes67_sap_service * sap, u16_t hash)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(hash != EMPTY_HASH);

    u16_t sz = sap->hash_table_sz;
    for(u16_t i = 0; i < sz; i++){
        if (sap->hash_table[i] == hash){
            return KNOWN;
        }
    }

    return UNKNOWN;
}

u8_t hash_add(struct aes67_sap_service * sap, u16_t hash)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(hash != EMPTY_HASH);

    u16_t sz = sap->hash_table_sz;
    for(u16_t i = 0; i < sz; i++){
        if (sap->hash_table[i] == EMPTY_HASH){
            sap->hash_table[i] = hash;
            return ADDED;
        }
    }

    return ERROR;
}


void hash_clear(struct aes67_sap_service * sap, u16_t hash)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(hash != 0);

    u16_t sz = sap->hash_table_sz;
    for(u16_t i = 0; i < sz; i++){
        if (sap->hash_table[i] == hash){
            sap->hash_table[i] = EMPTY_HASH;
        }
    }
}



void aes67_sap_service_init(
        struct aes67_sap_service * sap,

        u16_t hash_table_sz,
        u16_t * hash_table,

        aes67_sap_event_callback event_callback
)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(hash_table_sz == 0 || hash_table != NULL);
    AES67_PLATFORM_ASSERT(event_callback != NULL);

    sap->hash_table_sz = hash_table_sz;
    sap->hash_table = hash_table;

    // make sure to clear hash table
    aes67_memset(sap->hash_table, 0, sizeof(u16_t) * hash_table_sz);

    sap->event_callback = event_callback;
}

void aes67_sap_service_parse(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(msg != NULL);
    AES67_PLATFORM_ASSERT(msglen > 0);

    // make sure basic header is there
    if (msglen < 4){
        return;
    }

    u16_t hash = aes67_ntohs( *(u16_t*)&msg[2] );

    // we may silently discard the SAP message if the message hash value is 0
    // (which is the value we use for empty hashes)
    if (hash == EMPTY_HASH){
        return;
    }

    // TODO encrypted messages are not handled at this point in time.
    // the RFC actually recommends not to use encryption
    if ( (msg[0] & AES67_SAP_STATUS_ENCRYPTED_MASK) == AES67_SAP_STATUS_ENCRYPTED_YES ) {
        return;
    }

    u8_t auth_len = msg[1];
    u8_t ip_len = ((msg[0] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4) ? 4 : 16;

    u16_t pos = 4 + ip_len + auth_len * 4;

    // make sure there is enough data there that we're going to check
    if (msglen < pos + 3){
        return;
    }



    // if there is an authenticator callback..
    if (sap->auth_validate_callback != NULL){

        // TODO proper authentication

        // ..try to authenticate the message..
        if (aes67_auth_not_ok == sap->auth_validate_callback()){

            // ..and discard if not authenticated
            return;
        }
    }

    // introduce new variable that can be modified by zlib uncompressor
    u8_t * data = &msg[pos];
    u16_t datalen = msglen - pos;

    // reset position according actual payload data
    pos = 0;

    // uncompress content
    if ( (msg[0] & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ) {

        if (sap->uncompress_callback == NULL){
            // zlib compression not supported, discard message
            return;
        }

        // TODO compressed payloads are not handled at this point in time.
        datalen = sap->uncompress_callback(&data, data, datalen);

        // treat a zero length as error
        if (datalen == 0){
            return;
        }
    }


    u8_t * type = NULL;
    u16_t typelen = 0;

    // check if there is a SDP content start ("v=0") because if there is, there will not be a mimetype payload
    // apparently, older SAP versions did not specify payload types but required SDP payloads
    if ((msg[0] & AES67_SAP_STATUS_VERSION_MASK) == AES67_SAP_STATUS_VERSION_1 | (data[0] != 'v' && data[1] != '=' && data[2] != '0')){

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
        if ( (typelen == sizeof(AES67_SDP_MIMETYPE) - 1) && memcmp(AES67_SDP_MIMETYPE, sizeof(AES67_SDP_MIMETYPE)) ) {
            type = NULL;
            typelen = 0;
        }
    }


    u8_t * payload = &data[pos + 1];
    u16_t payloadlen = datalen - pos;

    enum aes67_sap_event event;

    // update internal hash table according to
    if ( (msg[0] & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){

        if (hash_is_known(sap, hash) == UNKNOWN){

            if (hash_add(sap, hash) == ERROR){
                //TODO uh oh make traceable
                //return; // do NOT silently discard, could be relevant
            }

            event = aes67_sap_event_new;
        } else {
            event = aes67_sap_event_refreshed;
        }

    } else {

        hash_clear(sap, hash);

        event = aes67_sap_event_deleted;
    }

    // publish event
    sap->event_callback(event, hash, type, typelen, payload, payloadlen);
}


u16_t aes67_sap_service_msg(struct aes67_sap_service * sap, u8_t * msg, u16_t maxlen, u8_t opt, u16_t hash, struct aes67_net_addr * ip, struct aes67_sdp * sdp)
{
    AES67_PLATFORM_ASSERT(sap != NULL);
    AES67_PLATFORM_ASSERT(msg != NULL);
    AES67_PLATFORM_ASSERT(maxlen > 64); // a somewhat meaningful min size
    AES67_PLATFORM_ASSERT((opt & !(AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK)) == 0); // only allowed options
    AES67_PLATFORM_ASSERT( (opt & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_NONE || sap->compress_callback != NULL); // if asking for compression, require callback
    AES67_PLATFORM_ASSERT(hash != 0);
    AES67_PLATFORM_ASSERT(ip != NULL);
    AES67_PLATFORM_ASSERT(sdp != NULL);

    u8_t is_ipv4 = (ip->ipver == aes67_net_ipver_4);

    msg[0] = AES67_SAP_STATUS_VERSION_2;
    msg[0] |= (opt & (AES67_SAP_STATUS_MSGTYPE_MASK | AES67_SAP_STATUS_COMPRESSED_MASK));
    msg[0] |= is_ipv4 ? AES67_SAP_STATUS_ADDRTYPE_IPv4 : AES67_SAP_STATUS_ADDRTYPE_IPv6;

    // auth data len = 0 for now
    msg[1] = 0;

    *(u16_t*)&msg[2] = aes67_htons(hash);

    memcpy(&msg[4], ip->addr, (is_ipv4 ? 4 : 16));

    u16_t len = 4 + (is_ipv4 ? 4 : 16);

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


    if ( (opt & AES67_SAP_STATUS_MSGTYPE_MASK) == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ){

        u16_t l = aes67_sdp_tostr(&msg[len], maxlen - len, sdp);

        if (l == 0){
            // error
            return 0;
        }
        len += l;

    } else { // AES67_SAP_STATUS_MSGTYPE_DELETE

        u16_t l = aes67_sdp_origin_tostr(&msg[len], maxlen - len, sdp);

        if (l == 0){
            // error
            return 0;
        }
        len += l;
    }

    // if called for compression
    if ( (opt & AES67_SAP_STATUS_COMPRESSED_MASK) == AES67_SAP_STATUS_COMPRESSED_ZLIB ){

        // and if compression callback set (if not just send uncompressed)
        if (sap->compress_callback != NULL){
            //TODO inline compression
        }

    }

    if ( sap->auth_enticate_callback != NULL){
        //TODO add authentication data
    }


    return len;
}
