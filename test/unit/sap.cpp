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

#include "CppUTest/TestHarness.h"

#include <string>

#include "aes67/sap.h"

typedef struct {
    uint8_t status;
    uint8_t auth_len;      // length(auth_data) == 4 * auth_len
    uint16_t msg_id_hash;
    struct aes67_net_addr ip;
    uint16_t typelen;
    uint8_t type[32];
    uint16_t datalen;
    uint8_t data[256];
} sap_packet_t;

#define PACKET_TYPE(str) .type = str, .typelen = sizeof(str)
#define PACKET_DATA(str) .data = str, .datalen = sizeof(str) - 1

static u16_t packet2mem(uint8_t data[], sap_packet_t & packet);

u16_t packet2mem(uint8_t data[], sap_packet_t & packet)
{
    data[AES67_SAP_STATUS] = packet.status;
    data[AES67_SAP_AUTH_LEN] = packet.auth_len;
    data[AES67_SAP_MSG_ID_HASH] = (packet.msg_id_hash >> 8) & 0xff;
    data[AES67_SAP_MSG_ID_HASH+1] = packet.msg_id_hash & 0xff;

    u16_t len = AES67_SAP_ORIGIN_SRC;

    if ( packet.ip.ipver == aes67_net_ipver_4 ){
        std::memcpy(&data[AES67_SAP_ORIGIN_SRC], packet.ip.addr, 4);
        len += 4;
        data[AES67_SAP_STATUS] = (data[AES67_SAP_STATUS] & ~AES67_SAP_STATUS_ADDRTYPE_MASK) | AES67_SAP_STATUS_ADDRTYPE_IPv4;
    } else {
        std::memcpy(&data[AES67_SAP_ORIGIN_SRC], packet.ip.addr, 16);
        len += 16;
        data[AES67_SAP_STATUS] = (data[AES67_SAP_STATUS] & ~AES67_SAP_STATUS_ADDRTYPE_MASK) | AES67_SAP_STATUS_ADDRTYPE_IPv6;
    }

    if (packet.typelen > 0){

        std::memcpy(&data[len], packet.type, packet.typelen);
        len += packet.typelen;
    }

    std::memcpy(&data[len], packet.data, packet.datalen);

    len += packet.datalen;

    return len;
}

static struct {
    bool isset;
    enum aes67_sap_event event;
    struct aes67_sap_session * session;
    u8_t * payloadtype;
    u16_t payloadtypelen;
    u8_t * payload;
    u16_t payloadlen;
} sap_event;

inline void sap_event_reset()
{
    sap_event.isset = false;
}

static void sap_event_callback(enum aes67_sap_event event, struct aes67_sap_session * session, u8_t * payloadtype, u16_t payloadtypelen, u8_t * payload, u16_t payloadlen)
{
    CHECK_TRUE(AES67_SAP_EVENT_IS_VALID(event));
//    CHECK_TRUE(session != nullptr); // this is actually not always the case (if we've run out of memory)
    CHECK_TRUE(payloadtypelen > 0 || payloadtype == nullptr);
    CHECK_TRUE(payloadlen > 0 || payload == nullptr);

    sap_event.event = event;
    sap_event.session = session;

    sap_event.payloadtype = payloadtype;
    sap_event.payloadtypelen = payloadtypelen;
    sap_event.payload = payload;
    sap_event.payloadlen = payloadlen;

    sap_event.isset = true;
}

#if AES67_SAP_AUTH_ENABLED == 1

static enum aes67_sap_auth_result auth_result;

#define AUTH_OK()   auth_result = aes67_sap_auth_result_ok
#define AUTH_NOT_OK()   auth_result = aes67_sap_auth_result_not_ok

enum aes67_sap_auth_result aes67_sap_service_auth_validate(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen)
{
    return auth_result;
}

#else // not auth

#define AUTH_OK()
#define AUTH_NOT_OK()

#endif //AES67_SAP_AUTH_ENABLED == 1


#if AES67_SAP_AUTH_SELF == 1

u8_t aes67_sap_service_auth_add(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen, u16_t maxlen)
{
    CHECK_TRUE(sap != nullptr);
    CHECK_TRUE(msg != nullptr);

    uint16_t doffset;

    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4 ){
        doffset = AES67_SAP_ORIGIN_SRC + 4;
    } else {
        doffset = AES67_SAP_ORIGIN_SRC + 16;
    }

    CHECK_TRUE(doffset < msglen);

    // just the length of our dummy auth data
    const u16_t auth_len = sizeof("is authorized") / 4 + ((sizeof("is authorized") % 4 == 0) ? 0 : 1);

    CHECK_TRUE(msglen + 4*auth_len <= maxlen);

    std::memmove(&msg[doffset+auth_len], &msg[doffset], msglen - doffset);

    msg[AES67_SAP_AUTH_LEN] = auth_len;

    // return 0 on success
    return 0;
}

#endif //AES67_SAP_AUTH_SELF == 1


#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

static uint8_t * decompressed = nullptr;

u8_t * aes67_sap_zlib_decompress(struct aes67_sap_service * sap, u8_t * payload, u16_t * payloadlen)
{
    CHECK_TRUE(sap != nullptr);
    CHECK_TRUE(payload != nullptr);
    CHECK_TRUE(payloadlen != nullptr);

    // make sure the allocated memory pointer is always unoccupied (otherwise there is a leak problem)
    CHECK_TRUE(decompressed == nullptr);

    // just copy payload to another (dynamic allocated) memory location

    decompressed = (uint8_t*)std::malloc(*payloadlen);

    std::memcpy(decompressed, payload, *payloadlen);

    *payloadlen = *payloadlen; // remains unchanged

    return decompressed;
}

#ifndef aes67_sap_zlib_decompress_free
void aes67_sap_zlib_decompress_free(u8_t * payload)
{
    CHECK_TRUE(payload != nullptr);
    CHECK_EQUAL(decompressed, payload);

    std::free(payload);

    // set NULL to indicate that has been freed
    decompressed = nullptr;
}
#endif

#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 1


#if AES67_SAP_COMPRESS_ENABLED == 1

u16_t aes67_sap_zlib_compress(struct aes67_sap_service * sap, u8_t * payload, u16_t payloadlen, u16_t maxlen)
{
    CHECK_TRUE(sap != NULL);
    CHECK_TRUE(payload != NULL);
    CHECK_TRUE(payloadlen > 0);
//    CHECK_TRUE(maxlen <= payloadlen);

    // leave as is

    return payloadlen;
}

#endif //AES67_SAP_COMPRESS_ENABLED == 1

TEST_GROUP(SAP_TestGroup)
{
};


TEST(SAP_TestGroup, sap_handle_v2)
{
    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    // make sure the auth
    AUTH_OK();

    aes67_sap_service_init(&sap, sap_event_callback);

    // announce valid packet

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);

    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
#endif

    // re-announce the same packet (ie same msg hash id + originating source)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);


    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
    CHECK_EQUAL(aes67_sap_event_refreshed, sap_event.event); // different event
#endif

    // delete session
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };
    len = packet2mem(data, p2);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p2.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p2.data, sap_event.payload, p2.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_TRUE( sap_event.session == NULL );
#else
    CHECK_TRUE( sap_event.session != NULL );
#endif

    aes67_sap_service_deinit(&sap);
}

TEST(SAP_TestGroup, sap_handle_v1)
{
    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    // make sure the auth
    AUTH_OK();

    aes67_sap_service_init(&sap, sap_event_callback);

    // announce valid packet
    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            .typelen = 0,
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
#endif


    // re-announce the same packet (ie same msg hash id + originating source)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
    CHECK_EQUAL(aes67_sap_event_refreshed, sap_event.event); // different event
#endif

    // delete session with "o=" payload start
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            .typelen = 0,
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };
    len = packet2mem(data, p2);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p2.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p2.data, sap_event.payload, p2.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_TRUE( sap_event.session == NULL );
#else
    CHECK_TRUE( sap_event.session != NULL );
#endif


    // delete session with "v=0" payload start
    sap_packet_t p3 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            .typelen = 0,
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };
    len = packet2mem(data, p3);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL( NULL, sap_event.session ); // note, this session was not previously known
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p3.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p3.data, sap_event.payload, p3.datalen);



    // packets with zero msg id hash are ignored
    sap_packet_t p4 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 0,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            .typelen = 0,
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p4);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_FALSE(sap_event.isset);

    aes67_sap_service_deinit(&sap);
}

TEST(SAP_TestGroup, sap_handle_pooloverflow)
{
#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    TEST_EXIT
#else //AES67_SAP_MEMORY == AES67_MEMORY_POOL

    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    // make sure the auth
    AUTH_OK();

    aes67_sap_service_init(&sap, sap_event_callback);

    // announce valid packet

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 0,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };

    CHECK_EQUAL(0, sap.no_of_ads);

    // fill pool with quasi-identical session (hashes 1 - POOL_SIZE)
    for(int i = 0; i < AES67_SAP_MEMORY_POOL_SIZE; i++){
        p1.msg_id_hash++; // change hash
        len = packet2mem(data, p1);

        sap_event_reset();
        aes67_sap_service_handle(&sap, data, len);

        CHECK_TRUE(sap_event.isset);
        CHECK_TRUE( sap_event.session != NULL );
        CHECK_EQUAL(i+1, sap.no_of_ads);
    }

    CHECK_EQUAL(AES67_SAP_MEMORY_POOL_SIZE, sap.no_of_ads);

    // send another (unique) announce message
    p1.msg_id_hash++;
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(AES67_SAP_MEMORY_POOL_SIZE, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL( NULL, sap_event.session);

    // resend previous announce message again
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(AES67_SAP_MEMORY_POOL_SIZE, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event); // note: event != refreshed
    CHECK_TRUE( sap_event.session == NULL );

    // delete
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 0,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };


    // empty pool with quasi-identical session (hashes 1 - POOL_SIZE)
    for(int i = 0; i < AES67_SAP_MEMORY_POOL_SIZE; i++){
        p2.msg_id_hash++; // change hash
        len = packet2mem(data, p2);

        sap_event_reset();
        aes67_sap_service_handle(&sap, data, len);

        CHECK_TRUE(sap_event.isset);
        CHECK_EQUAL(AES67_SAP_MEMORY_POOL_SIZE-i-1, sap.no_of_ads);
        CHECK_TRUE( sap_event.session != NULL );
    }

    CHECK_EQUAL(0, sap.no_of_ads);


    // add a new session to make sure it's still possible
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#if AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
#else
    CHECK_EQUAL( 1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
#endif

    // resubmit (-> refresh event)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

    CHECK_TRUE(sap_event.isset);
#if AES67_SAP_MEMORY_POOL_SIZE == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_TRUE( sap_event.session == NULL );
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL( 1, sap.no_of_ads);
    CHECK_TRUE( sap_event.session != NULL );
    CHECK_EQUAL(aes67_sap_event_refreshed, sap_event.event);
#endif


    aes67_sap_service_deinit(&sap);
#endif
}

TEST(SAP_TestGroup, sap_handle_compressed)
{
    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    // make sure the auth
    AUTH_OK();

    aes67_sap_service_init(&sap, sap_event_callback);

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_ZLIB,
            .auth_len = 0,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

#if AES67_SAP_DECOMPRESS_AVAILABLE == 0
    CHECK_FALSE(sap_event.isset);
#else
    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);
#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 0

    aes67_sap_service_deinit(&sap);
}


TEST(SAP_TestGroup, sap_msg)
{
    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    u8_t opt = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
    u16_t hash = 1234;
    struct aes67_net_addr ip1 = {
            .ipver = aes67_net_ipver_4,
            .addr = {5,6,7,8}
    };

    struct aes67_sdp sdp;

    len = aes67_sap_service_msg(&sap, data, sizeof(data), opt, hash, &ip1,  &sdp);

    CHECK_TRUE(len > 0);



    aes67_sap_service_deinit(&sap);
}