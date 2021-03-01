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

#include "aes67/sap.h"

#include "stubs/host/time.h"
#include "stubs/host/timer.h"
#include <string>


typedef struct {
    uint8_t status;
    uint8_t auth_len;      // length(auth_data) == 4 * auth_len
    uint8_t authdata[256];
    uint16_t msg_id_hash;
    struct aes67_net_addr ip;
    uint16_t typelen;
    uint8_t type[32];
    uint16_t datalen;
    uint8_t data[256];
} sap_packet_t;

#define PACKET_AUTH(str)    .authdata = str, .auth_len = ((sizeof(str) - 1) / 4)
#define PACKET_AUTH_NONE    .auth_len = 0
#define PACKET_TYPE(str)    .type = str, .typelen = sizeof(str)
#define PACKET_TYPE_NONE    .typelen = 0
#define PACKET_DATA(str)    .data = str, .datalen = sizeof(str) - 1

static uint8_t gl_user_data[] = "this is userdata";
static void * expected_user_data = gl_user_data;

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
    u16_t hash;
    aes67_net_addr src;
    u8_t * payloadtype;
    u16_t payloadtypelen;
    u8_t * payload;
    u16_t payloadlen;
    void * user_data;
} sap_event;

inline void sap_event_reset()
{
    std::memset(&sap_event, 0, sizeof(sap_event));
}

void
aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                        enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype, u16_t payloadtypelen,
                        u8_t *payload, u16_t payloadlen, void *user_data)
{
    CHECK_TRUE(AES67_SAP_EVENT_IS_VALID(event));
//    CHECK_TRUE(session_data != nullptr); // this is actually not always the case (if we've run out of memory)
    CHECK_TRUE(payloadtypelen > 0 || payloadtype == nullptr);
    CHECK_TRUE(payloadlen > 0 || payload == nullptr);
    CHECK_EQUAL(gl_user_data, user_data);

    sap_event.event = event;

    sap_event.hash = hash;
    sap_event.src.ipver = ipver;
    std::memcpy(sap_event.src.addr, ip, AES67_NET_IPVER_SIZE(ipver));

    sap_event.payloadtype = payloadtype;
    sap_event.payloadtypelen = payloadtypelen;
    sap_event.payload = payload;
    sap_event.payloadlen = payloadlen;

    sap_event.user_data = user_data;

    sap_event.isset = true;
}

#if AES67_SAP_AUTH_ENABLED == 1

static enum aes67_sap_auth_result auth_result;

#define AUTH_OK()   auth_result = aes67_sap_auth_result_ok
#define AUTH_NOT_OK()   auth_result = aes67_sap_auth_result_not_ok

enum aes67_sap_auth_result
aes67_sap_service_auth_validate(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, void *user_data)
{
    CHECK_EQUAL(gl_user_data, user_data);

    return auth_result;
}

#else // not auth

#define AUTH_OK()
#define AUTH_NOT_OK()

#endif //AES67_SAP_AUTH_ENABLED == 1


#if AES67_SAP_AUTH_SELF == 1

static u8_t auth_data[] = {0x13,0x37,0xba,0xbe};

u8_t aes67_sap_service_auth_add(struct aes67_sap_service *sap, u8_t *msg, u16_t msglen, u16_t maxlen, void *user_data)
{
    CHECK_EQUAL(gl_user_data, user_data);

    // the basic assumption of the auth data used here
    assert(sizeof(auth_data) % 4 == 0);

    CHECK_TRUE(msg != nullptr);

    uint16_t doffset; // data offset

    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4 ){
        doffset = AES67_SAP_ORIGIN_SRC + 4;
    } else {
        doffset = AES67_SAP_ORIGIN_SRC + 16;
    }

    CHECK_TRUE(doffset < msglen);


    CHECK_TRUE(msglen + sizeof(auth_data) <= maxlen);

    std::memmove(&msg[doffset + sizeof(auth_data)], &msg[doffset], msglen - doffset);

    std::memcpy(&msg[doffset], auth_data, sizeof(auth_data));


    msg[AES67_SAP_AUTH_LEN] = sizeof(auth_data) / 4;

    // return 0 on success
    return 0;
}

#endif //AES67_SAP_AUTH_SELF == 1


#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

static uint8_t * decompressed = nullptr;

u8_t * aes67_sap_zlib_decompress(u8_t * payload, u16_t * payloadlen, void * user_data)
{
    CHECK_TRUE(payload != nullptr);
    CHECK_TRUE(payloadlen != nullptr);
    CHECK_EQUAL(gl_user_data, user_data);

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

u16_t aes67_sap_zlib_compress(u8_t * payload, u16_t payloadlen, u16_t maxlen, void * user_data)
{
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

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);

    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
#if AES67_SAP_AUTH_ENABLED
//    CHECK_EQUAL(aes67_sap_auth_result_not_ok, sap_event.session_data.authenticated);
#endif
    CHECK_EQUAL(p1.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p1.ip.ipver, sap_event.src.ipver );
    MEMCMP_EQUAL(p1.ip.addr, sap_event.src.addr, (AES67_NET_IPVER_SIZE(p1.ip.ipver)));
#endif

    // re-announce the same packet (ie same msg hash id + originating source)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

#if AES67_SAP_HASH_CHECK == 1
    CHECK_FALSE(sap_event.isset);
#else // AES67_SAP_HASH_CHECK == 0
    CHECK_TRUE(sap_event.isset);

    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_updated, sap_event.event); // different event
#endif
#endif// AES67_SAP_HASH_CHECK == 0

    // delete session_data
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p2.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p2.data, sap_event.payload, p2.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
#else
#if AES67_SAP_AUTH_ENABLED
//    CHECK_EQUAL(aes67_sap_auth_result_not_ok, sap_event.session_data.authenticated);
#endif
    CHECK_EQUAL(p2.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p2.ip.ipver, sap_event.src.ipver );
    MEMCMP_EQUAL(p2.ip.addr, sap_event.src.addr, (AES67_NET_IPVER_SIZE(p2.ip.ipver)));
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

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    // announce valid packet
    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL(0, sap.no_of_ads);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
#if AES67_SAP_AUTH_ENABLED
//    CHECK_EQUAL(aes67_sap_auth_result_not_ok, sap_event.session_data.authenticated);
#endif
    CHECK_EQUAL(p1.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p1.ip.ipver, sap_event.src.ipver );
    MEMCMP_EQUAL(p1.ip.addr, sap_event.src.addr, (AES67_NET_IPVER_SIZE(p1.ip.ipver)));
#endif


    // re-announce the same packet (ie same msg hash id + originating source)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);
#if AES67_SAP_HASH_CHECK == 1
    CHECK_FALSE(sap_event.isset);
#else // AES67_SAP_HASH_CHECK == 1
    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_updated, sap_event.event); // different event
#endif
#endif // AES67_SAP_HASH_CHECK == 1

    // delete session_data with "o=" payload start
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p2.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p2.data, sap_event.payload, p2.datalen);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    //
#else
#if AES67_SAP_AUTH_ENABLED
//    CHECK_EQUAL(aes67_sap_auth_result_not_ok, sap_event.session_data.authenticated);
#endif
    CHECK_EQUAL(p2.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p2.ip.ipver, sap_event.src.ipver );
    MEMCMP_EQUAL(p2.ip.addr, sap_event.src.addr, (AES67_NET_IPVER_SIZE(p2.ip.ipver)));
#endif


    // delete session_data with "v=0" payload start
    sap_packet_t p3 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_deleted, sap_event.event); // different event
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p3.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p3.data, sap_event.payload, p3.datalen);



    // packets with zero msg id hash are ignored
    sap_packet_t p4 = {
            .status = AES67_SAP_STATUS_VERSION_1 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_FALSE(sap_event.isset);

    aes67_sap_service_deinit(&sap);
}

TEST(SAP_TestGroup, sap_handle_pooloverflow)
{
#if AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC
    TEST_EXIT;
#else //AES67_SAP_MEMORY == AES67_MEMORY_POOL

    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    // make sure the auth
    AUTH_OK();

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    // announce valid packet

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH_NONE,
            .msg_id_hash = 0,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };

    CHECK_EQUAL(0, sap.no_of_ads);

    // fill pool with quasi-identical session_data (hashes 1 - POOL_SIZE)
    for(int i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        p1.msg_id_hash++; // change hash
        len = packet2mem(data, p1);

        sap_event_reset();
        aes67_sap_service_handle(&sap, data, len, gl_user_data);

        CHECK_TRUE(sap_event.isset);
        CHECK_EQUAL(i+1, sap.no_of_ads);
    }

    CHECK_EQUAL(AES67_SAP_MEMORY_MAX_SESSIONS, sap.no_of_ads);

    // send another (unique) announce message
    p1.msg_id_hash++;
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(AES67_SAP_MEMORY_MAX_SESSIONS, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);

    // resend previous announce message again
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(AES67_SAP_MEMORY_MAX_SESSIONS, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event); // note: event != refreshed

    // delete
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            .auth_len = 0,
            .msg_id_hash = 0,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };


    // empty pool with quasi-identical session_data (hashes 1 - POOL_SIZE)
    for(int i = 0; i < AES67_SAP_MEMORY_MAX_SESSIONS; i++){
        p2.msg_id_hash++; // change hash
        len = packet2mem(data, p2);

        sap_event_reset();
        aes67_sap_service_handle(&sap, data, len, gl_user_data);

        CHECK_TRUE(sap_event.isset);
        CHECK_EQUAL(AES67_SAP_MEMORY_MAX_SESSIONS-i-1, sap.no_of_ads);
    }

    CHECK_EQUAL(0, sap.no_of_ads);


    // add a new session_data to make sure it's still possible
    len = packet2mem(data, p1);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#if AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
#else
    CHECK_EQUAL( 1, sap.no_of_ads);
#if AES67_SAP_AUTH_ENABLED
//    CHECK_EQUAL(aes67_sap_auth_result_not_ok, sap_event.session_data.authenticated);
#endif
    CHECK_EQUAL(p1.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p1.ip.ipver, sap_event.src.ipver );
    MEMCMP_EQUAL(p1.ip.addr, sap_event.src.addr, (AES67_NET_IPVER_SIZE(p1.ip.ipver)));
#endif

    // resubmit (-> refresh event)
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

#if AES67_SAP_HASH_CHECK == 1
    CHECK_FALSE(sap_event.isset);
#else // AES67_SAP_HASH_CHECK == 0
    CHECK_TRUE(sap_event.isset);
#if AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_new, sap_event.event);
#else
    CHECK_EQUAL( 1, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_updated, sap_event.event);
#endif
#endif// AES67_SAP_HASH_CHECK == 0


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

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_ZLIB,
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
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

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


TEST(SAP_TestGroup, sap_handle_auth)
{
    struct aes67_sap_service sap;

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    uint8_t data[256];
    uint16_t len;

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH("1337cafe"),
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p1);


    AUTH_OK();

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && AES67_SAP_MEMORY_MAX_SESSIONS == 0
    CHECK_EQUAL(0, sap.no_of_ads);
#else
    CHECK_EQUAL(1, sap.no_of_ads);
#endif


    // identical to p1 (except for auth data now no auth data given)
    // ie, session MUST NOT be altered
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH_NONE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p2);

#if AES67_SAP_AUTH_ENABLED == 1
    AUTH_NOT_OK();

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_FALSE(sap_event.isset);
    CHECK_EQUAL(1, sap.no_of_ads);


    // trying unauthorized deletion of previously authenticated packet p1
    sap_packet_t p3 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH_NONE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };
    len = packet2mem(data, p3);

    AUTH_NOT_OK();

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_FALSE(sap_event.isset);
    CHECK_EQUAL(1, sap.no_of_ads);


    // trying unauthorized deletion of previously authenticated packet p1 (now with auth data)
    sap_packet_t p4 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_DELETE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH("deadbeef"),
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n")
    };
    len = packet2mem(data, p4);

    AUTH_NOT_OK();

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_FALSE(sap_event.isset);
    CHECK_EQUAL(1, sap.no_of_ads);


    // repeat but authorize message
    AUTH_OK();

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);

#endif //AES67_SAP_AUTH_ENABLED == 1

    aes67_sap_service_deinit(&sap);
}


TEST(SAP_TestGroup, sap_msg)
{
    struct aes67_sap_service sap;

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    struct aes67_sdp sdp = {
            .originator.username        = {0},
            .originator.session_id      = {1, "1"},
            .originator.session_version = {1, "2"},
            .originator.ipver    = aes67_net_ipver_4,
            .originator.address         = {8,"10.0.0.1"},
    };

    uint8_t data[1500];
    uint8_t sdp_data[1500];
    uint8_t origin_data[256];
    uint16_t len, sdp_len, origin_len;

    std::memset(sdp_data, 0, sizeof(sdp_data));
    sdp_len = aes67_sdp_tostr(sdp_data, sizeof(sdp_data), &sdp, NULL);

    assert(sdp_len > 0);

    std::memset(origin_data, 0, sizeof(origin_data));
    origin_len = aes67_sdp_origin_tostr(origin_data, sizeof(origin_data), &sdp.originator);

    assert(origin_len > 0);

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5,6,7,8}
            }
    };

    std::memset(data, 0, sizeof(data));
    len = aes67_sap_service_msg_sdp(&sap, data, sizeof(data), p1.status, p1.msg_id_hash, &p1.ip, &sdp, gl_user_data);

    assert(len > 0);

    CHECK_EQUAL(AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p1.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN] + sizeof(AES67_SDP_MIMETYPE) + sdp_len, len);
    CHECK_EQUAL(AES67_SAP_STATUS_VERSION_2, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_VERSION_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_MSGTYPE_ANNOUNCE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ADDRTYPE_IPv4, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK);
    CHECK_EQUAL(0, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_RESERVED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_COMPRESSED_NONE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ENCRYPTED_NO, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ENCRYPTED_MASK);
#if AES67_SAP_AUTH_SELF == 0
    CHECK_EQUAL(0, data[AES67_SAP_AUTH_LEN]);
#else
    CHECK_TRUE(0 < data[AES67_SAP_AUTH_LEN]);
    MEMCMP_EQUAL(auth_data, &data[AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p1.ip.ipver))], 4*data[AES67_SAP_AUTH_LEN]);
#endif
    CHECK_EQUAL(p1.msg_id_hash, ntohs(*(uint16_t*)&data[AES67_SAP_MSG_ID_HASH]));
    MEMCMP_EQUAL(p1.ip.addr, &data[AES67_SAP_ORIGIN_SRC], AES67_NET_IPVER_SIZE(p1.ip.ipver));

    int pos = AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p1.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN];
    STRCMP_EQUAL(AES67_SDP_MIMETYPE, (const char *)&data[pos]);

    MEMCMP_EQUAL(&data[pos + sizeof(AES67_SDP_MIMETYPE)], sdp_data, sdp_len);


    // test with ipv6
    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_6,
                    .addr = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
            }
    };


    std::memset(data, 0, sizeof(data));
    len = aes67_sap_service_msg_sdp(&sap, data, sizeof(data), p2.status, p2.msg_id_hash, &p2.ip, &sdp, gl_user_data);

    assert(len > 0);

    CHECK_EQUAL(AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p2.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN] + sizeof(AES67_SDP_MIMETYPE) + sdp_len, len);
    CHECK_EQUAL(AES67_SAP_STATUS_VERSION_2, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_VERSION_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_MSGTYPE_ANNOUNCE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ADDRTYPE_IPv6, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK);
    CHECK_EQUAL(0, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_RESERVED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_COMPRESSED_NONE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ENCRYPTED_NO, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ENCRYPTED_MASK);
#if AES67_SAP_AUTH_SELF == 0
    CHECK_EQUAL(0, data[AES67_SAP_AUTH_LEN]);
#else
    CHECK_TRUE(0 < data[AES67_SAP_AUTH_LEN]);
    MEMCMP_EQUAL(auth_data, &data[AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p2.ip.ipver))], 4*data[AES67_SAP_AUTH_LEN]);
#endif
    CHECK_EQUAL(p2.msg_id_hash, ntohs(*(uint16_t*)&data[AES67_SAP_MSG_ID_HASH]));
    MEMCMP_EQUAL(p2.ip.addr, &data[AES67_SAP_ORIGIN_SRC], AES67_NET_IPVER_SIZE(p2.ip.ipver));

    pos = AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p2.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN];
    STRCMP_EQUAL(AES67_SDP_MIMETYPE, (const char *)&data[pos]);

    MEMCMP_EQUAL(&data[pos + sizeof(AES67_SDP_MIMETYPE)], sdp_data, sdp_len);

    // delete test
    sap_packet_t p3 = {
            .status = AES67_SAP_STATUS_MSGTYPE_DELETE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5,6,7,8}
            }
    };

    std::memset(data, 0, sizeof(data));
    len = aes67_sap_service_msg_sdp(&sap, data, sizeof(data), p3.status, p3.msg_id_hash, &p3.ip, &sdp, gl_user_data);

    assert(len > 0);

    CHECK_EQUAL(AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p3.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN] + sizeof(AES67_SDP_MIMETYPE) + origin_len, len);
    CHECK_EQUAL(AES67_SAP_STATUS_VERSION_2, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_VERSION_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_MSGTYPE_DELETE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_MSGTYPE_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ADDRTYPE_IPv4, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK);
    CHECK_EQUAL(0, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_RESERVED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_COMPRESSED_NONE, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_COMPRESSED_MASK);
    CHECK_EQUAL(AES67_SAP_STATUS_ENCRYPTED_NO, data[AES67_SAP_STATUS] & AES67_SAP_STATUS_ENCRYPTED_MASK);
#if AES67_SAP_AUTH_SELF == 0
    CHECK_EQUAL(0, data[AES67_SAP_AUTH_LEN]);
#else
    CHECK_TRUE(0 < data[AES67_SAP_AUTH_LEN]);
    MEMCMP_EQUAL(auth_data, &data[AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p1.ip.ipver))], 4*data[AES67_SAP_AUTH_LEN]);
#endif
    CHECK_EQUAL(p3.msg_id_hash, ntohs(*(uint16_t*)&data[AES67_SAP_MSG_ID_HASH]));
    MEMCMP_EQUAL(p3.ip.addr, &data[AES67_SAP_ORIGIN_SRC], AES67_NET_IPVER_SIZE(p1.ip.ipver));

    pos = AES67_SAP_ORIGIN_SRC + (AES67_NET_IPVER_SIZE(p3.ip.ipver)) + 4*data[AES67_SAP_AUTH_LEN];
    STRCMP_EQUAL(AES67_SDP_MIMETYPE, (const char *)&data[pos]);

    MEMCMP_EQUAL(&data[pos + sizeof(AES67_SDP_MIMETYPE)], origin_data, origin_len);


    aes67_sap_service_deinit(&sap);
}


TEST(SAP_TestGroup, sap_announcement_timer)
{
    struct aes67_sap_service sap;

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    CHECK_FALSE(aes67_sap_service_announcement_timer_state(&sap));
    CHECK_EQUAL(0, sap.announcement_sec);
    CHECK_FALSE(aes67_sap_service_announcement_timer_state(&sap));


    // as there is no prior announcement, timer will not be set
    aes67_sap_service_set_announcement_timer(&sap);

    CHECK_EQUAL(aes67_timer_state_unset, aes67_timer_getstate(&sap.announcement_timer));

//    u8_t msg[256];
//
//    aes67_sap_service_msg(&sap, msg, sizeof(msg), AES67_SAP_STATUS_MSGTYPE_ANNOUNCE, 4, aes67_net_ipver_4, (u8_t*)"\x01\x02\x03\x04", (u8_t*)"asdf", 5, NULL);
//
//    // this should trigger the timer to be called as soon as possible.
//    aes67_sap_service_set_announcement_timer(&sap);
//
//    CHECK_EQUAL(aes67_timer_state_set, aes67_timer_getstate(&sap.announcement_timer));
//    CHECK_EQUAL(AES67_TIMER_NOW , timer_gettimeout(&sap.announcement_timer));
//
//    // ASYNC expire timer
//    timer_expire(&sap.announcement_timer);
//
//    CHECK_TRUE(aes67_sap_service_announcement_timer_state(&sap));
//
//    // clear timer -> now we would sent a timer
//    aes67_timer_unset(&sap.announcement_timer);
//
//    CHECK_FALSE(aes67_sap_service_announcement_timer_state(&sap));


    struct aes67_sdp sdp = {
            .originator.username        = {0},
            .originator.session_id      = {1, "1"},
            .originator.session_version = {1, "2"},
            .originator.ipver    = aes67_net_ipver_4,
            .originator.address         = {8,"10.0.0.1"},
    };

    uint8_t data[1500];
    uint16_t len;

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5,6,7,8}
            }
    };

    std::memset(data, 0, sizeof(data));

    sap_event_reset();

    CHECK_EQUAL(false, sap_event.isset);

    len = aes67_sap_service_msg_sdp(&sap, data, sizeof(data), p1.status, p1.msg_id_hash, &p1.ip, &sdp, gl_user_data);

    CHECK_EQUAL(len, sap.announcement_size);

    CHECK_FALSE(aes67_sap_service_announcement_timer_state(&sap));

    // the module assumes a packet is sent after creating it
    // thus the announcement time has changed (when times have been updates)

    aes67_sap_service_update_times(&sap);

    CHECK_COMPARE(0, <, sap.announcement_sec);

    // this should trigger the timer to be called as soon as possible.
    aes67_sap_service_set_announcement_timer(&sap);

    CHECK_EQUAL(aes67_timer_state_set, aes67_timer_getstate(&sap.announcement_timer));
    CHECK_COMPARE(0 , <, timer_gettimeout(&sap.announcement_timer));

    aes67_sap_service_announcement_check(&sap, gl_user_data);

    CHECK_EQUAL(false, sap_event.isset);
    CHECK_EQUAL(aes67_timer_state_set, aes67_sap_service_announcement_timer_state(&sap));


    time_add_now_ms(1000*sap.announcement_sec);

    timer_expire(&sap.announcement_timer);

    CHECK_EQUAL(aes67_timer_state_expired,aes67_sap_service_announcement_timer_state(&sap));

    aes67_sap_service_announcement_check(&sap, gl_user_data);

    CHECK_EQUAL(aes67_timer_state_unset,aes67_sap_service_announcement_timer_state(&sap));

    CHECK_EQUAL(true, sap_event.isset);
    CHECK_EQUAL(aes67_sap_event_announcement_request, sap_event.event);
    CHECK_EQUAL(p1.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p1.ip.ipver, sap_event.src.ipver);
    MEMCMP_EQUAL(p1.ip.addr, sap_event.src.addr, AES67_NET_IPVER_SIZE(p1.ip.ipver));


    aes67_sap_service_deinit(&sap);
}


TEST(SAP_TestGroup, sap_timeouts)
{
    // timeouts only exist for internally managed sessions, if there are none, this does not work in the first place
#if AES67_SAP_MEMORY == AES67_MEMORY_POOL && 0 == AES67_SAP_MEMORY_MAX_SESSIONS
    TEST_EXIT;
#else
    struct aes67_sap_service sap;

    aes67_sap_service_init(&sap);
    expected_user_data = gl_user_data;

    // make sure to authenticate all messages
    AUTH_OK();


    CHECK_COMPARE(0, <, sap.timeout_sec);
    CHECK_EQUAL(aes67_timer_state_unset, aes67_sap_service_timeout_timer_state(&sap));


    uint8_t data[256];
    uint16_t len;

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH_NONE,
            .msg_id_hash = 1234,
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p1);

    aes67_time_t t1b, t1a; // before/after timestamps
    aes67_time_now(&t1b);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    aes67_time_now(&t1a);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(1, sap.no_of_ads);
    // t1a < p1.last_announcement < t1b
//    CHECK_COMPARE(0, <, aes67_time_diffmsec(&t1b, &sap_event.session_data.last_announcement));
//    CHECK_COMPARE(0, <, aes67_time_diffmsec(&sap_event.session_data.last_announcement, &t1a));

    sap_packet_t p2 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_NONE,
            PACKET_AUTH_NONE,
            .msg_id_hash = 12345, // another hash!
            .ip = {
                    .ipver = aes67_net_ipver_4,
                    .addr = {5, 6, 7, 8},
            },
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };
    len = packet2mem(data, p2);

    aes67_time_t t2b, t2a; // before/after timestamps
    aes67_time_now(&t2b);

    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    aes67_time_now(&t2a);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(2, sap.no_of_ads);

    // t1b < t2b < p2.last_announcement < t2a
    CHECK_COMPARE(0, <, aes67_time_diffmsec(&t1a, &t2b));
//    CHECK_COMPARE(0, <, aes67_time_diffmsec(&t2b, &sap_event.session_data.last_announcement));
//    CHECK_COMPARE(0, <, aes67_time_diffmsec(&sap_event.session_data.last_announcement, &t2a));


    CHECK_EQUAL(aes67_timer_state_unset, aes67_sap_service_timeout_timer_state(&sap));

    aes67_sap_service_set_timeout_timer(&sap);

    // this should not fail (depends on timer implementation)
    CHECK_EQUAL(aes67_timer_state_set, aes67_sap_service_timeout_timer_state(&sap));

    // try to clean up timeouts (timeout should not have happened yet)
    sap_event_reset();
    aes67_sap_service_timeouts_cleanup(&sap, gl_user_data);

    CHECK_EQUAL(aes67_timer_state_set, aes67_sap_service_timeout_timer_state(&sap));
    CHECK_FALSE(sap_event.isset);
    CHECK_EQUAL(2, sap.no_of_ads);

    // let time go beyond timeout
    time_add_now_ms(1000*sap.timeout_sec);
    timer_expire(&sap.timeout_timer);

    CHECK_EQUAL(aes67_timer_state_expired,aes67_sap_service_timeout_timer_state(&sap));

    sap_event_reset();
    aes67_sap_service_timeouts_cleanup(&sap, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL( 0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_timeout, sap_event.event);



    // now let's add two packets, and timeout only one thereof

    len = packet2mem(data, p1);
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    // step half a timeout into the future
    time_add_now_ms(500*sap.timeout_sec);

    CHECK_EQUAL(1, sap.no_of_ads);

    len = packet2mem(data, p2);
    aes67_sap_service_handle(&sap, data, len, gl_user_data);

    CHECK_EQUAL(2, sap.no_of_ads);

    sap_event_reset();
    aes67_sap_service_timeouts_cleanup(&sap, gl_user_data);

    CHECK_FALSE(sap_event.isset);
    CHECK_EQUAL(2, sap.no_of_ads);

    // step another half a timeout into the future
    time_add_now_ms(500*sap.timeout_sec);

    // and
    sap_event_reset();
    aes67_sap_service_timeouts_cleanup(&sap, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(1, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_timeout, sap_event.event);
    CHECK_EQUAL(p1.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p1.ip.ipver, sap_event.src.ipver);
    MEMCMP_EQUAL(p1.ip.addr, sap_event.src.addr, AES67_NET_IPVER_SIZE(p1.ip.ipver));


    // step another half a timeout into the future
    time_add_now_ms(500*sap.timeout_sec);

    // and
    sap_event_reset();
    aes67_sap_service_timeouts_cleanup(&sap, gl_user_data);

    CHECK_TRUE(sap_event.isset);
    CHECK_EQUAL(0, sap.no_of_ads);
    CHECK_EQUAL(aes67_sap_event_timeout, sap_event.event);
    CHECK_EQUAL(p2.msg_id_hash, sap_event.hash);
    CHECK_EQUAL(p2.ip.ipver, sap_event.src.ipver);
    MEMCMP_EQUAL(p2.ip.addr, sap_event.src.addr, AES67_NET_IPVER_SIZE(p2.ip.ipver));


    aes67_sap_service_deinit(&sap);

#endif //AES67_SAP_MEMORY == AES67_MEMORY_DYNAMIC || 0 < AES67_SAP_MEMORY_MAX_SESSIONS
}