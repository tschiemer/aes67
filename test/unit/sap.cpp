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
#include <cassert>

#include "aes67/sap.h"

typedef struct {
    uint8_t status;
    uint8_t auth_len;      // length(auth_data) == 4 * auth_len
    uint16_t msg_id_hash;
    uint8_t ip[16];
    uint16_t typelen;
    uint8_t type[32];
    uint16_t datalen;
    uint8_t data[256];
} sap_packet_t;

#define PACKET_TYPE(str) .type = str, .typelen = sizeof(str)
#define PACKET_DATA(str) .data = str, .datalen = sizeof(str) - 1

static u16_t packet2mem(uint8_t data[], sap_packet_t & packet)
{
    data[AES67_SAP_STATUS] = packet.status;
    data[AES67_SAP_AUTH_LEN] = packet.auth_len;
    data[AES67_SAP_MSG_ID_HASH] = (packet.msg_id_hash >> 8) & 0xff;
    data[AES67_SAP_MSG_ID_HASH+1] = packet.msg_id_hash & 0xff;

    u16_t len = AES67_SAP_ORIGIN_SRC;

    if ( (packet.status & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4){
        std::memcpy(&data[AES67_SAP_ORIGIN_SRC], packet.ip, 4);
        len += 4;
    } else {
        std::memcpy(&data[AES67_SAP_ORIGIN_SRC], packet.ip, 16);
        len += 16;
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

inline bool sap_event_isset()
{
    return sap_event.isset;
}

static void sap_event_callback(enum aes67_sap_event event, struct aes67_sap_session * session, u8_t * payloadtype, u16_t payloadtypelen, u8_t * payload, u16_t payloadlen)
{
    assert(event);
    assert(session != nullptr);
    assert(payloadtypelen == 0 || payloadtype == nullptr);
    assert(payloadlen == 0 || payload == nullptr);

    sap_event.event = event;
    sap_event.session = session;

    sap_event.payloadtype = payloadtype;
    sap_event.payloadtypelen = payloadtypelen;
    sap_event.payload = payload;
    sap_event.payloadlen = payloadlen;

    sap_event.isset = true;
}

#if AES67_SAP_AUTH_ENABLED == 1

enum aes67_sap_auth_result aes67_sap_service_auth_validate(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen)
{

}

#endif //AES67_SAP_AUTH_ENABLED == 1


#if AES67_SAP_AUTH_SELF == 1

u8_t aes67_sap_service_auth_add(struct aes67_sap_service * sap, u8_t * msg, u16_t msglen, u16_t maxlen)
{
    assert(sap != nullptr);
    assert(msg != nullptr);

    uint16_t doffset;

    if ( (msg[AES67_SAP_STATUS] & AES67_SAP_STATUS_ADDRTYPE_MASK) == AES67_SAP_STATUS_ADDRTYPE_IPv4 ){
//        doffset
    }
}

#endif //AES67_SAP_AUTH_SELF == 1


#if AES67_SAP_DECOMPRESS_AVAILABLE == 1

static uint8_t * decompressed = nullptr;

u8_t * aes67_sap_zlib_decompress(struct aes67_sap_service * sap, u8_t * payload, u16_t * payloadlen)
{
    assert(sap != nullptr);
    assert(payload != nullptr);
    assert(payloadlen != nullptr);

    // make sure the allocated memory pointer is always unoccupied (otherwise there is a leak problem)
    assert(decompressed == nullptr);

    // just copy payload to another (dynamic allocated) memory location

    decompressed = (uint8_t*)std::malloc(*payloadlen);

    std::memcpy(decompressed, payload, *payloadlen);

    *payloadlen = *payloadlen; // remains unchanged

    return decompressed;
}

#ifndef aes67_sap_zlib_decompress_free
void aes67_sap_zlib_decompress_free(u8_t * payload)
{
    assert(payload != nullptr);
    assert(payload == decompressed);

    std::free(payload);

    // set NULL to indicate that has been freed
    decompressed = nullptr;
}
#endif

#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 1


#if AES67_SAP_COMPRESS_ENABLED == 1

u16_t aes67_sap_zlib_compress(struct aes67_sap_service * sap, u8_t * payload, u16_t payloadlen, u16_t maxlen)
{
    assert(sap != NULL);
    assert(payload != NULL);
    assert(payloadlen > 0);
//    assert(maxlen <= payloadlen);

    // leave as is

    return payloadlen;
}

#endif //AES67_SAP_COMPRESS_ENABLED == 1

TEST_GROUP(SAP_TestGroup)
{
};


TEST(SAP_TestGroup, sap_decompress)
{
    struct aes67_sap_service sap;

    uint8_t data[256];
    uint16_t len;

    aes67_sap_service_init(&sap, sap_event_callback);

    sap_packet_t p1 = {
            .status = AES67_SAP_STATUS_VERSION_2 | AES67_SAP_STATUS_MSGTYPE_ANNOUNCE | AES67_SAP_STATUS_ADDRTYPE_IPv4 | AES67_SAP_STATUS_ENCRYPTED_NO | AES67_SAP_STATUS_COMPRESSED_ZLIB,
            .auth_len = 0,
            .msg_id_hash = 0x1234,
            .ip = {5,6,7,8},
            PACKET_TYPE("application/sdp"),
            PACKET_DATA("v=0\r\no=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\ns=SDP Seminar\r\nc=IN IP4 224.2.17.12/127\r\nm=audio 49170 RTP/AVP 0\r\n")
    };

    len = packet2mem(data, p1);
    sap_event_reset();
    aes67_sap_service_handle(&sap, data, len);

#if AES67_SAP_DECOMPRESS_AVAILABLE == 0
    CHECK_FALSE(sap_event_isset());
#else
    CHECK_TRUE(sap_event_isset());
    CHECK_EQUAL(0, sap_event.payloadtypelen);
    CHECK_EQUAL(NULL, sap_event.payloadtype);
    CHECK_EQUAL(p1.datalen, sap_event.payloadlen);
    MEMCMP_EQUAL(p1.data, sap_event.payload, p1.datalen);
#endif //AES67_SAP_DECOMPRESS_AVAILABLE == 0
}