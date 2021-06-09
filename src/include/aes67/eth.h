/**
 * @file eth.h
 * Lower level networking utilities, ethernet, ip, udp.
 *
 * References:
 * AES67-2018 https://www.aes.org/publications/standards/search.cfm?docID=96
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

#ifndef AES67_ETH_H
#define AES67_ETH_H

#include "aes67/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

//#define AES67_ETH_HEADER_DST    0
//#define AES67_ETH_HEADER_SRC    6
//#define

#define AES67_ETH_ETHERTYPE_IPv4        0x0800
#define AES67_ETH_ETHERTYPE_ARP         0x0806  // address resolution protocol
#define AES67_ETH_ETHERTYPE_AVTP        0x22f0  // audio video transport protocol
#define AES67_ETH_ETHERTYPE_SRP         0x22ea  // stream reservation protocol
#define AES67_ETH_ETHERTYPE_IPv6        0x86dd
#define AES67_ETH_ETHERTYPE_VLAN_TAG    0x8100
#define AES67_ETH_ETHERTYPE_IPv6        0x86dd
#define AES67_ETH_ETHERTYPE_CobraNet    0x8819

//#define AES67_ETH_CRC32_POLY            0x04c11db7
//#define AES67_ETH_CRC32_INITIAL         0xffffffff

#define AES67_IPV4_HEADER_MINSIZE                   20

#define AES67_IPV4_HEADER_VERSION_OFFSET            0
#define AES67_IPV4_HEADER_VERSION_MASK              0xf0
#define AES67_IPV4_HEADER_IHL_OFFSET                0
#define AES67_IPV4_HEADER_IHL_MASK                  0x0f
#define AES67_IPV4_HEADER_DSCP_OFFSET               1  // Differentiated Services Code Point (DiffServ)
#define AES67_IPV4_HEADER_DSCP_MASK                 0b11111100
#define AES67_IPV4_HEADER_ECN_OFFSET                1        // Explicit Congestion Notification
#define AES67_IPV4_HEADER_ECN_MASK                  0b11
#define AES67_IPV4_HEADER_LENGTH_OFFSET             2
#define AES67_IPV4_HEADER_IDENTIFICATION_OFFSET     4
#define AES67_IPV4_HEADER_FRAGMENTATION_OFFSET      6
#define AES67_IPV4_HEADER_FRAGMENTATION_FLAGS_MASK  0b1110000000000000
#define AES67_IPV4_HEADER_FRAGMENTATION_FOFFSET_MASK    0b000111111111111
#define AES67_IPV4_HEADER_TTL_OFFSET                8
#define AES67_IPV4_HEADER_PROTOCOL_OFFSET           9
#define AES67_IPV4_HEADER_HEADER_CHECKSUM_OFFSET    10
#define AES67_IPV4_HEADER_SOURCE_OFFSET             12
#define AES67_IPV4_HEADER_DESTINATION_OFFSET        16
#define AES67_IPV4_HEADER_DATA_OFFSET               20  // assuming IHL == 5 (ie no extra headers)

#define AES67_IPV4_HEADER_VERSION_4                 0x40
#define AES67_IPV4_HEADER_VERSION_6                 0x60
#define AES67_IPV4_HEADER_IHL_BASIC                 0x05

#define AES67_IPV4_HEADER_DSCP_DEFAULT              0
#define AES67_IPV4_HEADER_DSCP_DEFAULT_CLOCK        (46<<2)     // Class EF
#define AES67_IPV4_HEADER_DSCP_DEFAULT_MEDIA        (34<<2)     // Class AF41

#define AES67_IPV4_HEADER_ECN_NON_ECT               0   // Non ECN capable transport
#define AES67_IPV4_HEADER_ECN_ECT0                  1   // ECN capable transport 0
#define AES67_IPV4_HEADER_ECN_ECT1                  2   // ECN capable transport 1
#define AES67_IPV4_HEADER_ECN_CE                    3   // Congestion encountered


#define AES67_IPV4_HEADER_FRAGMENTATION_FLAGS_DF    0b0100000000000000  // don't fragment
#define AES67_IPV4_HEADER_FRAGMENTATION_FLAGS_MF    0b0010000000000000  // more fragments

#define AES67_IPV4_HEADER_PROTOCOL_ICMP             0x01
#define AES67_IPV4_HEADER_PROTOCOL_IGMP             0x02
#define AES67_IPV4_HEADER_PROTOCOL_TCP              0x06
#define AES67_IPV4_HEADER_PROTOCOL_UDP              0x11
#define AES67_IPV4_HEADER_PROTOCOL_RSVP             0x2e

// No 802.1Q headers
struct aes67_eth_frame {
    u8_t destination[6];
    u8_t source[6];
    u8_t tpid[2];
    u16_t length;
    u8_t data[];
} PACK_STRUCT;


struct aes67_ipv4_packet {
    u8_t byte0;             // version + IHL
    u8_t byte1;             // DSCP + ECN
    u16_t length;           // total packet size (header + data, >= 20)
    u16_t identification;   // fragmentation identification
    u16_t fragmentation;    // flags + offset
    u8_t ttl;               // time to live
    u8_t protocol;          //
    u16_t header_checksum;  // The checksum field is the 16-bit ones' complement of the ones' complement sum of all
                            // 16-bit words in the header. For purposes of computing the checksum, the value of the
                            // checksum field is zero.
    union {
        u8_t bytes[4];
        u32_t value;
    } PACK_STRUCT source;
    union {
        u8_t bytes[4];
        u32_t value;
    } PACK_STRUCT destination;
    u8_t data[];
} PACK_STRUCT;

struct aes67_udp_packet {
    u16_t source_port;
    u16_t destination_port;
    u16_t length;
    u16_t checksum;
    u8_t data[];
} PACK_STRUCT;

struct aes67_udp_ipv4_pseudoheader {
    union {
        u8_t bytes[4];
        u32_t value;
    } PACK_STRUCT source;
    union {
        u8_t bytes[4];
        u32_t value;
    } PACK_STRUCT destination;
    u8_t zeroes;
    u8_t protocol;
    u16_t udp_length;
    struct aes67_udp_packet udp;
};


u16_t aes67_ipv4_header_checksum(u8_t * header);

u16_t aes67_udp_checksum(u8_t * ip_header);

#ifdef __cplusplus
}
#endif

#endif //AES67_ETH_H
