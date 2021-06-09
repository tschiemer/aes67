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

#include <aes67/debug.h>
#include <aes67/eth.h>
#include <aes67/def.h>

u16_t aes67_ipv4_header_checksum(u8_t * header)
{
    int len = (header[AES67_IPV4_HEADER_IHL_OFFSET] & AES67_IPV4_HEADER_IHL_MASK) << 1;
    return aes67_16bit_ones_complement_sum(header, len, 0);
}

u16_t aes67_udp_checksum(u8_t * ip_header)
{
    // ipv4
    if ((ip_header[AES67_IPV4_HEADER_VERSION_OFFSET] & AES67_IPV4_HEADER_VERSION_MASK) == AES67_IPV4_HEADER_VERSION_4){

        // total ip packet length
        u16_t tlen = aes67_ntohs(*(u16_t*)(ip_header + AES67_IPV4_HEADER_LENGTH_OFFSET));

        u16_t iphdrlen = ((ip_header[AES67_IPV4_HEADER_IHL_OFFSET] & AES67_IPV4_HEADER_IHL_MASK) << 2);

        // udp header + body length
        u16_t udplen = tlen - iphdrlen;

        printf("tlen = %d, iplen = %d, udplen = %d\n", tlen, iphdrlen, udplen);

        // save ttl/checksum and set to pseudo header values
        u8_t ttl = ip_header[AES67_IPV4_HEADER_TTL_OFFSET];
        u16_t header_checksum = *(u16_t*)(ip_header + AES67_IPV4_HEADER_HEADER_CHECKSUM_OFFSET);

        ip_header[AES67_IPV4_HEADER_TTL_OFFSET] = 0;
        *(u16_t*)(ip_header + AES67_IPV4_HEADER_HEADER_CHECKSUM_OFFSET) = aes67_htons(udplen);

        // partial checksum of (pseudo-)header (6 short := 12 octets)
        u16_t checksum = aes67_16bit_ones_complement_sum(ip_header + AES67_IPV4_HEADER_TTL_OFFSET, 6, 0);

        // restore original ipv4 header
        ip_header[AES67_IPV4_HEADER_TTL_OFFSET] = ttl;
        *(u16_t*)(ip_header + AES67_IPV4_HEADER_HEADER_CHECKSUM_OFFSET) = header_checksum;

        // sum of udp (we have to take into account any potential optional ipv4 headers, otherwise we could just go over all at once..)

        checksum = aes67_16bit_ones_complement_sum(ip_header + iphdrlen, udplen >> 1, ~checksum );

        return checksum;
    }

    // ipv6
    if ((ip_header[AES67_IPV4_HEADER_VERSION_OFFSET] & AES67_IPV4_HEADER_VERSION_MASK) == AES67_IPV4_HEADER_VERSION_6){
        // TODO
    }

    AES67_ASSERT("invalid ip header version", 0);
}