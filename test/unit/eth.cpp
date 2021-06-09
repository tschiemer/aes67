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

#include "aes67/eth.h"

TEST_GROUP(Eth_TestGroup){};

TEST(Eth_TestGroup, eth_ipv4_header_checksum) {

    // test value from https://en.wikipedia.org/wiki/IPv4_header_checksum

    // without checksum
    uint8_t ip1[] = {
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
            0, 0, // checksum
            0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7, // end of header
            0x00, 0x35, 0xe9, 0x7c, 0x00, 0x5f, 0x27, 0x9f, 0x1e, 0x4b, 0x81, 0x80
    };

    u16_t ck = aes67_ipv4_header_checksum(ip1);

    CHECK_EQUAL(0xb861, ck);

    // same WITH checksum
    uint8_t ip2[] = {
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40,
            0x11, 0xb8, // checksum
            0x61, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7, // end of header
            0x00, 0x35, 0xe9, 0x7c, 0x00, 0x5f, 0x27, 0x9f, 0x1e, 0x4b, 0x81, 0x80
    };

    ck = aes67_ipv4_header_checksum(ip2);

    CHECK_EQUAL(0x0000, ck);
}