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

#include "aes67/net.h"

TEST_GROUP(Net_TestGroup)
        {
        };

#define RESET_ADDR(addr) std::memset(&addr, 0, sizeof(aes67_net_addr))
#define IPSTRLEN(cstr) (uint8_t*)(cstr), sizeof(cstr)-1

TEST(Net_TestGroup, str2addr_ipv4)
{
    aes67_net_addr addr;

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00", addr.addr, 4);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("255.255.255.255")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\xFF\xFF\xFF\xFF", addr.addr, 4);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1.2.3.4")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x01\x02\x03\x04", addr.addr, 4);


    RESET_ADDR(addr);

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.256")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.256.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.256.0.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("256.0.0.0")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.-1")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.-1.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.-1.0.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("-1.0.0.0")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0.0")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN(" 0.0.0.0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0 ")));


    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0:123")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(123, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00", addr.addr, 4);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("255.255.255.255:456")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(456, addr.port);
    MEMCMP_EQUAL("\xFF\xFF\xFF\xFF", addr.addr, 4);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1.2.3.4:789")));
    CHECK_EQUAL(aes67_net_ipver_4, addr.ipver);
    CHECK_EQUAL(789, addr.port);
    MEMCMP_EQUAL("\x01\x02\x03\x04", addr.addr, 4);


    RESET_ADDR(addr);

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0:")));

    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0:0")));
    CHECK_EQUAL(0, addr.port);

    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0:65535")));
    CHECK_EQUAL(0xFFFF, addr.port);

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0.0.0.0:65536")));
}


TEST(Net_TestGroup, str2addr_ipv6)
{
    aes67_net_addr addr;

#if AES67_USE_IPv6 == 0

    // make sure that the most simple ipv6 address fails

    RESET_ADDR(addr);
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:0")));

#else // AES67_USE_IPv6 == 1

    // basic format

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:0")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1:2:3:4:5:6:7:8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("100:200:300:400:500:600:700:800")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00", addr.addr, 16);



    // double colon syntax

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("::")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("::1")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1::")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("0::0")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1::8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1::7:8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1::3:4:5:6:7:8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x00\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1:2::8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("1:2:3:4:5:6::8")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x00\x00\x08", addr.addr, 16);


   // bracket format

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[::]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[::1]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[1::]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[1:2:3:4:5:6:7:8]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[100:200:300:400:500:600:700:800]")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(0, addr.port);
    MEMCMP_EQUAL("\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00", addr.addr, 16);


    // ports

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:123")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(123, addr.port);
    MEMCMP_EQUAL("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:456")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(456, addr.port);
    MEMCMP_EQUAL("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", addr.addr, 16);

    RESET_ADDR(addr);
    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[1:2:3:4:5:6:7:8]:789")));
    CHECK_EQUAL(aes67_net_ipver_6, addr.ipver);
    CHECK_EQUAL(789, addr.port);
    MEMCMP_EQUAL("\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08", addr.addr, 16);


    // boundaries

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:10000")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:10000:0:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("10000:0:0:0:0:0:0:0")));

    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:0")));
    CHECK_EQUAL(0, addr.port);

    CHECK_TRUE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:65535")));
    CHECK_EQUAL(0xFFFF, addr.port);

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:65536")));


    // syntax errors

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:-1")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:-1:0:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("-1:0:0:0:0:0:0:0")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN(" 0:0:0:0:0:0:0:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:0 ")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("0:0:0:0:0:0:0:0:0")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("1::2:3:4:5:6:7:8")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("1:2:3:4:5:6::7:8")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("1:2:3:4:::8")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("1:2:3::4::8")));

    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0]:0 ")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0 ]:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0:0:0:0:0:0:0] :0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[0:0: 0:0:0:0:0:0]:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN("[ 0:0:0:0:0:0:0:0]:0")));
    CHECK_FALSE(aes67_net_str2addr(&addr, IPSTRLEN(" [0:0:0:0:0:0:0:0]:0")));

#endif // AES67_USE_IPv6 == 1
}


TEST(Net_TestGroup, addr2str_ipv4)
{
    uint8_t str[256];
    aes67_net_addr addr;
    uint16_t len;

    RESET_ADDR(addr);

    addr.ipver = aes67_net_ipver_4;
    addr.port = 0;

    std::memcpy(addr.addr,"\x00\x00\x00\x00", 4);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("0.0.0.0") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("0.0.0.0", (const char *)str);

    std::memcpy(addr.addr,"\x01\x02\x03\x04", 4);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("1.2.3.4") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("1.2.3.4", (const char *)str);

    std::memcpy(addr.addr,"\xFF\xFF\xFF\xFF", 4);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("255.255.255.255") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("255.255.255.255", (const char *)str);


    addr.port = 1;
    std::memcpy(addr.addr,"\x00\x00\x00\x00", 4);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("0.0.0.0:1") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("0.0.0.0:1", (const char *)str);


    addr.port = 1234;
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("0.0.0.0:1234") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("0.0.0.0:1234", (const char *)str);

    addr.port = 65535;
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("0.0.0.0:65535") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("0.0.0.0:65535", (const char *)str);
}


TEST(Net_TestGroup, addr2str_ipv6)
{
    uint8_t str[256];
    aes67_net_addr addr;
    uint16_t len;

    RESET_ADDR(addr);

    addr.ipver = aes67_net_ipver_6;
    addr.port = 0;

#if AES67_USE_IPv6 == 0

    // No test: if ipv6 is not supported, an ipv4 is always assumed

#else // AES67_USE_IPv6 == 1

    std::memcpy(addr.addr,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("0:0:0:0:0:0:0:0") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("0:0:0:0:0:0:0:0", (const char *)str);

    std::memcpy(addr.addr,"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", (const char *)str);

    std::memcpy(addr.addr,"\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08", 16);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("1:2:3:4:5:6:7:8") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("1:2:3:4:5:6:7:8", (const char *)str);

    std::memcpy(addr.addr,"\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00", 16);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("100:200:300:400:500:600:700:800") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("100:200:300:400:500:600:700:800", (const char *)str);


    addr.port = 1;
    std::memcpy(addr.addr,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("[0:0:0:0:0:0:0:0]:1") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("[0:0:0:0:0:0:0:0]:1", (const char *)str);

    addr.port = 1234;
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("[0:0:0:0:0:0:0:0]:1234") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("[0:0:0:0:0:0:0:0]:1234", (const char *)str);

    addr.port = 65535;
    len = aes67_net_addr2str(str, &addr);
    CHECK_EQUAL(sizeof("[0:0:0:0:0:0:0:0]:65535") - 1, len);
    str[len] = '\0';
    STRCMP_EQUAL("[0:0:0:0:0:0:0:0]:65535", (const char *)str);

#endif // AES67_USE_IPv6 == 1
}


#undef RESET_ADDR
#undef IPSTRLEN