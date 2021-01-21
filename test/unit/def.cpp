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

#include "aes67/def.h"
#include <string>


TEST_GROUP(Def_TestGroup)
{
};


TEST(Def_TestGroup, memcmp)
{
    CHECK_EQUAL(std::memcmp("abcd", "abcd", 4), aes67_memcmp("abcd", "abcd", 4));
    CHECK_EQUAL(std::memcmp("abce", "abcd", 4), aes67_memcmp("abce", "abcd", 4));
    CHECK_EQUAL(std::memcmp("abcd", "abce", 4), aes67_memcmp("abcd", "abce", 4));

    CHECK_EQUAL(std::memcmp(NULL, NULL, 0), aes67_memcmp(NULL, NULL, 0));
}

TEST(Def_TestGroup, memset)
{
    uint8_t data[8];
    uint8_t data2[8];

    std::memset(data2, 4, sizeof(8));
    CHECK_EQUAL(data, aes67_memset(data, 4, sizeof(8)));
    MEMCMP_EQUAL(data2, data, sizeof(8));

    std::memset(data2, 255, sizeof(8));
    CHECK_EQUAL(data, aes67_memset(data, 255, sizeof(8)));
    MEMCMP_EQUAL(data2, data, sizeof(8));

    std::memset(data2, 256, sizeof(8));
    CHECK_EQUAL(data, aes67_memset(data, 256, sizeof(8)));
    MEMCMP_EQUAL(data2, data, sizeof(8));
}

TEST(Def_TestGroup, memcpy)
{
    uint8_t dst[8];

    aes67_memcpy(dst, "abcdef", sizeof("abcdef"));
    STRCMP_EQUAL("abcdef", (const char *)dst);
}


TEST(Def_TestGroup, memmove)
{
    const uint8_t orig[] = "0123456789abcdef";
    uint8_t data[32];

    // just copy operation
    CHECK_EQUAL(&data[0], aes67_memmove(&data[0], orig, sizeof(orig)));
    STRCMP_EQUAL((const char *)orig, (const char *)&data[0]);

    // overlapping move forward
    CHECK_EQUAL(&data[4], aes67_memmove(&data[4], &data[0], sizeof(orig)));
    STRCMP_EQUAL((const char *)orig, (const char *)&data[4]);

    // overlapping move backward
    CHECK_EQUAL(&data[0], aes67_memmove(&data[0], &data[4], sizeof(orig)));
    STRCMP_EQUAL((const char *)orig, (const char *)&data[0]);
}

TEST(Def_TestGroup, memchr)
{
    const uint8_t str[] = "0123456789";

    CHECK_EQUAL( &str[0], aes67_memchr(str, '0', sizeof(str)-1));
    CHECK_EQUAL( &str[1], aes67_memchr(str, '1', sizeof(str)-1));
    CHECK_EQUAL( &str[9], aes67_memchr(str, '9', sizeof(str)-1));

    CHECK_EQUAL( NULL, aes67_memchr(str, 'a', sizeof(str)-1));
}

TEST(Def_TestGroup, itoa)
{
    uint8_t str[256];
    uint16_t len;

    std::memset(str, 0, sizeof(str));

    len = aes67_itoa(0b01100101011011010100000011110101, str, 2);
    CHECK_EQUAL(sizeof("1100101011011010100000011110101")-1, len);
    str[len] = '\0';
    STRCMP_EQUAL("1100101011011010100000011110101", (const char *)str);

    len = aes67_itoa(0b11100101011011010100000011110101, str, 2);
    CHECK_EQUAL(sizeof("-11010100100101011111100001011")-1, len);
    str[len] = '\0';
    STRCMP_EQUAL("-11010100100101011111100001011", (const char *)str);


    len = aes67_itoa(05436406325, str, 8); // octal
    CHECK_EQUAL(sizeof("5436406325")-1, len);
    str[len] = '\0';
    STRCMP_EQUAL("5436406325", (const char *)str);


    len = aes67_itoa(0x2C7A0CD5, str, 16);
    CHECK_EQUAL(sizeof("2C7A0CD5")-1, len);
    str[len] = '\0';
    STRCMP_EQUAL("2c7a0cd5", (const char *)str);


    len = aes67_itoa(-0x2C7A0CD5, str, 16);
    CHECK_EQUAL(sizeof("-2C7A0CD5")-1, len);
    str[len] = '\0';
    STRCMP_EQUAL("-2c7a0cd5", (const char *)str);


    CHECK_FALSE(aes67_itoa(0, str, 1));
    CHECK_FALSE(aes67_itoa(0, str, 36));
}

TEST(Def_TestGroup, atoi)
{
    uint16_t len;

    CHECK_EQUAL(0b1100101011011010100000011110101, aes67_atoi((uint8_t*)"1100101011011010100000011110101", sizeof("1100101011011010100000011110101")-1, 2, &len));
    CHECK_EQUAL(sizeof("1100101011011010100000011110101")-1, len);

    CHECK_EQUAL(0b11100101011011010100000011110101, aes67_atoi((uint8_t*)"-11010100100101011111100001011", sizeof("-11010100100101011111100001011")-1, 2, &len));
    CHECK_EQUAL(sizeof("-11010100100101011111100001011")-1, len);


    CHECK_EQUAL(05436406325, aes67_atoi((uint8_t*)"5436406325", sizeof("5436406325")-1, 8, &len));
    CHECK_EQUAL(sizeof("5436406325")-1, len);


    CHECK_EQUAL(0x2C7A0CD5, aes67_atoi((uint8_t*)"2C7A0CD5", sizeof("2C7A0CD5")-1, 16, &len));
    CHECK_EQUAL(sizeof("2C7A0CD5")-1, len);

    CHECK_EQUAL(-0x2C7A0CD5, aes67_atoi((uint8_t*)"-2C7A0CD5", sizeof("-2C7A0CD5")-1, 16, &len));
    CHECK_EQUAL(sizeof("-2C7A0CD5")-1, len);

    CHECK_EQUAL(0x2C7A0CD5, aes67_atoi((uint8_t*)"2c7a0cd5", sizeof("2c7a0cd5")-1, 16, &len));
    CHECK_EQUAL(sizeof("2c7a0cd5")-1, len);
}