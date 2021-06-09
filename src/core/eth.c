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

#include "aes67/eth.h"

u16_t aes67_ipv4_header_checksum(u8_t * header)
{
    int len = (header[AES67_IPV4_HEADER_IHL_OFFSET] & AES67_IPV4_HEADER_IHL_MASK) << 1;

    u32_t sum = 0;
    while(len--){
        sum += *(header++) << 8;
        sum += *(header++);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    sum = (~sum) & 0xffff;

    return sum;
}