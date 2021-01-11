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
#ifndef AES67_PTP_H
#define AES67_PTP_H

#include "aes67/arch.h"

#define AES67_PTP_TYPE_STR_IEEE1588_2002    "IEEE1588-2002"
#define AES67_PTP_TYPE_STR_IEEE1588_2008    "IEEE1588-2008"
#define AES67_PTP_TYPE_STR_IEEE1588_2019    "IEEE1588-2019"
#define AES67_PTP_TYPE_STR_IEEE802AS_2011   "IEEE802.1AS-2011"

/**
 * PTP clock type
 */
enum aes67_ptp_type {
    aes67_ptp_type_IEEE1588_2002 = 1,
    aes67_ptp_type_IEEE1588_2008 = 2,
    aes67_ptp_type_IEEE1588_2019 = 3,
    aes67_ptp_type_IEEE802AS_2011 = 4,
};

/**
 * EUI64 as used for PTP clock identifiers
 */
union aes67_ptp_eui64 {
    u8_t u8[8];
    u32_t u32[2];
//    u64_t u64;
};

/**
 * PTP clock datastruct
 */
struct aes67_ptp {
    enum aes67_ptp_type type;
    union aes67_ptp_eui64 gmid;
    u8_t domain;
};


#endif //AES67_PTP_H
