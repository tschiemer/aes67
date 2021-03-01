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

#ifndef AES67_AES67OPTS_H
#define AES67_AES67OPTS_H

#define AES67_SAP_MEMORY AES67_MEMORY_POOL

#define AES67_SAP_MEMORY_MAX_SESSIONS 3

#define AES67_TIMER_DECLARATION \
    aes67_time_t started; \
    u32_t timeout_ms;

//#define AES67_SAP_AUTH_ENABLED 1
//#define AES67_SAP_AUTH_SELF 1
//#define AES67_SAP_DECOMPRESS_AVAILABLE 1
//#define AES67_SAP_COMPRESS_ENABLED 1

#endif //AES67_AES67OPTS_H_H
