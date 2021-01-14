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

#ifndef AES67_HOST_TIME_H
#define AES67_HOST_TIME_H

#include "aes67/arch.h"

typedef u32_t aes67_timestamp_t;

extern void aes67_timestamp_now(aes67_timestamp_t * timestamp);

extern u32_t aes67_timestamp_diffsec(aes67_timestamp_t * lhs, aes67_timestamp_t * rhs);

#endif //AES67_HOST_TIME_H
