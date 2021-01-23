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

#include "aes67/host/time.h"

#include <assert.h>

static aes67_timestamp_t counter = 0;

void aes67_timestamp_now(aes67_timestamp_t * timestamp)
{
    assert(timestamp != NULL);

    *timestamp = ++counter;
}

s32_t aes67_timestamp_diffsec(aes67_timestamp_t * lhs, aes67_timestamp_t * rhs)
{
    assert(lhs != NULL);
    assert(rhs != NULL);

    return (s32_t)*rhs - (s32_t)*lhs;
}