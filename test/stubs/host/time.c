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

#include "time.h"

#include <assert.h>

static aes67_time_t counter_ms = 0;

void time_add_now_ms(int32_t ms)
{
    counter_ms += ms;
}

void aes67_time_init_system(void)
{
    // do nothing
}

void aes67_time_deinit_system(void)
{
    // do nothing
}

void aes67_time_now(aes67_time_t * timestamp)
{
    assert(timestamp != NULL);

    *timestamp = ++counter_ms;
}

s32_t aes67_time_diffmsec(aes67_time_t * lhs, aes67_time_t * rhs)
{
    assert(lhs != NULL);
    assert(rhs != NULL);

    return ((s32_t)*rhs - (s32_t)*lhs);
}