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

#include "arch/time.h"

void aes67_time_init_system(void)
{

}

void aes67_time_deinit_system(void)
{

}

void aes67_timestamp_now(aes67_time_t *timestamp)
{
    clock_gettime(CLOCK_TAI, timestamp);
}

s32_t aes67_timestamp_diffmsec(aes67_time_t *lhs, aes67_time_t *rhs)
{
    return (1000 * rhs->tv_sec + rhs->tv_nsec / 1000000) - (1000*lhs->tv_sec + lhs->tv_nsec / 1000000) ;
}
