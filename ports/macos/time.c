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

static clock_serv_t clock_service;


void aes67_time_init_system(void)
{
    kern_return_t ret = host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &clock_service);

    assert(ret == 0);
}

void aes67_time_deinit_system(void)
{
    mach_port_deallocate(mach_task_self(), clock_service);
}

void aes67_time_now(aes67_time_t *timestamp)
{
    assert(timestamp != NULL);

    clock_get_time(clock_service, timestamp);
}

s32_t aes67_time_diffmsec(aes67_time_t *lhs, aes67_time_t *rhs)
{
    assert(lhs != NULL);
    assert(rhs != NULL);


    s32_t lhs_msec = 1000 * lhs->tv_sec + lhs->tv_nsec / 1000000;
    s32_t rhs_msec = 1000 * rhs->tv_sec + rhs->tv_nsec / 1000000;

    return lhs_msec - rhs_msec;
}
