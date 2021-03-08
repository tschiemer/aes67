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

#include "timer.h"

#include "time.h"

#include <assert.h>


uint32_t timer_gettimeout(struct aes67_timer *timer)
{
    return timer->timeout_ms;
}

void timer_expire( struct aes67_timer * timer )
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_expired;
}

void timer_check( struct aes67_timer * timer )
{
    assert(timer != NULL);

    if (timer->state != aes67_timer_state_set){
        return;
    }

    aes67_time_t now;
    aes67_time_now( &now );

    u32_t ms = timer->timeout_ms;

    if (ms > aes67_time_diffmsec(&timer->started, &now))
    {
        timer->state = aes67_timer_state_expired;
    }
}


void aes67_timer_init_system(void)
{
    // do nothing
}

void aes67_timer_deinit_system(void)
{
    // do nothing
}

void aes67_timer_init(struct aes67_timer * timer)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_unset;
}

void aes67_timer_set(struct aes67_timer * timer, u32_t millisec)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_set;

    timer->timeout_ms = millisec;

    aes67_time_now( &timer->started );
}

void aes67_timer_unset(struct aes67_timer * timer)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_unset;
}

void aes67_timer_deinit(struct aes67_timer * timer)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_unset;
}