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
#include <string.h>


typedef struct {
    aes67_timestamp_t started;
    u32_t timeout_ms;
} timer_info_t;

uint32_t timer_gettimeout(struct aes67_timer *timer)
{
    return ((timer_info_t*)timer->impl)->timeout_ms;
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

    aes67_timestamp_t now;
    aes67_timestamp_now( &now );

    u32_t ms = ((timer_info_t*)timer->impl)->timeout_ms;

    if (ms > aes67_timestamp_diffmsec(&((timer_info_t*)timer->impl)->started, &now))
    {
        timer->state = aes67_timer_state_expired;
    }
}

void aes67_timer_init(struct aes67_timer * timer)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_unset;

    timer->impl = malloc(sizeof(timer_info_t));
    memset(timer->impl, 0, sizeof(timer_info_t));
}

void aes67_timer_set(struct aes67_timer * timer, u32_t millisec)
{
    assert(timer != NULL);

    timer->state = aes67_timer_state_set;

    ((timer_info_t*)timer->impl)->timeout_ms = millisec;
    aes67_timestamp_now( &((timer_info_t*)timer->impl)->started );
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

    free(timer->impl);
}