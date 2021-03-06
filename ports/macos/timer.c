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

#include "aes67/host/timer.h"

#include <assert.h>

static dispatch_queue_t queue;

static void timer_event_handler(struct aes67_timer * timer)
{
    assert(timer);

    dispatch_source_cancel(timer->dispatchSource);

    timer->state = aes67_timer_state_expired;
}

void aes67_timer_init_system(void)
{
    queue = dispatch_queue_create("timerQueue", 0);
}

void aes67_timer_deinit_system(void)
{
    dispatch_release(queue);
}

void aes67_timer_init(struct aes67_timer *timer)
{
}

void aes67_timer_deinit(struct aes67_timer *timer)
{
    aes67_timer_unset(timer);
}

void aes67_timer_set(struct aes67_timer *timer, u32_t millisec)
{
    aes67_timer_unset(timer);

    timer->dispatchSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

    dispatch_source_set_event_handler_f(timer->dispatchSource, (dispatch_function_t)timer_event_handler);

    dispatch_set_context(timer->dispatchSource, timer);


    uint64_t nanosec = 1000000 * (uint64_t)millisec;

    dispatch_time_t dispatchTime = dispatch_time(DISPATCH_TIME_NOW, nanosec);

    dispatch_source_set_timer(timer->dispatchSource, dispatchTime, 1000000000, 1000000);

    timer->state = aes67_timer_state_set;

    dispatch_resume(timer->dispatchSource);
}

void aes67_timer_unset(struct aes67_timer *timer)
{
    if (timer->state != aes67_timer_state_set){
        return;
    }

    dispatch_source_cancel(timer->dispatchSource);

    if (timer->dispatchSource){
        // generates SIGILL...
        dispatch_release(timer->dispatchSource);
        timer->dispatchSource = NULL;
    }


    timer->state = aes67_timer_state_unset;
}

 