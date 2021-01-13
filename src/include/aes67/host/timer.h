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

#ifndef AES67_HOST_TIMER_H
#define AES67_HOST_TIMER_H

#include "aes67/arch.h"

enum aes67_timer_state {
    aes67_timer_state_unset     = 0,
    aes67_timer_state_set       = 1,
    aes67_timer_state_expired   = 2
};

#define AES67_TIMER_IS_VALID( x ) ( \
    (x) == aes67_timer_state_unset || \
    (x) == aes67_timer_state_set || \
    (x) == aes67_timer_state_expired \
)

struct aes67_timer {
    enum aes67_timer_state state;

    void * impl; // host implementation reference
};

extern void aes67_timer_init(struct aes67_timer * timer);

extern void aes67_timer_enable(struct aes67_timer * timer, u32_t millisec);

extern void aes67_timer_disable(struct aes67_timer * timer);

extern void aes67_timer_deinit(struct aes67_timer * timer);


#endif //AES67_HOST_TIMER_H
