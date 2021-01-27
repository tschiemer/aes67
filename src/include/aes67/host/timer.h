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
#include "aes67/host/time.h"
#include "aes67/opt.h"

#define AES67_TIMER_NOW 0

#ifdef __cplusplus
extern "C" {
#endif

enum aes67_timer_state {
    aes67_timer_state_unset = 0,
    aes67_timer_state_set = 1,
    aes67_timer_state_expired = 2
};

#define AES67_TIMER_IS_VALID(x) ( \
    (x) == aes67_timer_state_unset || \
    (x) == aes67_timer_state_set || \
    (x) == aes67_timer_state_expired \
)

#if AES67_TIMER_DECLARATION_INC == 1
#include "arch/timer.h"
#else //AES67_TIMER_DECLARATION_INC == 0

struct aes67_timer {
    enum aes67_timer_state state;

#ifdef AES67_TIMER_DECLARATION
    AES67_TIMER_DECLARATION
#endif

};

#define AES67_TIMER_GETSTATE(ptimer) (ptimer)->state

#endif //AES67_TIMER_DECLARATION_INC == 0

extern void aes67_timer_init_system(void);
extern void aes67_timer_deinit_system(void);

extern void aes67_timer_init(struct aes67_timer *timer);
extern void aes67_timer_deinit(struct aes67_timer *timer);

extern void aes67_timer_set(struct aes67_timer *timer, u32_t millisec);
extern void aes67_timer_unset(struct aes67_timer *timer);

inline enum aes67_timer_state aes67_timer_getstate(struct aes67_timer *timer)
{
    return AES67_TIMER_GETSTATE(timer);
}


#ifdef __cplusplus
}
#endif

#endif //AES67_HOST_TIMER_H
