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

#ifndef AES67_TEST_HOST_TIMER_H
#define AES67_TEST_HOST_TIMER_H

#include "aes67/host/timer.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t timer_gettimeout(struct aes67_timer *timer);

void timer_expire(struct aes67_timer *timer);

void timer_check(struct aes67_timer *timer);

#ifdef __cplusplus
}
#endif

#endif //AES67_TEST_HOST_TIMER_H
