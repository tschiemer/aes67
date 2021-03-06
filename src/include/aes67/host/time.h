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

#ifndef AES67_HOST_TIME_H
#define AES67_HOST_TIME_H

#include "aes67/arch.h"
#include "aes67/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#if AES67_TIME_DECLARATION_INC == 1
#include "arch/time.h"
#else //AES67_TIMER_DECLARATION_INC == 0
typedef AES67_TIMESTAMP_TYPE aes67_time_t;
#endif// AES67_TIMER_DECLARATION_INC == 0

extern void aes67_time_init_system(void);
extern void aes67_time_deinit_system(void);

extern void aes67_time_now(aes67_time_t *timestamp);

extern s32_t aes67_time_diffmsec(aes67_time_t *lhs, aes67_time_t *rhs);

inline s32_t aes67_time_diffsec(aes67_time_t *lhs, aes67_time_t *rhs)
{
    return aes67_time_diffmsec(lhs, rhs) / 1000;
}

#ifdef __cplusplus
}
#endif

#endif //AES67_HOST_TIME_H
