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

#include <signal.h>
#include <time.h>


static void timer_signal_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (sig != SIGALRM || info->si_code != SI_TIMER || ucontext == NULL){
        return;
    }

    struct aes67_timer * timer = info->si_value.sival_ptr;

    timer->state = aes67_timer_state_expired;

}


void aes67_timer_init_system(void)
{
    struct sigaction act;
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = timer_signal_handler;
    sigemptyset(&act.sa_mask);

    if (sigaction(SIGALRM, &act, NULL)){
        perror("timer_init_system: sigaction()");
        exit(1);
    }

}

void aes67_timer_deinit_system(void)
{
    // do nothing :)
}

void aes67_timer_init(struct aes67_timer *timer)
{
    //TODO can thus be local?
    struct sigevent sevp;

//    memset(&timer->sevp, 0, sizeof(struct sigevent));

    sevp.sigev_notify = SIGEV_SIGNAL;
    sevp.sigev_signo = SIGALRM;
    sevp.sigev_value.sival_ptr = timer;

    if (timer_create(CLOCK_TAI, &sevp, &timer->timerid)){
        perror("timer_init: timer_create()");
        exit(1);
    }

    timer->state = aes67_timer_state_unset;
}

void aes67_timer_deinit(struct aes67_timer *timer)
{
    if (timer->state == aes67_timer_state_set){
        timer->state = aes67_timer_state_undefined;
    }
    timer_delete(timer->timerid);
}

void aes67_timer_set(struct aes67_timer *timer, u32_t millisec)
{
    struct itimerspec its;

    its.it_value.tv_sec = millisec / 1000;
    its.it_value.tv_nsec = (millisec % 1000) * 1000000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    timer->state = aes67_timer_state_unset;

    if (timer_settime(timer->timerid, 0, &its, NULL)){
        perror("timer_set: timer_settime()");
    }
}

void aes67_timer_unset(struct aes67_timer *timer)
{
    if (timer->state == aes67_timer_state_unset){
        return;
    }
    timer->state = aes67_timer_state_unset;

    struct itimerspec its;

    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timer->timerid, 0, &its, NULL)){
        perror("timer_unset: timer_settime()");
    }
}

 