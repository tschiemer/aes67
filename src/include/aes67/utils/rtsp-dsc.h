/**
 * @file rtsp.h
 * Simple utility functions for Real-Time Streaming Protocol (RTSP)
 *
 * References:
 * Real-Time Streaming Protocol Version 2.0 https://tools.ietf.org/html/rfc7826
 */

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

#ifndef AES67_UTILS_RTSP_H
#define AES67_UTILS_RTSP_H

#include "aes67/arch.h"
#include "aes67/net.h"
#include "aes67/rtsp.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef AES67_RTSP_DSC_BUFSIZE
#define AES67_RTSP_DSC_BUFSIZE          1500
#endif

enum aes67_rtsp_dsc_state {
    aes67_rtsp_dsc_state_bored,
    aes67_rtsp_dsc_state_querying,
    aes67_rtsp_dsc_state_awaiting_response,
    aes67_rtsp_dsc_state_done
};

struct aes67_rtsp_dsc_res_st {
    volatile enum aes67_rtsp_dsc_state state;

    bool blocking;
    int sockfd;

    u8_t buf[AES67_RTSP_DSC_BUFSIZE];
    u16_t buflen;

    u8_t * line;
    u16_t llen;

    u16_t statuscode;
    u16_t hdrlen;
    u16_t contentlen;
};

void aes67_rtsp_dsc_init(struct aes67_rtsp_dsc_res_st * res, bool blocking);
void aes67_rtsp_dsc_deinit(struct aes67_rtsp_dsc_res_st * res);
int aes67_rtsp_dsc_start(
        struct aes67_rtsp_dsc_res_st * res,
        const enum aes67_net_ipver ipver,
        const u8_t *ip,
        const u16_t port,
        const char * encoded_uri
);
void aes67_rtsp_dsc_stop(struct aes67_rtsp_dsc_res_st * res);
void aes67_rtsp_dsc_process(struct aes67_rtsp_dsc_res_st * res);

inline const u8_t * aes67_rtsp_dsc_content(struct aes67_rtsp_dsc_res_st * res)
{
    return res->contentlen ? &res->buf[res->hdrlen] : NULL;
}

ssize_t aes67_rtsp_dsc_easy(
        const u8_t *ip,
        const enum aes67_net_ipver ipver,
        const u16_t port,
        const char *uri,
        u8_t *sdp,
        size_t maxlen
);

ssize_t aes67_rtsp_dsc_easy_url(const char *url, u8_t *sdp, size_t maxlen);

#ifdef __cplusplus
extern "C" {
#endif

#endif //AES67_UTILS_RTSP_H
