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

#include <stdbool.h>
#include "aes67/arch.h"
#include "aes67/net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RTSP_DEFAULT_PORT     554
#define AES67_RTSP_SCHEME           "rtsp"

#define AES67_RTSP_STATUS_OK        200

#define AES67_RTSP_BUFSIZE          1500
    

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

    u8_t buf[AES67_RTSP_BUFSIZE];
    u16_t buflen;

    u8_t * line;
    u16_t llen;

    u16_t resultcode;
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

typedef void (*aes67_rtsp_header_handler)(u8_t * buf, ssize_t len);

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
