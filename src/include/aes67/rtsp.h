/**
 * @file rtsp.h
 * Real-Time Session Protocol utilities
 *
 * References:
 * Real Time Streaming Protocol (RTSP) https://tools.ietf.org/html/rfc2326
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

#ifndef AES67_RTSP_H
#define AES67_RTSP_H

#include "aes67/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RTSP_DEFAULT_PORT     554
#define AES67_RTSP_SCHEME           "rtsp"

#define AES67_RTSP_STATUS_OK        200

//struct aes67_rtsp {
//    u32_t cseq;
//
//    u16_t buflen;
//    u8_t * buf;
//};
//
//enum aes67_rtsp_rx_status {
//    aes67_rtsp_rx_status_pending,
//    aes67_rtsp_rx_status_server
//};
//
//void aes67_rtsp_init(struct aes67_rtsp * rtsp);
//void aes67_rtsp_deinit(struct aes67_rtsp * rtsp);
//
//void aes67_rtsp_received(struct aes67_rtsp * rtsp, u8_t * buf, u16_t len);
//
//s32_t aes67_rtsp_describe(struct aes67_rtsp * rtsp, u8_t * buf, u16_t maxlen);


#ifdef __cplusplus
}
#endif

#endif //AES67_RTSP_H
