/**
 * @file rtsp.h
 * Real-Time Streaming Protocol (RTSP)
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

#define AES67_RTSP_DEFAULT_PORT     554
#define AES67_RTSP_SCHEME           "rtsp"

#define AES67_RTSP_STATUS_OK        200

#ifdef __cplusplus
extern "C" {
#endif


s32_t aes67_rtsp_describe(u8_t * ip, enum aes67_net_ipver ipver, u16_t port, u8_t * uri, u8_t * sdp, size_t maxlen);
s32_t aes67_rtsp_describe_url(u8_t * url, u8_t * sdp, size_t maxlen);

#ifdef __cplusplus
extern "C" {
#endif

#endif //AES67_UTILS_RTSP_H