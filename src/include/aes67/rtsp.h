/**
 * @file rtsp.h
 * Real-Time Session Protocol utilities
 *
 * References:
 * Real Time Streaming Protocol (RTSP) https://tools.ietf.org/html/rfc2326
 * Real-Time Streaming Protocol Version 2.0 https://tools.ietf.org/html/rfc7826
 * https://www.iana.org/assignments/rtsp-parameters/rtsp-parameters.xhtml
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

#define AES67_RTSP_STATUS_CONTINUE              100
#define AES67_RTSP_STATUS_OK                    200
#define AES67_RTSP_STATUS_CREATED               201
#define AES67_RTSP_STATUS_LOW_ON_STORAGE_SPACE  250
#define AES67_RTSP_STATUS_MULTIPLE_CHOICES      300
#define AES67_RTSP_STATUS_MOVED_PERMANENTLY     301
#define AES67_RTSP_STATUS_MOVED_TEMPORARILY     302
#define AES67_RTSP_STATUS_SEE_OTHER             303
#define AES67_RTSP_STATUS_NOT_MODIFIED          304
#define AES67_RTSP_STATUS_USE_PROXY             305
#define AES67_RTSP_STATUS_BAD_REQUEST           400
#define AES67_RTSP_STATUS_UNAUTHORIZED          401
#define AES67_RTSP_STATUS_PAYMENT_REQUIRED      402
#define AES67_RTSP_STATUS_FORBIDDEN             403
#define AES67_RTSP_STATUS_NOT_FOUND             404
#define AES67_RTSP_STATUS_METHOD_NOT_ALLOWED    405
#define AES67_RTSP_STATUS_NOT_ACCEPTABLE        406
#define AES67_RTSP_STATUS_PROXY_AUTH_REQUIRED   407
#define AES67_RTSP_STATUS_REQUEST_TIMEOUT       408
#define AES67_RTSP_STATUS_GONE                  410
#define AES67_RTSP_STATUS_LENGTH_REQUIRED       411
#define AES67_RTSP_STATUS_PRECONDITION_FAILED   412
#define AES67_RTSP_STATUS_ENTITY_TOO_LARGE      413
#define AES67_RTSP_STATUS_URI_TOO_LARGE         414
#define AES67_RTSP_STATUS_UNSUPPORTED_MEDIA     415
#define AES67_RTSP_STATUS_PARAM_NOT_UNDERSTOOD  451
#define AES67_RTSP_STATUS_CONFERENCE_NOT_FOUND  452
#define AES67_RTSP_STATUS_NOT_ENOUGH_BANDWIDTH  453
#define AES67_RTSP_STATUS_SESSION_NOT_FOUND     454
#define AES67_RTSP_STATUS_METHOD_NOT_VALID_IN_STATE 455
#define AES67_RTSP_STATUS_HDR_FIELD_NOT_VALID   456
#define AES67_RTSP_STATUS_INVALID RANGE         457
#define AES67_RTSP_STATUS_PARAM_IS_READONLY     458
#define AES67_RTSP_STATUS_AGGR_OP_NOT_ALLOWED   459
#define AES67_RTSP_STATUS_ONLY_AGGR_OP_ALLOWED  460
#define AES67_RTSP_STATUS_UNSUPPORTED_TRANSPORT 461
#define AES67_RTSP_STATUS_DEST_UNREACHABLE      462
#define AES67_RTSP_STATUS_KEY_MGMT_FAILURE      463
#define AES67_RTSP_STATUS_INTERNAL_ERROR        500
#define AES67_RTSP_STATUS_NOT_IMPLEMENTED       501
#define AES67_RTSP_STATUS_BAD_GATEWAY           502
#define AES67_RTSP_STATUS_SERVICE_UNAVAILABLE   503
#define AES67_RTSP_STATUS_GATEWAY_TIMEOUT       504
#define AES67_RTSP_STATUS_VERSION_NOT_SUPPORTED 505
#define AES67_RTSP_STATUS_OPTION_NOT_SUPPORTED  551

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
