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

#ifndef AES67_UTILS_SAPSRV_H
#define AES67_UTILS_SAPSRV_H

#include "aes67/sap.h"
#include "aes67/arch.h"
#include "aes67/net.h"
#include "aes67/opt.h"
//#include "aes67/debug.h"

#if AES67_SAP_MEMORY != AES67_MEMORY_DYNAMIC
#error sap-server requires dynamic memory allocation (at this point in time)
#endif

#if AES67_SAP_FILTER_SDP != 1
#error This server assumes it will handle SDP payloads only (ie requires AES67_SAP_FILTER_SDP == 1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_SAPSRV_SCOPE_IPv4_GLOBAL        0x1
#define AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED  0x2
#define AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL     0x10
#define AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL    0x20
#define AES67_SAPSRV_SCOPE_IPv6_SITELOCAL     0x40

#define AES67_SAPSRV_SCOPE_IPv4               0x3
#define AES67_SAPSRV_SCOPE_IPv6               0x70

#define AES67_SAPSRV_SCOPES_HAS(x) (((x) & 0x73))
#define AES67_SAPSRV_SCOPES_ISVALID(x) (((x) & 0x73) == (x))

#define AES67_SAPSRV_RX_BUFLEN                  1024

typedef void * aes67_sapsrv_t;
typedef void * aes67_sapsrv_session_t;

enum aes67_sapsrv_event {
    aes67_sapsrv_event_discovered,
    aes67_sapsrv_event_updated,
    aes67_sapsrv_event_deleted,
    aes67_sapsrv_event_timeout
};

#define AES67_SAPSRV_EVENT_ISTVALID(x) (\
    (x) == aes67_sapsrv_event_discovered || \
    (x) == aes67_sapsrv_event_updated || \
    (x) == aes67_sapsrv_event_deleted || \
    (x) == aes67_sapsrv_event_timeout \
)

typedef void (*aes67_sapsrv_event_handler)(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sapsrv_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data);


aes67_sapsrv_t
aes67_sapsrv_start(u32_t listen_scopes, u32_t send_scopes, u16_t port, aes67_sapsrv_event_handler event_handler,
                   void *user_data);
void aes67_sapsrv_stop(aes67_sapsrv_t sapserver);

int aes67_sapsrv_setblocking(aes67_sapsrv_t sapserver, bool state);

void aes67_sapsrv_process(aes67_sapsrv_t sapserver);

aes67_sapsrv_session_t aes67_sapsrv_session_add(aes67_sapsrv_t sapserver, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const u8_t * payload, const u16_t payloadlen);
void aes67_sapsrv_session_update(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t session, const u8_t * payload, const u16_t payloadlen);
void aes67_sapsrv_session_delete(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t session);

aes67_sapsrv_session_t aes67_sapsrv_session_by_origin(aes67_sapsrv_t sapserver, const struct aes67_sdp_originator * origin);

#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_SAPSRV_H
