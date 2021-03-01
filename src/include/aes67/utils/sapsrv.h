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

#ifndef AES67_UTILS_SAP_SERVER_H
#define AES67_UTILS_SAP_SERVER_H

#include <aes67/sap.h>
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

typedef void * aes67_sapserver_t;
typedef void * aes67_sapserver_session_t;


typedef void (*aes67_sapserver_event_handler)(aes67_sapserver_t sapserver, enum aes67_sap_event event, u8_t * type, u16_t typelen, u8_t * payload, u16_t payloadlen, void * user_data);


#if AES67_SAP_MEMORY != AES67_MEMORY_DYNAMIC
void * aes67_sap_session_malloc(size_t size);
void * aes67_sap_session_free(void * session);
#endif

aes67_sapserver_t aes67_sapserver_start(const struct aes67_net_addr *listen_addr, const struct aes67_net_addr *iface_addr, aes67_sapserver_event_handler event_handler, void *user_data);
void aes67_sapserver_stop(aes67_sapserver_t sapserver);

void aes67_sapserver_process(aes67_sapserver_t sapserver);

aes67_sapserver_session_t aes67_sapserver_session_add(aes67_sapserver_t sapserver, const u8_t * type, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const u16_t typelen, const u8_t * payload, const u16_t payloadlen);
void aes67_sapserver_session_update(aes67_sapserver_t sapserver, aes67_sapserver_session_t session, const u8_t * payload, const u16_t payloadlen);
void aes67_sapserver_session_remove(aes67_sapserver_t sapserver, aes67_sapserver_session_t session);

#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_SAP_SERVER_H
