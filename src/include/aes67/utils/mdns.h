/**
 * @file mdns.h
 * Common abstraction of mDNS service.
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

#ifndef AES67_UTILS_MDNS_H
#define AES67_UTILS_MDNS_H

#include "aes67/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void * aes67_mdns_context_t;
typedef void * aes67_mdns_resource_t;

enum aes67_mdns_result {
    aes67_mdns_result_ok,
    aes67_mdns_result_error
};

typedef void (*aes67_mdns_browse_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * type, const u8_t * name, const u8_t * domain, void * context);
typedef void (*aes67_mdns_resolve_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * fullname, const u8_t * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context);


aes67_mdns_context_t  aes67_mdns_new(void);
void aes67_mdns_delete(aes67_mdns_context_t ctx);


aes67_mdns_resource_t
aes67_mdns_browse_start(aes67_mdns_context_t ctx, const u8_t *type, const u8_t *subtype, const u8_t *domain,
                        aes67_mdns_browse_callback callback, void *user_data);
aes67_mdns_resource_t
aes67_mdns_resolve_start(aes67_mdns_context_t ctx, const u8_t *name, const u8_t *type, const u8_t *domain,
                         aes67_mdns_resolve_callback callback, void *user_data);

aes67_mdns_resource_t
aes67_mdns_lookup_start(aes67_mdns_context_t ctx, const u8_t *type, const u8_t *subtype, const u8_t *domain,
                        aes67_mdns_resolve_callback callback, void *user_data);

void aes67_mdns_stop(aes67_mdns_resource_t res);

void aes67_mdns_process(aes67_mdns_context_t ctx, struct timeval *timeout);

void aes67_mdns_getsockfds(aes67_mdns_context_t ctx, int *fds, int *nfds);


#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_MDNS_H
