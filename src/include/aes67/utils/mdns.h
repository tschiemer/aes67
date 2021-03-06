/**
 * @file mdns.h
 * Common abstraction of mDNS service.
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
#include "aes67/net.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void * aes67_mdns_context_t;
typedef void * aes67_mdns_resource_t;

enum aes67_mdns_result {
    aes67_mdns_result_error,
    aes67_mdns_result_discovered,
    aes67_mdns_result_terminated,
    aes67_mdns_result_registered,
    aes67_mdns_result_collision
};

typedef void (*aes67_mdns_browse_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * domain, void * context);
typedef void (*aes67_mdns_resolve_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, enum aes67_net_ipver ipver, const u8_t * ip, u32_t ttl, void * context);
typedef void (*aes67_mdns_service_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char *type, const char *name, const char *domain, void * context);
typedef void (*aes67_mdns_register_callback)(aes67_mdns_resource_t res, enum aes67_mdns_result result, void * user_data);

aes67_mdns_context_t  aes67_mdns_new(void);
void aes67_mdns_delete(aes67_mdns_context_t ctx);


aes67_mdns_resource_t
aes67_mdns_browse_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                        aes67_mdns_browse_callback callback, void *user_data);
aes67_mdns_resource_t
aes67_mdns_resolve_start(aes67_mdns_context_t ctx, const char *type, const char *name, const char *domain,
                         aes67_mdns_resolve_callback callback, void *user_data);

aes67_mdns_resource_t
aes67_mdns_resolve2_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                          aes67_mdns_resolve_callback callback, void *user_data);

aes67_mdns_resource_t
aes67_mdns_service_start(aes67_mdns_context_t ctx, const char *type, const char *name, const char *domain,
                         const char * host, u16_t port, u16_t txtlen, const u8_t * txt, aes67_mdns_service_callback callback, void *user_data);

aes67_mdns_resource_t
aes67_mdns_service_addrecord(aes67_mdns_context_t ctx, aes67_mdns_resource_t service, u16_t rrtype, u16_t rdlen, const u8_t * rdata, u32_t ttl);

aes67_mdns_resource_t
aes67_mdns_service_commit(aes67_mdns_context_t ctx, aes67_mdns_resource_t service);

aes67_mdns_resource_t
aes67_mdns_register_start(aes67_mdns_context_t ctx, const char *fullname, u16_t rrtype, u16_t rrclass, u16_t rdlen, const u8_t * rdata, u32_t ttl, aes67_mdns_register_callback callback, void *user_data);


void aes67_mdns_stop(aes67_mdns_resource_t res);


void aes67_mdns_process(aes67_mdns_context_t ctx, int timeout_msec);

void aes67_mdns_getsockfds(aes67_mdns_context_t ctx, int * fds[], size_t *count);

int aes67_mdns_geterrcode(aes67_mdns_resource_t res);


#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_MDNS_H
