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

#include "aes67/utils/sapsrv.h"

#include "aes67/sap.h"
#include "aes67/sdp.h"
//#include "aes67/debug.h"

#include "assert.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

typedef struct sapsrv_session_st {

    u16_t payloadlen;
    u8_t * payload;
    struct sapsrv_session_st * next;
} sapsrv_session_t;

typedef struct {
    struct aes67_sap_service service;
    aes67_sapserver_event_handler event_handler;
    void * user_data;
    int sockfd;
    sapsrv_session_t * first_session;
} sapsrv_t;

#define SAPSERVER(s) ((sapsrv_t*)(s))


#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
static sapserver_t sapserver_singleton;
static u8_t initialized = false;
#endif

//static sapsrv_session_t * new_session();

void aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                             enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype, u16_t payloadtypelen,
                             u8_t *payload, u16_t payloadlen, void *user_data)
{

}

aes67_sapserver_t aes67_sapserver_start(const struct aes67_net_addr *listen_addr, const struct aes67_net_addr *iface_addr, aes67_sapserver_event_handler event_handler, void *user_data)
{
    assert(event_handler != NULL);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    assert(initialized == false);
    sapserver_t * sapserver = &sapserver_singleton;
    initialized = true;
#else
    sapsrv_t * server = malloc(sizeof(sapsrv_t));
#endif

    aes67_sap_service_init(&server->service);

    server->event_handler = event_handler;
    server->user_data = user_data;

    server->first_session = NULL;

    server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (server->sockfd == -1) {
        return NULL;
    }

    /**
     * TODO SETUP
     * - sanity chech listen_addr and iface_addr
     *   - iface_addr needed only if listen_addr is a mcast address
     * - socket
     *   - create socket (allow port reuse?)
     *   - bind to listen_addr
     *   - if listen_addr is mcast address: join multicast group
     */


    return server;
}

void aes67_sapserver_stop(aes67_sapserver_t sapserver)
{
    assert(sapserver != NULL);

    /**
     * TODO teardown
     * - leave multicast group
     * - close socket
     */

    aes67_sap_service_deinit(&SAPSERVER(sapserver)->service);



#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    initialized = false;
#else
    free(sapserver);
#endif
}

void aes67_sapserver_process(aes67_sapserver_t sapserver)
{
    assert(sapserver != NULL);

    aes67_sap_service_process(&SAPSERVER(sapserver)->service, sapserver);
}

aes67_sapserver_session_t aes67_sapserver_session_add(aes67_sapserver_t sapserver, const u8_t * type, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const u16_t typelen, const u8_t * payload, const u16_t payloadlen)
{
    sapsrv_session_t * session = malloc(sizeof(sapsrv_session_t));

    return session;
}

void aes67_sapserver_session_update(aes67_sapserver_t sapserver, aes67_sapserver_session_t session, const u8_t * payload, const u16_t payloadlen)
{

}

void aes67_sapserver_session_remove(aes67_sapserver_t sapserver, aes67_sapserver_session_t session)
{

}