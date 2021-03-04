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
//#include <netinet/in6.h>
#include <netdb.h>
#include <libproc.h>
#include <ifaddrs.h>

typedef struct sapsrv_session_st {
    u16_t hash;
    struct aes67_net_addr ip;
    u16_t payloadlen;
    u8_t * payload;
    struct aes67_sdp_originator origin;
    struct sapsrv_session_st * next;
} sapsrv_session_t;

typedef struct {
    struct aes67_sap_service service;
    sapsrv_session_t * first_session;

    aes67_sapsrv_event_handler event_handler;
    void * user_data;

    struct aes67_net_addr listen_addr;
    struct aes67_net_addr iface_addr;

    int sockfd;
    struct sockaddr_storage addr;
} sapsrv_t;

#define SAPSERVER(s)    ((sapsrv_t*)(s))
#define ADDR_IN(a)      ((struct sockaddr_in*)(a))
#define ADDR_IN6(a)     ((struct sockaddr_in6*)(a))
#define ADDR(a)         ((a)->ss_family == AF_INET ? ADDR_IN(a) : ADDR_IN6(a))


#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
static sapserver_t sapserver_singleton;
static u8_t initialized = false;
#endif

static sapsrv_session_t * session_new(sapsrv_t * server, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const struct aes67_sdp_originator * origin, const u8_t * payload,  const u16_t payloadlen)
{
    sapsrv_session_t * session = malloc(sizeof(sapsrv_session_t));

    session->hash = hash;

    session->ip.ipver = ipver;
    memcpy(session->ip.addr, ip, AES67_NET_IPVER_SIZE(ipver));

    memcpy(&session->origin, origin, sizeof(struct aes67_sdp_originator));

    session->payloadlen = payloadlen;
    session->payload = malloc(payloadlen);

    assert(session->payload);

    memcpy(session->payload, payload, payloadlen);

    session->next = server->first_session;
    server->first_session = session;

    return session;
}

static sapsrv_session_t * session_update(sapsrv_t *  sapserver, sapsrv_session_t * session, const u8_t * payload, const u16_t payloadlen)
{
    //TODO should use a lock here really

    u8_t * changed = malloc(payloadlen);
    memcpy(changed, payload, payloadlen);

    u8_t * previous = session->payload;

    session->payload = changed;
    session->payloadlen = payloadlen;

    free(previous);

    return session;
}

static void session_delete(sapsrv_t * server, sapsrv_session_t * session)
{
    if (server->first_session == session){
        server->first_session = session->next;
    } else {
        sapsrv_session_t * current = server->first_session;
        while(current != NULL){
            if (current->next == session){
                current->next = session->next;
                break;
            }
        }
    }

    if (session->payload != NULL){
        free(session->payload);
    }
    free(session);
}

static int get_ifindex(struct aes67_net_addr * addr)
{
    if (addr->ipver == aes67_net_ipver_undefined){
        return 0;
    }

    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;

    int iface = 0;

    int family = addr->ipver == aes67_net_ipver_4 ? AF_INET : AF_INET6;

    getifaddrs(&ifaddr);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr) continue;
        if (!ifa->ifa_name) continue;
        if (ifa->ifa_addr->sa_family != family) continue;

        if (family == AF_INET){
            struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;
            if (inaddr->sin_addr.s_addr == *(u32_t*)(addr->addr)){
                iface = if_nametoindex(ifa->ifa_name);
                break;
            }
        } else {
            struct sockaddr_in6* inaddr = (struct sockaddr_in6*)ifa->ifa_addr;
            if (memcmp(&inaddr->sin6_addr, addr->addr, AES67_NET_IPVER_SIZE(addr->ipver)) == 0){
                iface = if_nametoindex(ifa->ifa_name);
                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    return iface;
}

static int join_mcast_group(sapsrv_t * server)
{
    // opt join mcast group
    if (aes67_net_ismcastip_addr(&server->listen_addr)){

        assert( server->iface_addr.ipver == aes67_net_ipver_undefined || server->listen_addr.ipver == server->iface_addr.ipver);

        int optname;
        union {
            struct ip_mreq v4;
            struct ipv6_mreq v6;
        } mreq;
        socklen_t optlen;

        // prepare mcast join
        if (server->listen_addr.ipver == aes67_net_ipver_4){
            mreq.v4.imr_multiaddr.s_addr = *(in_addr_t*)server->listen_addr.addr;
            mreq.v4.imr_interface.s_addr = htonl(INADDR_ANY);//*(in_addr_t*)server->iface_addr.addr;
            optname = IP_ADD_MEMBERSHIP;
            optlen = sizeof(mreq.v4);
        } else {
            memcpy(&mreq.v6.ipv6mr_multiaddr, server->listen_addr.addr, AES67_NET_IPVER_SIZE(aes67_net_ipver_6));
            mreq.v6.ipv6mr_interface = get_ifindex(&server->iface_addr);
            optname = IPV6_JOIN_GROUP;
            optlen = sizeof(mreq.v6);
        }

        if (setsockopt(server->sockfd, IPPROTO_IP, optname, &mreq, optlen) < 0){
            perror("setsockopt(IP_ADD_MEMBERSHIP/IPV6_JOIN_GROUP) failed");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int leave_mcast_group(sapsrv_t * server)
{
    // opt leave mcast group
    if (aes67_net_ismcastip_addr(&server->listen_addr)){

        int optname;
        union {
            struct ip_mreq v4;
            struct ipv6_mreq v6;
        } mreq;
        socklen_t optlen;

        // prepare mcast join
        if (server->listen_addr.ipver == aes67_net_ipver_4){
            mreq.v4.imr_multiaddr.s_addr = *(in_addr_t*)server->listen_addr.addr;
            mreq.v4.imr_interface.s_addr = *(in_addr_t*)server->iface_addr.addr;
            optname = IP_DROP_MEMBERSHIP;
            optlen = sizeof(mreq.v4);
        } else {
            memcpy(&mreq.v6.ipv6mr_multiaddr, server->listen_addr.addr, AES67_NET_IPVER_SIZE(aes67_net_ipver_6));
            mreq.v6.ipv6mr_interface = get_ifindex(&server->iface_addr);
            optname = IPV6_LEAVE_GROUP;
            optlen = sizeof(mreq.v6);
        }

        if (setsockopt(server->sockfd, IPPROTO_IP, optname, &mreq, optlen) < 0){
            perror("setsockopt(IP_DROP_MEMBERSHIP/IPV6_LEAVE_GROUP) failed");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int aes67_sapsrv_setblocking(aes67_sapsrv_t sapserver, bool state)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    if (server->sockfd == -1){
        return -1;
    }

    // set non-blocking stdin
    int flags = fcntl(server->sockfd, F_GETFL, 0);
    flags = (flags & ~O_NONBLOCK) | (state ? 0 : O_NONBLOCK);
    if (fcntl(server->sockfd, F_SETFL, flags) == -1){
        fprintf(stderr, "Couldn't change non-/blocking\n");
        return -1;
    }

    return 0;
}

void aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                             enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype, u16_t payloadtypelen,
                             u8_t *payload, u16_t payloadlen, void *user_data)
{
    assert(user_data != NULL);
    sapsrv_t * server = (sapsrv_t*)user_data;

//    printf("sap service %d (plen %d)\n", event, payloadlen);

    // because we require sdp payload types, don't check payload type (see AES67_SAP_FILTER_SDP)

    // let's ignore the SAP originator and just focus on the SDP originator
    // so.. let's extract the origin

    // simple sanity check
    if (payloadlen < sizeof("v=0\r\no=- 1 2 IN IP4 2")){
        return;
    }

    // try to detect originator start
    u8_t * o;
    if (payload[0] == 'v' && payload[1] == '=' && payload[2] == '0'){
        o = aes67_memchr(payload, '\n', 5);
        if (o == NULL){
            return;
        }
        o++;
    } else if (payload[0] == 'o' && payload[1] == '='){
        o = payload;
    } else {
        return;
    }

    struct aes67_sdp_originator origin;
    if (AES67_SDP_OK != aes67_sdp_origin_fromstr(&origin, o, payloadlen - (o - payload))){
        return;
    }

    sapsrv_session_t * session = aes67_sapsrv_session_by_origin(server, &origin);

    if (event == aes67_sap_event_new || event == aes67_sap_event_updated){

        enum aes67_sapsrv_event evt;

        if (session == NULL){
            evt = aes67_sapsrv_event_discovered;
            session = session_new(server, hash, ipver, ip, &origin, payload, payloadlen);
        } else {

            // if previous session is not older, just skip (because is just a SAP message to prevent timeout)
            if (aes67_sdp_origin_cmpversion(&session->origin, &origin) != -1){
                return;
            }

            evt = aes67_sapsrv_event_updated;

            // update originator
            memcpy(&session->origin, &origin, sizeof(struct aes67_sdp_originator));
        }


        // publish
        server->event_handler(server, session, evt, &session->origin, session->payload, session->payloadlen, server->user_data);


    } else if (event == aes67_sap_event_deleted || event == aes67_sap_event_timeout){
        // if event was not known before, there is no reason telling the client about (?)
        if (session == NULL){
            // nothing to be done
            return;
        }

        enum aes67_sapsrv_event evt = event == aes67_sap_event_deleted ? aes67_sapsrv_event_deleted : aes67_sapsrv_event_timeout;

        // publish
        server->event_handler(server, session, evt, &session->origin, session->payload, session->payloadlen, server->user_data);

        session_delete(server, session);
    }
}

aes67_sapsrv_t aes67_sapsrv_start(const struct aes67_net_addr *listen_addr, const struct aes67_net_addr *iface_addr, aes67_sapsrv_event_handler event_handler, void *user_data)
{
    assert(listen_addr != NULL);
    assert(AES67_NET_IPVER_ISVALID(listen_addr->ipver));
    assert(event_handler != NULL);

#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    assert(initialized == false);
    sapserver_t * server = &sapserver_singleton;
    initialized = true;
#else
    sapsrv_t * server = malloc(sizeof(sapsrv_t));
    if (server == NULL){
        return NULL;
    }
#endif
    memset(server, 0, sizeof(sapsrv_t));

    aes67_sap_service_init(&server->service);

    memcpy(&server->listen_addr, listen_addr, sizeof(server->listen_addr));

    if (iface_addr != NULL){
        memcpy(&server->iface_addr, iface_addr, sizeof(server->iface_addr));
    }

    server->event_handler = event_handler;
    server->user_data = user_data;

    server->first_session = NULL;

    memset(&server->addr, 0, sizeof(server->addr));

    if (listen_addr->ipver == aes67_net_ipver_4){
        server->addr.ss_len = sizeof(struct sockaddr_in);
        server->addr.ss_family = AF_INET;
        ADDR_IN(&server->addr)->sin_port = htons(listen_addr->port);
    } else if (listen_addr->ipver == aes67_net_ipver_6){
        server->addr.ss_len = sizeof(struct sockaddr_in6);
        server->addr.ss_family = AF_INET6;
        ADDR_IN6(&server->addr)->sin6_port = htons(listen_addr->port);

    } else {
        free(server);
        return NULL;
    }

    server->sockfd = socket(server->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);

    if (server->sockfd == -1) {
        return NULL;
    }

    // set addr/port reuse
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        free(server);
        close(server->sockfd);
        return NULL;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0){
        perror("setsockopt(SO_REUSEPORT) failed");
        free(server);
        close(server->sockfd);
        return NULL;
    }
#endif

    if (aes67_net_ismcastip_addr(listen_addr)){

//        assert(iface_addr != NULL);


        if (listen_addr->ipver == aes67_net_ipver_4){
            ADDR_IN(&server->addr)->sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            memcpy(&ADDR_IN6(&server->addr)->sin6_addr, &in6addr_any, sizeof(in6addr_any));
        }

    } else {
        if (listen_addr->ipver == aes67_net_ipver_4){
            ADDR_IN(&server->addr)->sin_addr.s_addr = *(in_addr_t*)listen_addr->addr;
        } else {
            memcpy(&ADDR_IN6(&server->addr)->sin6_addr, listen_addr->addr, AES67_NET_IPVER_SIZE(aes67_net_ipver_6));
        }
    }

//    printf("len = %d\n", ADDR_IN(&server->addr)->sin_len);
//    printf("family = %d\n", ADDR_IN(&server->addr)->sin_family);
//    printf("ip = %08x\n", ntohl(ADDR_IN(&server->addr)->sin_addr.s_addr));
//    printf("port = %d\n", ntohs(ADDR_IN(&server->addr)->sin_port));

    if (bind(server->sockfd, (struct sockaddr*)&server->addr, server->addr.ss_len) == -1){
        perror("bind() failed");
        free(server);
        close(server->sockfd);
        return NULL;
    }

    if (join_mcast_group(server)){
        free(server);
        close(server->sockfd);
        return NULL;
    }

    return server;
}

void aes67_sapsrv_stop(aes67_sapsrv_t sapserver)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    leave_mcast_group(server);

    if (server->sockfd != -1){
        close(server->sockfd);
        server->sockfd = -1;
    }

    aes67_sap_service_deinit(&server->service);


#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
    initialized = false;
#else
    free(sapserver);
#endif
}

void aes67_sapsrv_process(aes67_sapsrv_t sapserver)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    if (server->sockfd != -1){

        u8_t buf[1500];
        ssize_t rlen;

        if ( (rlen = recv(server->sockfd, buf, sizeof(buf), 0)) > 0){
//            printf("recv %zd\n", rlen);
            aes67_sap_service_handle(&server->service, buf, rlen, server);
        } else {
//            printf("%zd\n", rlen);
        }
    }

    aes67_sap_service_process(&server->service, sapserver);
}

aes67_sapsrv_session_t aes67_sapsrv_session_add(aes67_sapsrv_t sapserver, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const u8_t * payload, const u16_t payloadlen)
{
    sapsrv_session_t * session = NULL;//session_new(sapserver, hash, ipver, ip, payload, payloadlen);

    //TODO announce

    return session;
}

void aes67_sapsrv_session_update(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t session, const u8_t * payload, const u16_t payloadlen)
{
    sapsrv_session_t * sess = session_update(sapserver, session, payload, payloadlen);

    //TODO announce
}

void aes67_sapsrv_session_delete(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t session)
{
    //TODO remove from list
    //SAP delete
    //free
}

aes67_sapsrv_session_t aes67_sapsrv_session_by_origin(aes67_sapsrv_t sapserver, const struct aes67_sdp_originator * origin)
{
    assert( sapserver != NULL );
    assert( origin != NULL );

    sapsrv_t * server = sapserver;

    sapsrv_session_t * current = server->first_session;

    for(; current != NULL; current = current->next ){
        if (aes67_sdp_origin_eq((struct aes67_sdp_originator *)origin, &current->origin)){
            return current;
        }
    }

    return NULL;
}