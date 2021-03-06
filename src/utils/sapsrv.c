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
#include <syslog.h>

//#if !defined(SYSLOG)
//#define SYSLOG(priority, fmt, ...)
//#endif

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

    u32_t listen_scopes;
    u32_t send_scopes;
    u16_t port;

    int sockfd4;
    struct sockaddr_in addr4;

    int sockfd6;
    struct sockaddr_in6 addr6;
} sapsrv_t;


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
            current = current->next;
        }
    }

    if (session->payload != NULL){
        free(session->payload);
    }
    free(session);
}

//static int get_ifindex(struct aes67_net_addr * addr)
//{
//    if (addr->ipver == aes67_net_ipver_undefined){
//        return 0;
//    }
//
//    struct ifaddrs* ifaddr;
//    struct ifaddrs* ifa;
//
//    int iface = 0;
//
//    int family = addr->ipver == aes67_net_ipver_4 ? AF_INET : AF_INET6;
//
//    getifaddrs(&ifaddr);
//
//    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
//    {
//        if (!ifa->ifa_addr) continue;
//        if (!ifa->ifa_name) continue;
//        if (ifa->ifa_addr->sa_family != family) continue;
//
//        if (family == AF_INET){
//            struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;
//            if (inaddr->sin_addr.s_addr == *(u32_t*)(addr->addr)){
//                iface = if_nametoindex(ifa->ifa_name);
//                break;
//            }
//        } else {
//            struct sockaddr_in6* inaddr = (struct sockaddr_in6*)ifa->ifa_addr;
//            if (memcmp(&inaddr->sin6_addr, addr->addr, AES67_NET_IPVER_SIZE(addr->ipver)) == 0){
//                iface = if_nametoindex(ifa->ifa_name);
//                break;
//            }
//        }
//    }
//
//    freeifaddrs(ifaddr);
//
//    return iface;
//}


int aes67_sapsrv_join_mcast_group(int sockfd, u32_t scope)
{
    int proto;
    int optname;
    union {
        struct ip_mreq v4;
        struct ipv6_mreq v6;
    } mreq;
    socklen_t optlen;

    // prepare mcast join
    if (scope & AES67_SAPSRV_SCOPE_IPv4){
        proto = IPPROTO_IP;
        optname = IP_ADD_MEMBERSHIP;
        if (scope & AES67_SAPSRV_SCOPE_IPv4_GLOBAL){
            memcpy(&mreq.v4.imr_multiaddr.s_addr, (u8_t[])AES67_SAP_IPv4_GLOBAL, 4);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED){
            memcpy(&mreq.v4.imr_multiaddr.s_addr, (u8_t[])AES67_SAP_IPv4_ADMIN, 4);
        }
        mreq.v4.imr_interface.s_addr = htonl(INADDR_ANY);//*(in_addr_t*)server->iface_addr.addr;
        optlen = sizeof(struct ip_mreq);
    } else if (scope & AES67_SAPSRV_SCOPE_IPv6){
        proto = IPPROTO_IPV6;
        optname = IPV6_JOIN_GROUP;
        if (scope & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_LL, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_IPv4){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_IP4, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_AL, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_SL, 16);
        }
        mreq.v6.ipv6mr_interface = 0; // default interface // get_ifindex(&server->iface_addr);
        optlen = sizeof(struct ipv6_mreq);
    } else {
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, proto, optname, &mreq, optlen) < 0){
        perror("setsockopt(IP_ADD_MEMBERSHIP/IPV6_JOIN_GROUP) failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int join_mcast_groups(sapsrv_t * server, u32_t scopes)
{
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_GLOBAL) && aes67_sapsrv_join_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_GLOBAL)){
//        perror("4gl");
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED) && aes67_sapsrv_join_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED)){
//        perror("4al");
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL)){
//        perror("6ll");
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_IPv4) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_IPv4)){
//        perror("6al");
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL)){
//        perror("6al");
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_SITELOCAL)){
//        perror("6sl");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int aes67_sapsrv_leave_mcast_group(int sockfd, u32_t scope)
{
    // only
    assert( ((scope & AES67_SAPSRV_SCOPE_IPv4) == AES67_SAPSRV_SCOPE_IPv4) + ((scope & AES67_SAPSRV_SCOPE_IPv6) == AES67_SAPSRV_SCOPE_IPv6) == 1);

    int proto;
    int optname;
    union {
        struct ip_mreq v4;
        struct ipv6_mreq v6;
    } mreq;
    socklen_t optlen;

    // prepare mcast join
    if (scope & AES67_SAPSRV_SCOPE_IPv4){
        proto = IPPROTO_IP;
        optname = IP_DROP_MEMBERSHIP;
        if (scope & AES67_SAPSRV_SCOPE_IPv4_GLOBAL){
            memcpy(&mreq.v4.imr_multiaddr.s_addr, (u8_t[])AES67_SAP_IPv4_GLOBAL, 4);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED){
            memcpy(&mreq.v4.imr_multiaddr.s_addr, (u8_t[])AES67_SAP_IPv4_ADMIN, 4);
        }
        mreq.v4.imr_interface.s_addr = htonl(INADDR_ANY);//*(in_addr_t*)server->iface_addr.addr;
        optlen = sizeof(mreq.v4);
    } else if (scope & AES67_SAPSRV_SCOPE_IPv6){
        proto = IPPROTO_IPV6;
        optname = IPV6_LEAVE_GROUP;
        if (scope & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_LL, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_IPv4){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_IP4, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_AL, 16);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_SL, 16);
        }
        mreq.v6.ipv6mr_interface = 0; // default interface // get_ifindex(&server->iface_addr);
        optlen = sizeof(mreq.v6);
    } else {
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, IPPROTO_IP, optname, &mreq, optlen) < 0){
        perror("setsockopt(IP_DROP_MEMBERSHIP/IPV6_LEAVE_GROUP) failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


static int leave_mcast_groups(sapsrv_t * server, u32_t scopes)
{
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_GLOBAL) && aes67_sapsrv_leave_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_GLOBAL)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED) && aes67_sapsrv_leave_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_IPv4) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_IPv4)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_SITELOCAL)){
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int set_sock_requse(int sockfd)
{
    // set addr/port reuse
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return EXIT_FAILURE;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0){
        perror("setsockopt(SO_REUSEPORT) failed");
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}

int aes67_sapsrv_setblocking(aes67_sapsrv_t sapserver, bool state)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    if (server->sockfd4 != -1){

        // set non-blocking stdin
        int flags = fcntl(server->sockfd4, F_GETFL, 0);
        flags = (flags & ~O_NONBLOCK) | (state ? 0 : O_NONBLOCK);
        if (fcntl(server->sockfd4, F_SETFL, flags) == -1){
            fprintf(stderr, "Couldn't change non-/blocking\n");
            return EXIT_FAILURE;
        }
    }

    if (server->sockfd6 != -1){

        // set non-blocking stdin
        int flags = fcntl(server->sockfd6, F_GETFL, 0);
        flags = (flags & ~O_NONBLOCK) | (state ? 0 : O_NONBLOCK);
        if (fcntl(server->sockfd6, F_SETFL, flags) == -1){
            fprintf(stderr, "Couldn't change non-/blocking\n");
            return EXIT_FAILURE;
        }
    }


    return EXIT_SUCCESS;
}

void aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                             enum aes67_net_ipver ipver, u8_t *ip, u8_t *type, u16_t typelen,
                             u8_t *payload, u16_t payloadlen, void *user_data)
{
    assert(user_data != NULL);
    sapsrv_t * server = (sapsrv_t*)user_data;

    syslog(LOG_DEBUG, "sap evt=%d, plen=%d", event, payloadlen);

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

aes67_sapsrv_t
aes67_sapsrv_start(u32_t listen_scopes, u32_t send_scopes, u16_t port, aes67_sapsrv_event_handler event_handler,
                   void *user_data)
{
    assert(AES67_SAPSRV_SCOPES_HAS(listen_scopes));
    assert(AES67_SAPSRV_SCOPES_HAS(send_scopes));
    assert(port > 0);
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

    server->listen_scopes = listen_scopes;
    server->send_scopes = send_scopes;
    server->port = port;
    server->event_handler = event_handler;
    server->user_data = user_data;

    server->first_session = NULL;


    if (listen_scopes & AES67_SAPSRV_SCOPE_IPv4){
        server->addr4.sin_len = sizeof(struct sockaddr_in);
        server->addr4.sin_family = AF_INET;
        server->addr4.sin_port = htons(port);

        server->sockfd4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (server->sockfd4 == -1) {
            free(server);
            return NULL;
        }

        if (set_sock_requse(server->sockfd4)){
            close(server->sockfd4);
            free(server);
            return NULL;
        }

        if (bind(server->sockfd4, (struct sockaddr*)&server->addr4, server->addr4.sin_len) == -1){
            perror("bind() failed");
            close(server->sockfd4);
            free(server);
            return NULL;
        }
    }

    if (listen_scopes & AES67_SAPSRV_SCOPE_IPv6){
        server->addr6.sin6_len = sizeof(struct sockaddr_in6);
        server->addr6.sin6_family = AF_INET6;
        server->addr6.sin6_port = htons(port);

        server->sockfd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

        if (server->sockfd6 == -1) {
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            free(server);
            return NULL;
        }

        if (set_sock_requse(server->sockfd4)){
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            close(server->sockfd6);
            free(server);
        }

        if (bind(server->sockfd6, (struct sockaddr*)&server->addr6, server->addr6.sin6_len) == -1){
            perror("bind() failed");
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            close(server->sockfd6);
            free(server);
            return NULL;
        }
    }

    if (join_mcast_groups(server, listen_scopes)){
        if (server->sockfd4 != -1){
            close(server->sockfd4);
        }
        if (server->sockfd6 != -1){
            close(server->sockfd6);
        }
        free(server);
        return NULL;
    }

    return server;
}

void aes67_sapsrv_stop(aes67_sapsrv_t sapserver)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    leave_mcast_groups(server, server->listen_scopes);

    if (server->sockfd4 != -1){
        close(server->sockfd4);
    }

    if (server->sockfd6 != -1){
        close(server->sockfd6);
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

    u8_t buf[AES67_SAPSRV_RX_BUFLEN];
    ssize_t rlen;

    if (server->sockfd4 != -1){
        if ( (rlen = recv(server->sockfd4, buf, sizeof(buf), 0)) > 0){
//            printf("recv4 %zd\n", rlen);
            aes67_sap_service_handle(&server->service, buf, rlen, server);
        }
    }

    if (server->sockfd6 != -1){
        if ( (rlen = recv(server->sockfd6, buf, sizeof(buf), 0)) > 0){
//            printf("recv6 %zd\n", rlen);
            aes67_sap_service_handle(&server->service, buf, rlen, server);
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