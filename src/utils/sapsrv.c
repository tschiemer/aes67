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

#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
//#include <libproc.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <errno.h>


typedef struct sapsrv_session_st {
    u8_t managed_by;
    time_t last_activity;
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

    bool blocking;

//    int sockfd[2];
//#define sockfd4 sockfd[0]
    int sockfd4;
    struct sockaddr_in addr4;

    int sockfd6;
//#define sockfd6 sockfd[1]
    struct sockaddr_in6 addr6;
    unsigned int ipv6_if;
} sapsrv_t;


#if AES67_SAP_MEMORY == AES67_MEMORY_POOL
static sapserver_t sapserver_singleton;
static u8_t initialized = false;
#endif

static sapsrv_session_t * session_new(sapsrv_t *server, u8_t managed_by, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t *ip, const struct aes67_sdp_originator *origin, const u8_t *payload, const u16_t payloadlen);
static sapsrv_session_t * session_update(sapsrv_t *  sapserver, sapsrv_session_t * session, const struct aes67_sdp_originator *origin, const u8_t * payload, const u16_t payloadlen);
static void session_delete(sapsrv_t * server, sapsrv_session_t * session);

static sapsrv_session_t * aes67_sapsrv_session_by_id(aes67_sapsrv_t sapserver, const u16_t hash, enum aes67_net_ipver ipver, u8_t * ip);

static int set_sock_reuse(int sockfd);
static int aes67_sapsrv_join_mcast_group(int sockfd, u32_t scope, unsigned int ipv6_if);
static int aes67_sapsrv_leave_mcast_group(int sockfd, u32_t scope, unsigned int ipv6_if);
static int join_mcast_groups(sapsrv_t * server, u32_t scopes);
static int leave_mcast_groups(sapsrv_t * server, u32_t scopes);

static void sap_send(sapsrv_t * server, sapsrv_session_t * session, u8_t opt);



static sapsrv_session_t * session_new(sapsrv_t *server, u8_t managed_by, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t *ip, const struct aes67_sdp_originator *origin, const u8_t *payload, const u16_t payloadlen)
{
    sapsrv_session_t * session = malloc(sizeof(sapsrv_session_t));

    session->managed_by = managed_by;
    session->last_activity = 0;

    session->hash = hash;

    session->ip.ipver = ipver;
    memcpy(session->ip.ip, ip, AES67_NET_IPVER_SIZE(ipver));

    memcpy(&session->origin, origin, sizeof(struct aes67_sdp_originator));

    session->payloadlen = payloadlen;
    session->payload = malloc(payloadlen);

    assert(session->payload);

    memcpy(session->payload, payload, payloadlen);

    session->next = server->first_session;
    server->first_session = session;

    return session;
}

static sapsrv_session_t * session_update(sapsrv_t *  sapserver, sapsrv_session_t * session, const struct aes67_sdp_originator *origin, const u8_t * payload, const u16_t payloadlen)
{
    //TODO should use a lock here really

    memcpy(&session->origin.session_version.data, origin->session_version.data, origin->session_version.length);
    session->origin.session_version.length = origin->session_version.length;

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

static sapsrv_session_t * aes67_sapsrv_session_by_id(aes67_sapsrv_t sapserver, const u16_t hash, enum aes67_net_ipver ipver, u8_t * ip)
{
    assert( sapserver != NULL );
    assert(AES67_NET_IPVER_ISVALID(ipver));
    assert( ip != NULL );

    sapsrv_t * server = sapserver;

    sapsrv_session_t * current = server->first_session;

    for(; current != NULL; current = current->next ){
        if (current->hash == hash && current->ip.ipver == ipver && memcmp(current->ip.ip, ip, AES67_NET_IPVER_SIZE(ipver)) == 0){
            return current;
        }
    }

    return NULL;
}


int aes67_sapsrv_join_mcast_group(int sockfd, u32_t scope, unsigned int ipv6_if)
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
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv4_GLOBAL_STR);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED){
            memcpy(&mreq.v4.imr_multiaddr.s_addr, (u8_t[])AES67_SAP_IPv4_ADMIN, 4);
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv4_ADMIN_STR);
        }
        mreq.v4.imr_interface.s_addr = htonl(INADDR_ANY);//*(in_addr_t*)server->iface_addr.addr;
        optlen = sizeof(struct ip_mreq);
    } else if (scope & AES67_SAPSRV_SCOPE_IPv6){
        proto = IPPROTO_IPV6;
        optname = IPV6_JOIN_GROUP;
        if (scope & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_LL, 16);
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv6_LL_STR);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_IPv4){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_IP4, 16);
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv6_IP4_STR);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_AL, 16);
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv6_AL_STR);
        } else if (scope & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL){
            memcpy(&mreq.v6.ipv6mr_multiaddr, (u8_t[])AES67_SAP_IPv6_SL, 16);
            syslog(LOG_INFO, "sapsrv joining mcast " AES67_SAP_IPv6_SL_STR);
        }
//        printf("%08x:%08x:%08x:%08x\n",
//               ntohl(((struct in6_addr*)&mreq.v6.ipv6mr_multiaddr)->__u6_addr.__u6_addr32[0]),
//               ntohl(((struct in6_addr*)&mreq.v6.ipv6mr_multiaddr)->__u6_addr.__u6_addr32[1]),
//                       ntohl(((struct in6_addr*)&mreq.v6.ipv6mr_multiaddr)->__u6_addr.__u6_addr32[2]),
//               ntohl(((struct in6_addr*)&mreq.v6.ipv6mr_multiaddr)->__u6_addr.__u6_addr32[3])
//       );
        mreq.v6.ipv6mr_interface = ipv6_if; // default interface // get_ifindex(&server->iface_addr);
        optlen = sizeof(struct ipv6_mreq);
    } else {
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, proto, optname, &mreq, optlen) < 0){
        syslog(LOG_ERR, "sapsrv setsockopt(IP_ADD_MEMBERSHIP/IPV6_JOIN_GROUP) failed (scope): %s", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int join_mcast_groups(sapsrv_t * server, u32_t scopes)
{
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_GLOBAL) && aes67_sapsrv_join_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_GLOBAL, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 4gl: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED) && aes67_sapsrv_join_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 4al: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 6ll: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_IPv4) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_IPv4, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 6al: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 6al: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL) && aes67_sapsrv_join_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_SITELOCAL, server->ipv6_if)){
        syslog(LOG_ERR, "sapsrv 6sl: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int aes67_sapsrv_leave_mcast_group(int sockfd, u32_t scope, unsigned int ipv6_if)
{
    assert(sockfd>0);
    // only
    assert( !!(scope & AES67_SAPSRV_SCOPE_IPv4) + !!(scope & AES67_SAPSRV_SCOPE_IPv6)  == 1);

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
        mreq.v6.ipv6mr_interface = ipv6_if; // default interface // get_ifindex(&server->iface_addr);
        optlen = sizeof(mreq.v6);
    } else {
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, proto, optname, &mreq, optlen) < 0){
        syslog(LOG_ERR, "setsockopt(IP_DROP_MEMBERSHIP/IPV6_LEAVE_GROUP): %s", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


static int leave_mcast_groups(sapsrv_t * server, u32_t scopes)
{
    assert(server);

    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_GLOBAL) && aes67_sapsrv_leave_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_GLOBAL, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED) && aes67_sapsrv_leave_mcast_group(server->sockfd4, AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_IPv4) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_IPv4, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    if ( (scopes & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL) && aes67_sapsrv_leave_mcast_group(server->sockfd6, AES67_SAPSRV_SCOPE_IPv6_SITELOCAL, server->ipv6_if)){
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int set_sock_reuse(int sockfd)
{
    // set addr/port reuse
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        syslog(LOG_ERR, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return EXIT_FAILURE;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0){
        syslog(LOG_ERR, "setsockopt(SO_REUSEPORT): %s", strerror(errno));
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}
void aes67_sapsrv_getsockfds(aes67_sapsrv_t sapserver, int * fds[], size_t * count)
{
    assert(sapserver != NULL);
    assert(fds != NULL);
    assert(count != NULL);

    sapsrv_t * server = sapserver;

    size_t c = 0;

    static int __fds[2];

    if (server->sockfd4 != -1){
        __fds[c++] = server->sockfd4;
    }
    if (server->sockfd6 != -1){
        __fds[c++] = server->sockfd6;
    }

    *fds = __fds;

    *count = c;
}

int aes67_sapsrv_setblocking(aes67_sapsrv_t sapserver, bool state)
{
    assert(sapserver != NULL);

    sapsrv_t * server = sapserver;

    server->blocking = state;

    return EXIT_SUCCESS;
}

static void sap_send(sapsrv_t * server, sapsrv_session_t * session, u8_t opt)
{
    assert(server != NULL);
    assert(session != NULL);
    assert(AES67_NET_IPVER_ISVALID(session->ip.ipver));

    u8_t sap[AES67_SAPSRV_SDP_MAXLEN+60];

    u16_t saplen = aes67_sap_service_msg(&server->service, sap, sizeof(sap), opt, session->hash, session->ip.ipver, session->ip.ip, session->payload, session->payloadlen, server);

    if (saplen == 0){
        syslog(LOG_ERR, "failed to generate SAP msg");
        return;
    }

    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;

    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(server->port);

    addr_in6.sin6_family = AF_INET6;
    addr_in6.sin6_port = htons(server->port);

    ssize_t s;

    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv4_GLOBAL)){
        memcpy(&addr_in.sin_addr, (u8_t[])AES67_SAP_IPv4_GLOBAL, 4);
        if ( (s = sendto(server->sockfd4, sap, saplen, 0, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in))) != saplen){
            syslog(LOG_ERR, "ipv4-g tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv4-g tx %zd", s);
        }
    }
    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED)){
        memcpy(&addr_in.sin_addr, (u8_t[])AES67_SAP_IPv4_ADMIN, 4);
        if ( (s = sendto(server->sockfd4, sap, saplen, 0, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in))) != saplen){
            syslog(LOG_ERR, "ipv4-a tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv4-a tx %zd", s);
        }
    }
    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL)){
        memcpy(&addr_in6.sin6_addr, (u8_t[])AES67_SAP_IPv6_LL, 16);
        if ( (s = sendto(server->sockfd6, sap, saplen, 0, (struct sockaddr*)&addr_in6, sizeof(struct sockaddr_in6))) != saplen){
            syslog(LOG_ERR, "ipv6-ll tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv6-ll tx %zd", s);
        }
    }
    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL)){
        memcpy(&addr_in6.sin6_addr, (u8_t[])AES67_SAP_IPv6_AL, 16);
        if ( (s = sendto(server->sockfd6, sap, saplen, 0, (struct sockaddr*)&addr_in6, sizeof(struct sockaddr_in6))) != saplen){
            syslog(LOG_ERR, "ipv6-al tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv6-al tx %zd", s);
        }
    }
    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv6_IPv4)){
        memcpy(&addr_in6.sin6_addr, (u8_t[])AES67_SAP_IPv6_IP4, 16);
        if ( (s = sendto(server->sockfd6, sap, saplen, 0, (struct sockaddr*)&addr_in6, sizeof(struct sockaddr_in6))) != saplen){
            syslog(LOG_ERR, "ipv6-v4 tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv6-v4 tx %zd", s);
        }
    }
    if ( (server->send_scopes & AES67_SAPSRV_SCOPE_IPv6_SITELOCAL)){
        memcpy(&addr_in6.sin6_addr, (u8_t[])AES67_SAP_IPv6_SL, 16);
        if ( (s = sendto(server->sockfd6, sap, saplen, 0, (struct sockaddr*)&addr_in6, sizeof(struct sockaddr_in6))) != saplen){
            syslog(LOG_ERR, "ipv6-sl tx (%zd)", s);
        } else {
            syslog(LOG_DEBUG, "ipv6-sl tx %zd", s);
        }
    }

    session->last_activity = time(NULL);
}

void aes67_sap_service_event(struct aes67_sap_service *sap, enum aes67_sap_event event, u16_t hash,
                             enum aes67_net_ipver ipver, u8_t *ip, u8_t *type, u16_t typelen,
                             u8_t *payload, u16_t payloadlen, void *user_data)
{
    assert(user_data != NULL);
    sapsrv_t * server = (sapsrv_t*)user_data;

    syslog(LOG_DEBUG, "sap evt=%d hash=%hu plen=%d", event, hash, payloadlen);

    // announcement requests get special treatement (because they're triggered by the local stack and no origin is provided)
    if (event == aes67_sap_event_announcement_request){

        sapsrv_session_t * session = aes67_sapsrv_session_by_id(server, hash, ipver, ip);

        // should not occur
        if (session == NULL){
            return;
        }

        // should never happen, but in case, let's log it
        if (session->managed_by == AES67_SAPSRV_MANAGEDBY_REMOTE){
            syslog(LOG_ERR, "announcement request for remote sap");
            return;
        }

        sap_send(server, session, AES67_SAP_STATUS_MSGTYPE_ANNOUNCE);

        return;
    }

    // timeouts also get special treatment (because they're triggered by the local stack and no origin is provided)
    if (event == aes67_sap_event_timeout){

        sapsrv_session_t * session = aes67_sapsrv_session_by_id(server, hash, ipver, ip);

        // should not occur
        if (session == NULL){
            return;
        }

        // don't let remotes interfere with locally managed sdps
        // (which implies that the hash sum will never really be zero without)
        if (session->managed_by == AES67_SAPSRV_MANAGEDBY_LOCAL){
            return;
        }

        // if hash doesn't match, ignore
        // note that remotely managed sessions have their stored hash value updated to the last announcement message
        // thus only once the last announcement message times out, we consider this an actual timeout.
        if (session->hash != hash){
            return;
        }

        // publish
        server->event_handler(server, session, aes67_sapsrv_event_timeout, &session->origin, session->payload, session->payloadlen, server->user_data);

        session_delete(server, session);

        return;
    }

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
        // ignore messages that miss expected payload start to begin with
        return;
    }

    struct aes67_sdp_originator origin;
    if (AES67_SDP_OK != aes67_sdp_origin_fromstr(&origin, o, payloadlen - (o - payload))){
        // ignore messages that do not have a valid origin
        return;
    }

    sapsrv_session_t * session = aes67_sapsrv_session_by_origin(server, &origin);

    // safety check
    if (session != NULL){

        // don't let remotes interfere with locally managed SDPs
        if (session->managed_by == AES67_SAPSRV_MANAGEDBY_LOCAL){
            // but inform host about remote, it can decide what to do, it changes are to be made
            // pass received data to host
            // (but only when it's an announcement message)
            if (event == aes67_sap_event_new || event == aes67_sap_event_updated){
                server->event_handler(server, session, aes67_sapsrv_event_remote_duplicate, &origin, payload, payloadlen, server->user_data);
            }
            return;
        }

        // if hash doesn't match, ignore, we're familiar with this session, maybe it's a duplicate
//        if (session->hash != hash){
//            return;
//        }
    }

    if (event == aes67_sap_event_new || event == aes67_sap_event_updated){

        enum aes67_sapsrv_event evt;

        if (session == NULL){
            evt = aes67_sapsrv_event_discovered;
            session = session_new(server, AES67_SAPSRV_MANAGEDBY_REMOTE, hash, ipver, ip, &origin, payload, payloadlen);
        } else {

            // IMPORTANT set hash to value of last announced one because this will be the last announcement to timeout
            session->hash = hash;

            // if previous session is not older, just skip (because is just a SAP message to prevent timeout)
            if (aes67_sdp_origin_cmpversion(&session->origin, &origin) != -1){

                session->last_activity = time(NULL);

                return;
            }

            evt = aes67_sapsrv_event_updated;

            // update originator
            memcpy(&session->origin, &origin, sizeof(struct aes67_sdp_originator));
        }

        session->last_activity = time(NULL);

        // publish
        server->event_handler(server, session, evt, &session->origin, session->payload, session->payloadlen, server->user_data);


    } else if (event == aes67_sap_event_deleted){

        // if event was not known before, there is no reason telling the host about (?)
        if (session == NULL){
            // nothing to be done
            return;
        }

        // do not check hash, assume that a delete message will first come from the originating device itself

        // publish
        server->event_handler(server, session, aes67_sapsrv_event_deleted, &session->origin, session->payload, session->payloadlen, server->user_data);

        session_delete(server, session);
    }
}

aes67_sapsrv_t
aes67_sapsrv_start(u32_t send_scopes, u16_t port, u32_t listen_scopes, unsigned int ipv6_if,
                   aes67_sapsrv_event_handler event_handler, void *user_data)
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
    server->blocking = true;
    server->ipv6_if = ipv6_if;
    server->event_handler = event_handler;
    server->user_data = user_data;

    server->first_session = NULL;

    if ((listen_scopes | send_scopes) & AES67_SAPSRV_SCOPE_IPv4){
        server->addr4.sin_family = AF_INET;
        server->addr4.sin_port = htons(port);

        server->sockfd4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (server->sockfd4 == -1) {
            free(server);
            return NULL;
        }

        if (set_sock_reuse(server->sockfd4)){
            close(server->sockfd4);
            free(server);
            return NULL;
        }

        if (bind(server->sockfd4, (struct sockaddr*)&server->addr4, sizeof(struct sockaddr_in)) == -1){
            syslog(LOG_ERR, "sapsrv ipv4 bind(): %s", strerror(errno));
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            free(server);
            return NULL;
        }

        // set non-blocking stdin
        int flags = fcntl(server->sockfd4, F_GETFL, 0);
        if (fcntl(server->sockfd4, F_SETFL, flags|O_NONBLOCK) == -1){
            syslog(LOG_ERR, "sapsrv ipv4 fcntl(sockfd4,..,O_NONBLOCK): %s", strerror(errno));
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            free(server);
            return NULL;
        }

    }

    if ((listen_scopes | send_scopes) & AES67_SAPSRV_SCOPE_IPv6){
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

        if (set_sock_reuse(server->sockfd4)){
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            close(server->sockfd6);
            free(server);
        }

        if (bind(server->sockfd6, (struct sockaddr*)&server->addr6, sizeof(struct sockaddr_in6)) == -1){
            syslog(LOG_ERR, "sapsrv ipv6 bind(): %s", strerror(errno));
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
            close(server->sockfd6);
            free(server);
            return NULL;
        }

        // set non-blocking stdin
        int flags = fcntl(server->sockfd6, F_GETFL, 0);
        if (fcntl(server->sockfd6, F_SETFL, flags|O_NONBLOCK) == -1){
            syslog(LOG_ERR, "sapsrv fcntl(sockfd6,..,O_NONBLOCK): %s", strerror(errno));
            if (server->sockfd4 != -1){
                close(server->sockfd4);
            }
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

    assert(server->sockfd4 != -1 || server->sockfd6 != -1);

    u8_t buf[AES67_SAPSRV_SDP_MAXLEN+20]; // 20 for SAP header
    ssize_t rlen;

    if (server->blocking){

        int nfds = (server->sockfd4 > server->sockfd6 ? server->sockfd4 : server->sockfd6) + 1;
        fd_set rfds;
        fd_set xfds;

        FD_ZERO(&rfds);
        FD_ZERO(&xfds);

        if (server->sockfd4 != -1){
            FD_SET(server->sockfd4, &rfds);
            FD_SET(server->sockfd4, &xfds);
        }
        if (server->sockfd6 != -1){
            FD_SET(server->sockfd6, &rfds);
            FD_SET(server->sockfd6, &xfds);
        }

        int s = select(nfds, &rfds, NULL, &xfds, NULL);
        if (s > 0){
            if ( (rlen = recv(s, buf, sizeof(buf), 0)) > 0){
                syslog(LOG_DEBUG, "sapsrv %s rx %zd", s == server->sockfd4 ? "ipv4" : "ipv6", rlen);
                aes67_sap_service_handle(&server->service, buf, rlen, server);
            }
        }
    } else {

        if (server->sockfd4 != -1){
            if ( (rlen = recv(server->sockfd4, buf, sizeof(buf), 0)) > 0){
                syslog(LOG_DEBUG, "sapsrv ipv4 rx %zd", rlen);
                aes67_sap_service_handle(&server->service, buf, rlen, server);
            }
        }

        if (server->sockfd6 != -1){
            if ( (rlen = recv(server->sockfd6, buf, sizeof(buf), 0)) > 0){
                syslog(LOG_DEBUG, "sapsrv ipv6 rx %zd", rlen);
                aes67_sap_service_handle(&server->service, buf, rlen, server);
            }
        }
    }

    aes67_sap_service_process(&server->service, sapserver);
}

aes67_sapsrv_session_t aes67_sapsrv_session_add(aes67_sapsrv_t sapserver, const u16_t hash, const enum aes67_net_ipver ipver, const u8_t * ip, const u8_t * payload, const u16_t payloadlen)
{
    assert(sapserver != NULL);
    assert(payload != NULL);
    assert(payloadlen <= AES67_SAPSRV_SDP_MAXLEN);

    u8_t * o = (u8_t*)(payload[4] == '\n' ? &payload[5] : &payload[4]);

    struct aes67_sdp_originator origin;
    if (aes67_sdp_origin_fromstr(&origin, o, payloadlen - (o - payload)) == AES67_SDP_ERROR){
//        fprintf(stderr, "invalid origin\n", o[0], o[1], o[2]);
        return NULL;
    }

    sapsrv_t * server = (sapsrv_t*)sapserver;
    sapsrv_session_t * session = session_new(server, AES67_SAPSRV_MANAGEDBY_LOCAL, hash, ipver, ip, &origin, payload, payloadlen);

    sap_send(server, session, AES67_SAP_STATUS_MSGTYPE_ANNOUNCE);

    return session;
}

void aes67_sapsrv_session_update(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, const u8_t * payload, const u16_t payloadlen)
{
    assert(sapserver != NULL);
    assert(sapsession != NULL);
    assert(payload != NULL);
    assert(payloadlen <= AES67_SAPSRV_SDP_MAXLEN);

    u8_t * o = (u8_t*)&payload[(payload[sizeof("v=0\n")] == 'o') ? sizeof("v=0\n") : sizeof("v=0\r\n")];

    struct aes67_sdp_originator origin;
    if (aes67_sdp_origin_fromstr(&origin, o, payloadlen - (o - payload)) == AES67_SDP_ERROR){
        printf("invalid origin\n");
        return;
    }

    sapsrv_t * server = (sapsrv_t*)sapserver;

    sapsrv_session_t * session = (sapsrv_session_t *)sapsession;

    session_update(server, session, &origin, payload, payloadlen);

    sap_send(server, session, AES67_SAP_STATUS_MSGTYPE_ANNOUNCE);
}

void aes67_sapsrv_session_delete(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, bool announce)
{
    assert(sapserver != NULL);
    assert(sapsession != NULL);

    sapsrv_t * server = (sapsrv_t*)sapserver;

    sapsrv_session_t * session = (sapsrv_session_t *)sapsession;

    if (announce) {
        sap_send(server, session, AES67_SAP_STATUS_MSGTYPE_DELETE);
    } else {
        struct aes67_sap_session * ss = aes67_sap_service_find(&server->service, session->hash, session->ip.ipver, session->ip.ip);
        if (ss == NULL){
            syslog(LOG_ERR, "sapsrv trying to silently delete a session that isn't registered");
        } else {
            aes67_sap_service_unregister(&server->service, ss);
        }
    }

    session_delete(sapserver, session);
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

aes67_sapsrv_session_t aes67_sapsrv_session_first(aes67_sapsrv_t sapserver)
{
    assert(sapserver != NULL);

    return ((sapsrv_t*)sapserver)->first_session;
}

aes67_sapsrv_session_t aes67_sapsrv_session_next(aes67_sapsrv_session_t session)
{
    assert(session != NULL);

    return ((sapsrv_session_t*)session)->next;
}

void aes67_sapsrv_session_get_payload(aes67_sapsrv_session_t session, u8_t ** payload, u16_t * len)
{
    assert(session != NULL);
    assert(payload != NULL);
    assert(len != NULL);

    *payload = ((sapsrv_session_t*)session)->payload;
    *len = ((sapsrv_session_t*)session)->payloadlen;
}

struct aes67_sdp_originator * aes67_sapsrv_session_get_origin(aes67_sapsrv_session_t session)
{
    assert(session != NULL);
    return &((sapsrv_session_t*)session)->origin;
}

u8_t * aes67_sapsrv_session_get_sdp(aes67_sapsrv_session_t session, u16_t * sdplen)
{
    assert(session != NULL);
    *sdplen = ((sapsrv_session_t*)session)->payloadlen;
    return ((sapsrv_session_t*)session)->payload;
}

time_t aes67_sapsrv_session_get_lastactivity(aes67_sapsrv_session_t session)
{
    assert(session != NULL);
    return ((sapsrv_session_t*)session)->last_activity;
}

u8_t aes67_sapsrv_session_get_managedby(aes67_sapsrv_session_t session)
{
    assert(session != NULL);

    return ((sapsrv_session_t*)session)->managed_by;
}
void aes67_sapsrv_session_set_managedby(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, u8_t managed_by)
{
    assert(sapserver != NULL);
    assert(sapsession != NULL);
    assert(AES67_SAPSRV_MANAGEDBY_ISVALID(managed_by));

    sapsrv_t * server = sapserver;
    sapsrv_session_t * session = sapsession;

    struct aes67_sap_session * ss = aes67_sap_service_find(&server->service, session->hash, session->ip.ipver, session->ip.ip);
    if (ss != NULL){
        ss->stat = (ss->stat & ~AES67_SAP_SESSION_STAT_SRC) | (managed_by == AES67_SAPSRV_MANAGEDBY_LOCAL ? AES67_SAP_SESSION_STAT_SRC_IS_SELF : AES67_SAP_SESSION_STAT_SRC_IS_OTHER);
    }

    session->managed_by = managed_by;
}