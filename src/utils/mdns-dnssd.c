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

/**
 * TODOs
 *
 * - what happens when a device explicitly invalidates its records?
 */

#include "aes67/utils/mdns.h"

#include <dns_sd.h>
#include <assert.h>
#include <string.h>
#include <dns.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

enum restype {
    restype_undefined,
    restype_browse,
    restype_resolve_resolve,
    restype_resolve_getaddr,
    restype_resolve2_browse,
    restype_resolve2_resolve,
    restype_resolve2_getaddr,
};

#define restype_isvalid(x) ( \
    (x) == restype_browse || \
    (x) == restype_resolve_resolve || \
    (x) == restype_resolve_getaddr || \
    (x) == restype_resolve2_browse || \
    (x) == restype_resolve2_resolve || \
    (x) == restype_resolve2_getaddr \
)

struct resource_st;

typedef struct context_st {
    DNSServiceRef sharedRef;
    struct resource_st * first_resource;
} context_t;

typedef struct resource_st {
    context_t * ctx;
    struct resource_st * next;
    struct resource_st * parent;

    enum restype type;

    DNSServiceRef serviceRef;
    DNSServiceErrorType errorCode;

    aes67_mdns_browse_callback callback;
    void * user_data;

    enum aes67_mdns_result result;
    char * serviceName;
    char * regType;
    char * hostTarget;
    u16_t port;
    u16_t txtlen;
    u8_t * txt;

} resource_t;


static resource_t *resource_new(context_t * ctx, enum restype restype, void *callback, void *context, resource_t *parent);
static void resource_link(resource_t *res);
static void resource_delete(resource_t *res);

static size_t to_regtype(char * regtype, size_t maxlen, const char * type);

static void browse_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * serviceName, const char * regtype, const char * replyDomain, void * context);
static aes67_mdns_resource_t browse_start(resource_t *res, const char *type, const char *domain);

static void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context);
static aes67_mdns_resource_t resolve_start(resource_t * res, const char * name, const char * type, const char * domain);

static void getaddr_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *hostname, const struct sockaddr *address, uint32_t ttl, void *context);
static aes67_mdns_resource_t getaddr_start(resource_t * res, const char * hostname);

static resource_t * resource_new(context_t * ctx, enum restype restype, void *callback, void *context, resource_t *parent)
{
    assert(ctx != NULL);
    assert(restype_isvalid(restype));

    resource_t * res = malloc(sizeof(resource_t));

    res->ctx = ctx;
    res->type = restype;
    res->callback = callback;
    res->user_data = context;

    res->serviceRef = NULL;
    res->serviceName = NULL;
    res->regType = NULL;
    res->hostTarget = NULL;
    res->port = 0;
    res->txtlen = 0;
    res->txt = NULL;

    return res;
}

static void resource_link(resource_t *res)
{
    assert(res != NULL);

    context_t * ctx = res->ctx;

    res->next = ctx->first_resource;
    ctx->first_resource = res;
}

static void resource_delete(resource_t *res)
{
    assert(res != NULL);
    assert(res->ctx != NULL);

    context_t * ctx = res->ctx;

    if (ctx->first_resource == res){
        ctx->first_resource = res->next;
    } else {
        // if resource has generated childen, delete them aswell (only if first resource)
        while (ctx->first_resource->parent == res){
            resource_delete(ctx->first_resource);
        }

        resource_t * next = ctx->first_resource;
        while (next != NULL){
            // if resource has generated childen, delete
            if (next->parent == res){
                resource_t * child = next;
                next = next->next;
                resource_delete(child);
            }
            else if (next->next == res){
                next->next = res->next;
            } else {
                next = next->next;
            }
        }
    }


    if (res->serviceRef != NULL){
        DNSServiceRefDeallocate( res->serviceRef );
    }
    if (res->serviceName != NULL){
        free(res->serviceName);
        res->serviceName = NULL;
    }
    if (res->regType != NULL){
        free(res->regType);
        res->regType = NULL;
    }
    if (res->hostTarget != NULL){
        free(res->hostTarget);
        res->hostTarget = NULL;
    }
    if (res->txt != NULL){
        free(res->txt);
        res->txt = NULL;
    }

    free(res);
}

static size_t to_regtype(char * regtype, size_t maxlen, const char * type)
{
    u32_t l = strlen((char*)type);

    assert(l < maxlen);

    // because dns-sd wants subtypes in the form of "_rtsp._tcp,_ravenna" instead of "_ravenna._sub._rtsp._tcp"
    // we'll have to change the type to be queried
    char * sub = strstr(type, "._sub.");
    if (sub == NULL){
        strcpy(regtype, type);
    } else {
        size_t ls = sub - type;
        size_t lp = l - ls - sizeof("._sub");
        memcpy(regtype, &sub[sizeof("._sub")], lp);
        regtype[lp] = ',';
        memcpy(&regtype[lp+1], type, ls);

        l = ls + lp + 1;
        regtype[l] = '\0';
    }

    return l;
}

aes67_mdns_context_t aes67_mdns_new(void)
{

    context_t * ctx = calloc(1, sizeof(context_t));

    if (ctx == NULL){
        return NULL;
    }

    DNSServiceErrorType error = DNSServiceCreateConnection(&ctx->sharedRef);
    if (error){
        free(ctx);
        return NULL;
    }

    return ctx;
}

void aes67_mdns_delete(aes67_mdns_context_t ctx)
{
    context_t * __ctx = ctx;

    while(__ctx->first_resource != NULL){
        aes67_mdns_stop(__ctx->first_resource);
    }
}


static void browse_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * serviceName, const char * regtype, const char * replyDomain, void * context)
{
//    printf("browse: flags=%d if=%d err=%d %s %s %s\n", flags, interfaceIndex, errorCode, regtype, serviceName, replyDomain);

    resource_t * res = (resource_t*)context;

    assert(res->type == restype_browse || res->type == restype_resolve2_browse);


    enum aes67_mdns_result result;

    if (errorCode!= kDNSServiceErr_NoError){
        result = aes67_mdns_result_error;
    } else if (flags & kDNSServiceFlagsAdd){
        result = aes67_mdns_result_discovered;
    } else {
        result = aes67_mdns_result_terminated;
    }

    res->errorCode = errorCode;

    if (res->type == restype_browse){
        ((aes67_mdns_browse_callback)res->callback)(res, result, regtype, serviceName, replyDomain, res->user_data);

    } else if (res->type == restype_resolve2_browse){

        if (errorCode != kDNSServiceErr_NoError){
            ((aes67_mdns_resolve_callback)res->callback)(res, aes67_mdns_result_error, NULL, NULL, NULL, 0, 0, NULL, aes67_net_ipver_undefined, NULL, 0, res->user_data);
            return;
        }

        resource_t * res2 = resource_new(res->ctx, restype_resolve2_resolve, res->callback, res->user_data, res);

        res2->result = result;

        if (regtype != NULL){
            res2->regType = calloc(1, strlen(regtype)+1);
            strcpy((char*)res2->regType, regtype);
        }
        if (serviceName != NULL){
            res2->serviceName = calloc(1, strlen(serviceName)+1);
            strcpy((char*)res2->serviceName, serviceName);
        }

        resolve_start(res2, (const char*)serviceName, (const char*)regtype, (const char*)replyDomain);
    }


}

static aes67_mdns_resource_t browse_start(resource_t *res, const char *type, const char *domain)
{
    assert(res != NULL);
    assert(type != NULL);

    // convert to dns-sd style type
    char regtype[256];
    to_regtype(regtype, sizeof(regtype), type);

    DNSServiceFlags flags = kDNSServiceFlagsShareConnection;
    u32_t interfaceIndex = 0; // all possible interfaces

    res->serviceRef = res->ctx->sharedRef;

    DNSServiceErrorType errorCode = DNSServiceBrowse(&res->serviceRef, flags, interfaceIndex, (const char *)regtype,
                                                     (const char *) domain, browse_callback, res);
    if (errorCode != kDNSServiceErr_NoError){
        resource_delete(res);
        return NULL;
    }

    resource_link(res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_browse_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                        aes67_mdns_browse_callback callback, void *user_data)
{
    resource_t * res = resource_new(ctx, restype_browse, callback, user_data, NULL);
    return browse_start(res, type, domain);
}

aes67_mdns_resource_t
aes67_mdns_resolve2_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                          aes67_mdns_resolve_callback callback, void *user_data)
{
    resource_t * res = resource_new(ctx, restype_resolve2_browse, callback, user_data, NULL);
    return browse_start(res, type, domain);
}

static void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
//    printf("resolve: flags=%d if=%d err=%d %s %s\n", flags, interfaceIndex, errorCode, fullname, hosttarget);

    resource_t * res = (resource_t*)context;

    assert(res->type == restype_resolve_resolve || res->type == restype_resolve2_resolve);

    enum aes67_mdns_result result;

    if (errorCode != kDNSServiceErr_NoError){
        result = aes67_mdns_result_error;
    } else if (flags & kDNSServiceFlagsAdd){
        result = aes67_mdns_result_discovered;
    } else {
        result = aes67_mdns_result_terminated;
    }

    res->errorCode = errorCode;

    if (errorCode != kDNSServiceErr_NoError){
        ((aes67_mdns_resolve_callback)res->callback)(res, result, res->regType, res->serviceName, NULL, 0, 0, NULL, aes67_net_ipver_undefined, NULL, 0, res->user_data);
    } else {

        resource_t * res2;

        if (res->type == restype_resolve_resolve){
            res2 = resource_new(res->ctx, restype_resolve_getaddr, res->callback, res->user_data, res);
            res2->result = result;
        } else {
            res2 = resource_new(res->ctx, restype_resolve2_getaddr, res->callback, res->user_data, res);
            res2->result = res->result;
        }

        if (res->serviceName != NULL){
            res2->serviceName = calloc(1, strlen(res->serviceName)+1);
            strcpy(res2->serviceName,res->serviceName);
        }

        if (res->regType != NULL){
            res2->regType = calloc(1, strlen(res->regType)+1);
            strcpy(res2->regType, res->regType);
        }

        if (hosttarget != NULL){
            res2->hostTarget = calloc(1, strlen(hosttarget)+1);
            strcpy(res2->hostTarget, hosttarget);
        }
        res2->port = ntohs(port);
        res2->txtlen = txtlen;

        if (txtlen > 0){
            res2->txt = calloc(1, txtlen);
            memcpy(res2->txt, txt, txtlen);
        }

        getaddr_start(res2, hosttarget);
    }

    if (res->type == restype_resolve2_getaddr && (flags & kDNSServiceFlagsMoreComing) == 0){
        resource_delete(res);
    }
}

static aes67_mdns_resource_t resolve_start(resource_t * res, const char * name, const char * type, const char * domain)
{
    assert(res != NULL);
    assert(type != NULL);

    // convert to dns-sd style type
    char regtype[256];
    to_regtype(regtype, sizeof(regtype), type);

    DNSServiceFlags flags = kDNSServiceFlagsShareConnection;
    u32_t interfaceIndex = 0; // all possible interfaces

    char * domain_ = domain == NULL ? "local." : (char*)domain;

    res->serviceRef = res->ctx->sharedRef;

    DNSServiceErrorType errorCode = DNSServiceResolve(&res->serviceRef, flags, interfaceIndex, (const char *)name, (const char*)regtype,
                                                      (const char *) domain_, resolve_callback, res);
    if (errorCode != kDNSServiceErr_NoError){
//        printf("%d\n", errorCode);
        resource_delete(res);
        return NULL;
    }

    resource_link(res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_resolve_start(aes67_mdns_context_t ctx, const char *type, const char *name, const char *domain,
                         aes67_mdns_resolve_callback callback, void *user_data)
{
    assert(ctx != NULL);
    assert(type != NULL);
    assert(name != NULL);

    resource_t * res = resource_new(ctx, restype_resolve_resolve, callback, user_data, NULL);

    res->regType = calloc(1, strlen(type)+1);
    strcpy(res->regType, type);

    res->serviceName = calloc(1, strlen(name)+1);
    strcpy(res->serviceName, name);

    return resolve_start(res, name, type, domain);
}

static void getaddr_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *hostname, const struct sockaddr *address, uint32_t ttl, void *context)
{
//    printf("getaddr %d\n", errorCode);

    resource_t * res = (resource_t*)context;

    assert(res->type == restype_resolve_getaddr || res->type == restype_resolve2_getaddr );

    enum aes67_mdns_result result;

    if (errorCode != kDNSServiceErr_NoError){
        result = aes67_mdns_result_error;
    } else if (res->type == restype_resolve2_getaddr) {
        result = res->result;
    } else {
        result = aes67_mdns_result_discovered;
    }

    enum aes67_net_ipver ipver = aes67_net_ipver_undefined;
    u8_t * ip = NULL;

    if (address != NULL){
        if (address->sa_family == AF_INET){
            ipver = aes67_net_ipver_4;
            ip = (u8_t*)&((struct sockaddr_in *)address)->sin_addr;
        } else if (address->sa_family == AF_INET6){
            ipver = aes67_net_ipver_6;
            ip = (u8_t*)&((struct sockaddr_in6 *)address)->sin6_addr;
        }
    }

    ((aes67_mdns_resolve_callback) res->callback)(res, result, res->regType, res->serviceName, res->hostTarget,
                                                  res->port, res->txtlen, res->txt, ipver, ip, ttl, res->user_data);

    if (res->type == restype_resolve2_getaddr && (flags & kDNSServiceFlagsMoreComing) == 0) {
        resource_delete(res);
    }
}

static aes67_mdns_resource_t getaddr_start(resource_t * res, const char * hostname)
{
    assert(res != NULL);

    DNSServiceFlags flags = kDNSServiceFlagsShareConnection;
    u32_t interfaceIndex = 0; // all possible interfaces
    DNSServiceProtocol protocol = kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6;

    res->serviceRef = res->ctx->sharedRef;

    DNSServiceErrorType errorCode = DNSServiceGetAddrInfo(&res->serviceRef, flags, interfaceIndex, protocol, hostname,
                                                          getaddr_callback, res);

    if (errorCode != kDNSServiceErr_NoError){
//        printf("%d\n", errorCode);
        resource_delete(res);
        return NULL;
    }

    resource_link(res);

    return res;
}

void aes67_mdns_stop(aes67_mdns_resource_t res)
{
    assert(res != NULL);

    resource_delete(res);
}



void aes67_mdns_process(aes67_mdns_context_t ctx, struct timeval *timeout)
{
    assert(ctx != NULL);

    context_t * __ctx = (context_t*)ctx;

    dnssd_sock_t dns_sd_fd = DNSServiceRefSockFD(__ctx->sharedRef);

    int nfds = dns_sd_fd + 1;
    struct fd_set fds;

    FD_ZERO(&fds);
    FD_SET(dns_sd_fd, &fds);

    int retval = select(nfds, &fds, NULL, &fds, timeout);
    if (retval > 0){
        DNSServiceProcessResult(__ctx->sharedRef);
    }
}

void aes67_mdns_getsockfds(aes67_mdns_context_t ctx, int fds[], int *nfds)
{
    assert(ctx != NULL);
    assert(fds != NULL);
    assert(nfds != NULL);

    context_t * __ctx = ctx;

    if (__ctx->sharedRef){
        fds[0] = DNSServiceRefSockFD(__ctx->sharedRef);
        *nfds = 1;
    }
}

int aes67_mdns_geterrcode(aes67_mdns_resource_t res)
{
    assert(res != NULL);

    resource_t * __res = res;

    return __res->errorCode;
}