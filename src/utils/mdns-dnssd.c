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

enum restype {
    restype_undefined,
    restype_browse,
    restype_resolve,
    restype_lookup_browse,
    restype_lookup_resolve,
};

#define restype_isvalid(x) ( \
    (x) == restype_browse || \
    (x) == restype_resolve || \
    (x) == restype_lookup_browse || \
    (x) == restype_lookup_resolve \
)

struct resource_st;

typedef struct context_st {
    DNSServiceRef sharedRef;
    struct resource_st * first_resource;
} context_t;

typedef struct resource_st {
    context_t * ctx;
    enum restype type;
    DNSServiceRef serviceRef;
    enum aes67_mdns_result result;
    u8_t * serviceName;
    u8_t * regType;
    aes67_mdns_browse_callback callback;
    DNSServiceErrorType errorCode;
    void * user_data;
    struct resource_st * next;
    struct resource_st * parent;
} resource_t;


//static struct resource * first_resource = NULL;

static resource_t *resource_new(context_t * ctx, enum restype restype, void *callback, void *context, resource_t *parent);
static void resource_link(resource_t *res);
static void resource_delete(resource_t *res);

static ssize_t to_regtype(char * regtype, size_t maxlen, const u8_t * type, const u8_t * subtype);

static void browse_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * serviceName, const char * regtype, const char * replyDomain, void * context);
static aes67_mdns_resource_t browse_start(resource_t * res, const u8_t * type, const u8_t * subtype, const u8_t * domain);

static void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context);
static aes67_mdns_resource_t resolve_start(resource_t * res, const u8_t * name, const u8_t * type, const u8_t * domain);

static resource_t * resource_new(context_t * ctx, enum restype restype, void *callback, void *context, resource_t *parent)
{
    assert(ctx != NULL);
    assert(restype_isvalid(restype));

    resource_t * res = malloc(sizeof(resource_t));

    res->ctx = ctx;
    res->type = restype;
    res->serviceRef = NULL;
    res->serviceName = NULL;
    res->regType = NULL;
    res->callback = callback;
    res->user_data = context;

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

    free(res);
}

static ssize_t to_regtype(char * regtype, size_t maxlen, const u8_t * type, const u8_t * subtype)
{
    u32_t l = strlen((char*)type);
    u32_t ls = subtype == NULL ? 0 : strlen((char*)subtype);

    assert(l + ls < maxlen-2);

    memcpy(regtype, type, l);

    if (ls > 0){
        regtype[l++] = ',';
        memcpy(&regtype[l], subtype, ls);
        l += ls;
    }

    regtype[l] = '\0';

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
//    printf("browse: flags=%d if=%d err=%d %s %s.%s\n", flags, interfaceIndex, errorCode, regtype, serviceName, replyDomain);

    resource_t * res = (resource_t*)context;

    assert(res->type == restype_browse || res->type == restype_lookup_browse);


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
        ((aes67_mdns_browse_callback)res->callback)(res, result, (const u8_t*)regtype, (const u8_t*)serviceName, (const u8_t*)replyDomain, res->user_data);

    } else if (res->type == restype_lookup_browse){

        if (errorCode != kDNSServiceErr_NoError){
            ((aes67_mdns_lookup_callback)res->callback)(res, aes67_mdns_result_error, NULL, NULL, NULL, 0, 0, NULL, res->user_data);
            return;
        }

        resource_t * res2 = resource_new(res->ctx, restype_lookup_resolve, res->callback, res->user_data, res);

        res2->result = result;

        if (regtype != NULL){
            res2->regType = calloc(1, strlen(regtype)+1);
            strcpy((char*)res2->regType, regtype);
        }
        if (serviceName != NULL){
            res2->serviceName = calloc(1, strlen(serviceName)+1);
            strcpy((char*)res2->serviceName, serviceName);
        }

        resolve_start(res2, (const u8_t*)serviceName, (const u8_t*)regtype, (const u8_t*)replyDomain);
    }


}

static aes67_mdns_resource_t browse_start(resource_t * res, const u8_t * type, const u8_t * subtype, const u8_t * domain)
{
    assert(res != NULL);
    assert(type != NULL);

    DNSServiceFlags flags = kDNSServiceFlagsShareConnection;
    u32_t interfaceIndex = 0; // all possible interfaces

    char regtype[256];
    to_regtype(regtype, sizeof(regtype), type, subtype);

    res->serviceRef = res->ctx->sharedRef;

    DNSServiceErrorType errorCode = DNSServiceBrowse(&res->serviceRef, flags, interfaceIndex, regtype,
                                                     (const char *) domain, browse_callback, res);
    if (errorCode != kDNSServiceErr_NoError){
        resource_delete(res);
        return NULL;
    }

    resource_link(res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_browse_start(aes67_mdns_context_t ctx, const u8_t *type, const u8_t *subtype, const u8_t *domain,
                        aes67_mdns_browse_callback callback, void *user_data)
{
    resource_t * res = resource_new(ctx, restype_browse, callback, user_data, NULL);
    return browse_start(res, type, subtype, domain);
}

aes67_mdns_resource_t
aes67_mdns_lookup_start(aes67_mdns_context_t ctx, const u8_t *type, const u8_t *subtype, const u8_t *domain,
                        aes67_mdns_lookup_callback callback, void *user_data)
{
    resource_t * res = resource_new(ctx, restype_lookup_browse, callback, user_data, NULL);
    return browse_start(res, type, subtype, domain);
}

static void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
//    printf("resolve: flags=%d if=%d err=%d %s %s\n", flags, interfaceIndex, errorCode, fullname, hosttarget);

    resource_t * res = (resource_t*)context;

    assert(res->type == restype_resolve || res->type == restype_lookup_resolve);

    enum aes67_mdns_result result;

    if (errorCode != kDNSServiceErr_NoError){
        result = aes67_mdns_result_error;
    } else if (flags & kDNSServiceFlagsAdd){
        result = aes67_mdns_result_discovered;
    } else {
        result = aes67_mdns_result_terminated;
    }

    res->errorCode = errorCode;

    if (res->type == restype_resolve) {
        ((aes67_mdns_resolve_callback)res->callback)(res, result, (const u8_t*)fullname, (const u8_t*)hosttarget, ntohs(port), txtlen, (const u8_t*)txt, res->user_data);
    } else if (res->type == restype_lookup_resolve){

        if (result != aes67_mdns_result_error){
            result = res->result;
        }

        ((aes67_mdns_lookup_callback)res->callback)(res, result, (const u8_t*)res->regType, (const u8_t*)res->serviceName, (const u8_t*)hosttarget, ntohs(port), txtlen, (const u8_t*)txt, res->user_data);
    }


    if (res->type == restype_lookup_resolve){
        resource_delete(res);
    }

}

static aes67_mdns_resource_t resolve_start(resource_t * res, const u8_t * name, const u8_t * type, const u8_t * domain)
{
    assert(res != NULL);
    assert(type != NULL);

    DNSServiceFlags flags = kDNSServiceFlagsShareConnection;
    u32_t interfaceIndex = 0; // all possible interfaces

    char * domain_ = domain == NULL ? "local." : (char*)domain;

    res->serviceRef = res->ctx->sharedRef;

    DNSServiceErrorType errorCode = DNSServiceResolve(&res->serviceRef, flags, interfaceIndex, (const char *)name, ( char*)type,
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
aes67_mdns_resolve_start(aes67_mdns_context_t ctx, const u8_t *name, const u8_t *type, const u8_t *domain,
                         aes67_mdns_resolve_callback callback, void *user_data)
{
    assert(ctx != NULL);

    resource_t * res = resource_new(ctx, restype_resolve, callback, user_data, NULL);
    return resolve_start(res, name, type, domain);
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