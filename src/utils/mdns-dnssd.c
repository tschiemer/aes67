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
 * - use a single shared connection? -> kDNSServiceFlagsShareConnection
 *    -> use for two-step lookup (only)?
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

struct resource {
    enum restype type;
    DNSServiceRef serviceRef;
    aes67_mdns_browse_callback callback;
    void * context;
    struct resource * next;
    struct resource * parent;
};


static struct resource * first_resource = NULL;

static struct resource *new_resource(enum restype restype, void *callback, void *context, struct resource *parent);
static void link_resource(struct resource * res);
static void delete_resource(struct resource * res);

static ssize_t to_regtype(char * regtype, size_t maxlen, const u8_t * type, const u8_t * subtype);

static void browse_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * serviceName, const char * regtype, const char * replyDomain, void * context);
static aes67_mdns_resource_t browse_start(struct resource * res, const u8_t * type, const u8_t * subtype, const u8_t * domain);

static void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context);
static aes67_mdns_resource_t resolve_start(struct resource * res, const u8_t * name, const u8_t * type, const u8_t * domain);

struct resource *new_resource(enum restype restype, void *callback, void *context, struct resource *parent)
{
    assert(restype_isvalid(restype));

    struct resource * res = malloc(sizeof(struct resource));

    res->type = restype;
    res->serviceRef = NULL;
    res->callback = callback;
    res->context = context;

    return res;
}

void link_resource(struct resource * res)
{
    assert(res != NULL);

    res->next = first_resource;
    first_resource = res;
}

void delete_resource(struct resource * res)
{
    assert(res != NULL);

    if (first_resource == res){
        first_resource = res->next;
    } else {
        // if resource has generated childen, delete them aswell (only if first resource)
        while (first_resource->parent == res){
            delete_resource(first_resource);
        }

        struct resource * next = first_resource;
        while (next != NULL){
            // if resource has generated childen, delete
            if (next->parent == res){
                struct resource * child = next;
                next = next->next;
                delete_resource(child);
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

    free(res);
}

ssize_t to_regtype(char * regtype, size_t maxlen, const u8_t * type, const u8_t * subtype)
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

s32_t aes67_mdns_init(void)
{
    if (first_resource != NULL) {
        aes67_mdns_deinit();
    }

    return EXIT_SUCCESS;
}

void aes67_mdns_deinit(void)
{
    while(first_resource != NULL){
        aes67_mdns_stop(first_resource);
    }
}


void browse_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * serviceName, const char * regtype, const char * replyDomain, void * context)
{
//    printf("%d %s %s.%s\n", errorCode, regtype, serviceName, replyDomain);

    struct resource * res = (struct resource*)context;

    assert(res->type == restype_browse || res->type == restype_lookup_browse);

    if (res->type == restype_browse){
        ((aes67_mdns_browse_callback)res->callback)(res, errorCode, (const u8_t*)regtype, (const u8_t*)serviceName, (const u8_t*)replyDomain, res->context);

    } else if (res->type == restype_lookup_browse){

        if (errorCode != kDNSServiceErr_NoError){
            ((aes67_mdns_resolve_callback)res->callback)(res, errorCode, NULL, NULL, 0, 0, NULL, res->context);
            return;
        }

        struct resource * res2 = new_resource(restype_lookup_resolve, res->callback, res->context, res);
        resolve_start(res2, (const u8_t*)serviceName, (const u8_t*)regtype, (const u8_t*)replyDomain);
    }


}

aes67_mdns_resource_t browse_start(struct resource * res, const u8_t * type, const u8_t * subtype, const u8_t * domain)
{
    assert(res != NULL);
    assert(type != NULL);

    DNSServiceFlags flags = 0; // reserved for future use
    u32_t interfaceIndex = 0; // all possible interfaces

    char regtype[256];
    to_regtype(regtype, sizeof(regtype), type, subtype);

    DNSServiceErrorType errorCode = DNSServiceBrowse(&res->serviceRef, flags, interfaceIndex, regtype,
                                                     (const char *) domain, browse_callback, res);
    if (errorCode != kDNSServiceErr_NoError){
        delete_resource(res);
        return NULL;
    }

    link_resource(res);

    return res;
}

aes67_mdns_resource_t aes67_mdns_browse_start(const u8_t * type, const u8_t * subtype, const u8_t * domain, aes67_mdns_browse_callback callback, void * context)
{
    struct resource * res = new_resource(restype_browse, callback, context, NULL);
    return browse_start(res, type, subtype, domain);
}

aes67_mdns_resource_t aes67_mdns_lookup_start(const u8_t * type, const u8_t * subtype, const u8_t * domain, aes67_mdns_resolve_callback callback, void * context)
{
    struct resource * res = new_resource(restype_lookup_browse, callback, context, NULL);
    return browse_start(res, type, subtype, domain);
}

void resolve_callback(DNSServiceRef ref, DNSServiceFlags flags, u32_t interfaceIndex, DNSServiceErrorType errorCode, const char * fullname, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
    struct resource * res = (struct resource*)context;

    assert(res->type == restype_resolve || res->type == restype_lookup_resolve);

//    if (res->type == restype_browse) {
        ((aes67_mdns_resolve_callback)res->callback)(res, errorCode, (const u8_t*)fullname, (const u8_t*)hosttarget, ntohs(port), txtlen, (const u8_t*)txt, res->context);
//    }


    if (res->type == restype_lookup_resolve){
        delete_resource(res);
    }

}

aes67_mdns_resource_t resolve_start(struct resource * res, const u8_t * name, const u8_t * type, const u8_t * domain)
{
    assert(res != NULL);
    assert(type != NULL);

    DNSServiceFlags flags = 0; // reserved for future use
    u32_t interfaceIndex = 0; // all possible interfaces

    char * domain_ = domain == NULL ? "local." : (char*)domain;

    DNSServiceErrorType errorCode = DNSServiceResolve(&res->serviceRef, flags, interfaceIndex, (const char *)name, ( char*)type,
                                                      (const char *) domain_, resolve_callback, res);
    if (errorCode != kDNSServiceErr_NoError){
//        printf("%d\n", errorCode);
        delete_resource(res);
        return NULL;
    }

    link_resource(res);

    return res;
}

aes67_mdns_resource_t aes67_mdns_resolve_start(const u8_t * name, const u8_t * type, const u8_t * domain, aes67_mdns_resolve_callback callback, void * context)
{
    struct resource * res = new_resource(restype_resolve, callback, context, NULL);
    return resolve_start(res, name, type, domain);
}



void aes67_mdns_stop(aes67_mdns_resource_t res)
{
    assert(res != NULL);

    delete_resource(res);
}



void aes67_mdns_process(u32_t timeout_usec)
{
    struct resource * res = first_resource;

    while (res != NULL){

        if (res->serviceRef != NULL){
            dnssd_sock_t dns_sd_fd = DNSServiceRefSockFD(res->serviceRef);


            int nfds      = dns_sd_fd + 1;
            fd_set readfds;

            FD_ZERO(&readfds);
            FD_SET(dns_sd_fd, &readfds);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = timeout_usec;

            int retval = select(nfds, &readfds, NULL, NULL, &tv);
            if (retval == -1){
                perror("select()");
            } else if (retval) {
                DNSServiceProcessResult(res->serviceRef);
            } else {
                // timeout
            }
        }

        res = res->next;
    }
}