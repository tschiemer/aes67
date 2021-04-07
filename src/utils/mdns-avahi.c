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

#include "aes67/utils/mdns.h"

#include <assert.h>
#include <string.h>
//#include <syslog.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

//#error TODO see https://www.avahi.org/doxygen/html/client-browse-services_8c-example.html

// forward decl
struct context_st;

enum restype {
    restype_undefined,
    restype_browse,
    restype_resolve,
    restype_resolve2,
    restype_register_pending,
    restype_register_done,
    restype_publish_service_pending,
    restype_publish_service_done,
};

typedef struct resource_st {
    struct context_st * context;
    void * res;
    enum restype type;
    enum aes67_mdns_result result;
    int errno;

    void * callback;
    void * user_data;

    struct resource_st * next;
} resource_t;


typedef struct context_st {
    AvahiSimplePoll *simple_poll;
    AvahiClient *client;

    resource_t * first_resource;
} context_t;

static resource_t * resource_new(context_t * context, enum restype restype, void *callback, void * user_data)
{

    resource_t * r = calloc(1, sizeof(resource_t));

    r->context = context;
    r->type = restype;

    r->callback = callback;
    r->user_data = user_data;


    return r;
}

static void resource_link(context_t * context, resource_t * res)
{
    res->next = context->first_resource;
    context->first_resource = res;
}

static void resource_delete(context_t * context, resource_t * res)
{
    if (context->first_resource == res){
        context->first_resource = res->next;
    } else {
        resource_t * prev = context->first_resource;

        while(prev != NULL){

            if (prev->next == res){
                prev->next = res->next;
                break;
            }

            prev = prev->next;
        }
    }

    if (res->type == restype_browse && res->res){
        avahi_service_browser_free(res->res);
    }
    else if (res->type == restype_resolve && res->res){
        avahi_service_resolver_free(res->res);
    }

    free(res);
}

static char* avahi_string_list_to_raw(AvahiStringList *l, uint16_t * len) {
    AvahiStringList *n;
    size_t s = 0;
    char *t, *e;

    *len = 0;

    for (n = l; n; n = n->next) {
        s += 1 + n->size; /* +1 for the leading segment length byte */
    }

    if (!(t = e = malloc(s+1)))
        return NULL;

    l = avahi_string_list_reverse(l);

    for (n = l; n; n = n->next) {
        *(e++) = n->size;
        for(int i = 0; i < n->size; i++){
            *(e++) = n->text[i];
        }

        assert(e);
    }

    l = avahi_string_list_reverse(l);

//    *e = 0; // actually, this is not needed, but let's play it safe.

    // make sure to tell caller size of total txt
    *len = s;

    return t;
}

static void resolve_callback(
        AvahiServiceResolver *r,
        AVAHI_GCC_UNUSED AvahiIfIndex interface,
        AVAHI_GCC_UNUSED AvahiProtocol protocol,
        AvahiResolverEvent event,
        const char *name,
        const char *type,
        const char *domain,
        const char *host_name,
        const AvahiAddress *address,
        uint16_t port,
        AvahiStringList *txt,
        AvahiLookupResultFlags flags,
        AVAHI_GCC_UNUSED void* userdata) {

    resource_t * res = userdata;
    assert(res);

    assert(r);

    char * txtstr = NULL;
    uint16_t txtlen = 0;

    enum aes67_mdns_result result = aes67_mdns_result_error;

    /* Called whenever a service has been resolved successfully or timed out */
    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
//            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));
            result = aes67_mdns_result_error;
            break;

        case AVAHI_RESOLVER_FOUND: {
//            fprintf(stderr, "Service '%s' of type '%s' in domain '%s':\n", name, type, domain);
            if (res->type == restype_resolve2){
                result = res->result;
            } else {
                result = aes67_mdns_result_discovered;
            }
            txtstr = avahi_string_list_to_raw(txt, &txtlen);
            break;
        }
    }


    enum aes67_net_ipver ipver = aes67_net_ipver_undefined;
    const uint8_t * ip = NULL;
    if (address->proto == AVAHI_PROTO_INET){
        ipver = aes67_net_ipver_4;
        ip = (uint8_t*)&address->data.ipv4.address;
    } else if (address->proto == AVAHI_PROTO_INET6){
        ipver = aes67_net_ipver_6;
        ip = address->data.ipv6.address;
    }

    uint16_t ttl = 0;

    ((aes67_mdns_resolve_callback) res->callback)(res, result, type, name, host_name,
                                                  port, txtlen, (uint8_t*)txtstr, ipver, ip, ttl, res->user_data);
    if (txtstr)
        free(txtstr);

    avahi_service_resolver_free(r);
}
static void browse_callback(
        AvahiServiceBrowser *b,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char *name,
        const char *type,
        const char *domain,
        AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
        void* userdata) {

    resource_t * res = userdata;
    assert(res);

    enum aes67_mdns_result result;

    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
//            fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b))));
//            avahi_simple_poll_quit(res->context->simple_poll);
            result = aes67_mdns_result_error;
            return;
        case AVAHI_BROWSER_NEW:
//            fprintf(stderr, "(Browser) NEW: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            result = aes67_mdns_result_discovered;
            break;
        case AVAHI_BROWSER_REMOVE:
//            fprintf(stderr, "(Browser) REMOVE: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            result = aes67_mdns_result_terminated;
            break;

        case AVAHI_BROWSER_ALL_FOR_NOW:
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
//            fprintf(stderr, "(Browser) %s\n", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
            return;

        default:
            // ignore
            return;
    }



    if (res->type == restype_browse){
        ((aes67_mdns_browse_callback)res->callback)(res, result, type, name, domain, res->user_data);
    }
    else if (res->type == restype_resolve2){

        if (result == aes67_mdns_result_error){
            ((aes67_mdns_resolve_callback)res->callback)(res, aes67_mdns_result_error, NULL, NULL, NULL, 0, 0, NULL, aes67_net_ipver_undefined, NULL, 0, res->user_data);
            return;
        }

        res->result = result;

        if (!(avahi_service_resolver_new(res->context->client, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, res))) {
            fprintf(stderr, "Failed to resolve service '%s': %s\n", name,
                    avahi_strerror(avahi_client_errno(res->context->client)));
        }
    }
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);

    context_t * context = userdata;

    /* Called whenever the client or server state changes */

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
//            create_services(c);
            break;
        case AVAHI_CLIENT_FAILURE:
            fprintf(stderr, "Client failure: %s\n", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(context->simple_poll);
            break;
        case AVAHI_CLIENT_S_COLLISION:
            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */
        case AVAHI_CLIENT_S_REGISTERING:
            /* The server records are now being established. This
             * might be caused by a host name change. We need to wait
             * for our own records to register until the host name is
             * properly esatblished. */
            //TODO reset all registered services
//            if (group)
//                avahi_entry_group_reset(group);
            break;
        case AVAHI_CLIENT_CONNECTING:
            ;
    }
}


aes67_mdns_context_t  aes67_mdns_new(void)
{
    int error;

    context_t * context = calloc(1, sizeof(context_t));

    /* Allocate main loop object */
    if (!(context->simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        free(context);
        return NULL;
    }

    /* Allocate a new client */
    context->client = avahi_client_new(avahi_simple_poll_get(context->simple_poll), 0, client_callback, context, &error);

    /* Check wether creating the client object succeeded */
    if (!context->client) {
        fprintf(stderr, "Failed to create client: %s\n", avahi_strerror(error));
        aes67_mdns_delete(context);
        return NULL;
    }

    return context;
}

void aes67_mdns_delete(aes67_mdns_context_t ctx)
{
    assert(ctx != NULL);

    context_t * context = ctx;

    if (context->client){
        avahi_client_free(context->client);
    }

    if (context->simple_poll){
        avahi_simple_poll_free(context->simple_poll);
    }

    free(context);
}


aes67_mdns_resource_t
aes67_mdns_browse_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                        aes67_mdns_browse_callback callback, void *user_data)
{
    assert(ctx);

    context_t * context = ctx;

    AvahiIfIndex interface = AVAHI_IF_UNSPEC;
    AvahiProtocol protocol = AVAHI_PROTO_UNSPEC;

    AvahiLookupFlags flags = 0;

    resource_t * res = resource_new(context, restype_browse, callback, user_data);

    AvahiServiceBrowser * sb = res->res = avahi_service_browser_new(context->client, interface, protocol, type, domain, flags, browse_callback, res);

    if (!sb){
        free(res);
        return NULL;
    }

    resource_link(context, res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_resolve_start(aes67_mdns_context_t ctx, const char *type, const char *name, const char *domain,
                         aes67_mdns_resolve_callback callback, void *user_data)
{
    assert(ctx);

    context_t * context = ctx;

    AvahiIfIndex interface = AVAHI_IF_UNSPEC;
    AvahiProtocol protocol = AVAHI_PROTO_UNSPEC;

    AvahiLookupFlags flags = 0;

    resource_t * res = resource_new(context, restype_resolve, callback, user_data);

    AvahiServiceResolver * sr = res->res = avahi_service_resolver_new(res->context->client, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, flags, resolve_callback, res);

    if (!sr) {
        fprintf(stderr, "Failed to resolve service '%s': %s\n", name,
                avahi_strerror(avahi_client_errno(res->context->client)));
        free(res);
        return NULL;
    }

    resource_link(context, res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_resolve2_start(aes67_mdns_context_t ctx, const char *type, const char *domain,
                          aes67_mdns_resolve_callback callback, void *user_data)
{
    assert(ctx);

    context_t * context = ctx;

    AvahiIfIndex interface = AVAHI_IF_UNSPEC;
    AvahiProtocol protocol = AVAHI_PROTO_UNSPEC;

    AvahiLookupFlags flags = 0;

    resource_t * res = resource_new(context, restype_resolve2, callback, user_data);

    AvahiServiceBrowser * sb = res->res = avahi_service_browser_new(context->client, interface, protocol, type, domain, flags, browse_callback, res);

    if (!sb){
        free(res);
        return NULL;
    }

    resource_link(context, res);

    return res;
}


static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata) {
    assert(userdata);

    resource_t * res = userdata;

    /* Called whenever the entry group state changes */
    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED :
            /* The entry group has been established successfully */
            fprintf(stderr, "Service 'asdf' successfully established.\n");
            res->type = restype_register_done;
            break;

        case AVAHI_ENTRY_GROUP_COLLISION : {
//            char *n;
//            /* A service name collision with a remote service
//             * happened. Let's pick a new name */
//            n = avahi_alternative_service_name(name);
//            avahi_free(name);
//            name = n;
//            fprintf(stderr, "Service name collision, renaming service to '%s'\n", name);
//            /* And recreate the services */
//            create_services(avahi_entry_group_get_client(g));
            break;
        }
        case AVAHI_ENTRY_GROUP_FAILURE :
            fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
            /* Some kind of failure happened while we were registering our services */
//            avahi_simple_poll_quit(res->context->simple_poll);
            break;
        case AVAHI_ENTRY_GROUP_UNCOMMITED:
        case AVAHI_ENTRY_GROUP_REGISTERING:
            ;
    }
}

aes67_mdns_resource_t
aes67_mdns_service_start(aes67_mdns_context_t ctx, const char *type, const char *name, const char *domain,
                         const char * host, u16_t port, u16_t txtlen, const u8_t * txt, aes67_mdns_service_callback callback, void *user_data)
{
    assert(ctx);

    context_t * context = ctx;

    if (avahi_client_get_state(context->client) != AVAHI_CLIENT_S_RUNNING){
        return NULL;
    }

    resource_t * res = resource_new(context, restype_register_pending, callback, user_data);

    AvahiEntryGroup * group = res->res = avahi_entry_group_new(context->client, entry_group_callback, res);

    if (!group) {
        fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(context->client)));
        free(res);
        return NULL;
    }

    AvahiIfIndex interface = AVAHI_IF_UNSPEC;
    AvahiProtocol protocol = AVAHI_PROTO_UNSPEC;

    AvahiPublishFlags flags = 0;

    int ret = avahi_entry_group_add_service(group, interface, protocol, flags, name, type, domain, host, port, txt, txtlen, NULL);
    if (ret < 0){
        if (ret == AVAHI_ERR_COLLISION){

        }
        free(res);
        return NULL;
    }


    resource_link(context, res);

    return res;
}

aes67_mdns_resource_t
aes67_mdns_service_addrecord(aes67_mdns_context_t ctx, aes67_mdns_resource_t service, u16_t rrtype, u16_t rdlen, const u8_t * rdata, u32_t ttl)
{
    return NULL;
}

aes67_mdns_resource_t
aes67_mdns_register_start(aes67_mdns_context_t ctx, const char *fullname, u16_t rrtype, u16_t rrclass, u16_t rdlen, const u8_t * rdata, u32_t ttl, aes67_mdns_register_callback callback, void *user_data)
{
    return NULL;
}


void aes67_mdns_stop(aes67_mdns_resource_t res)
{
    assert(res);

    resource_t * r = res;

    resource_delete(r->context, r);
}


void aes67_mdns_process(aes67_mdns_context_t ctx, int timeout_msec)
{
    assert(ctx != NULL);

    context_t * context = ctx;

    avahi_simple_poll_iterate(context->simple_poll, timeout_msec);
}

int aes67_mdns_geterrcode(aes67_mdns_resource_t res)
{
    assert(res);

    resource_t * r = res;

    return r->errno;
}