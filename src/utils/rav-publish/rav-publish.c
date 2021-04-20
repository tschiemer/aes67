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
#include "aes67/rav.h"
#include "aes67/utils/rtsp-srv.h"
#include "dnmfarrell/URI-Encode-C/src/uri_encode.h"
#include "aes67/net.h"
#include "aes67/sdp.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <dns_util.h>

typedef struct sdpres_st {
    char * name;
    struct aes67_net_addr addr;
    char * data;
    u32_t len;
    struct sdpres_st * next;
} sdpres_t;

static char * argv0;

static struct {
//    bool raw;
    bool verbose;
    bool rtsp;
    char * host;
    struct aes67_net_addr addr;
    u16_t port;
    u32_t ttl;
} opts = {
    .verbose = false,
    .rtsp = true,
    .host = NULL,
    .addr.ipver = aes67_net_ipver_undefined,
    .port = 0,
    .ttl = 100
};

static volatile bool keep_running;

static struct aes67_rtsp_srv rtsp_srv;

static aes67_mdns_context_t mdns;

static sdpres_t * first_sdpres = NULL;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h?] | [-v] [-p <rtsp-port>] [[--host <host>] [--ip <ip>] | [--no-rtsp]] <sdp-file1> ...\n"
             "Sets up Ravenna style discovery mechanism for provided SDP files.\n"
             "By default sets up a mini-RTSP server serving the given session descriptions.\n"
             "Options:\n"
             "\t -h,-?\t\t Outputs this info\n"
             "\t -v\t\t Some status output to STDERR\n"
             "\t -p, --port <rtsp-port>\t  Port of RTSP server.\n"
             "\t --host <host>\t Host of target device (by default will assume self; if given will try to use originator IPv4/6 from SDP file).\n"
             "\t --ip <ip>\t (Override) IPv4/6 address of target device (create an record for host).\n"
             "\t --no-rtsp\t Do not start a RTSP server.\n"
            , argv0);
}


static void sig_stop(int sig)
{
    keep_running = false;
}

static void publish_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char *type, const char *name, const char *domain, void * context)
{
    assert(result == aes67_mdns_result_error || result == aes67_mdns_result_registered);

    if (result == aes67_mdns_result_error){
        keep_running = false;
        fprintf(stderr, "Failed to register service %s._ravenna_session._sub._rtsp._tcp.%s\n", name, domain);
    } else {
        fprintf(stderr, "Registered service %s._ravenna_session._sub._rtsp._tcp.%s\n", name, domain);
    }
}

//static void fd_blocking(int fd, bool yes){
//
//    // set non-blocking
//    int flags = fcntl(fd, F_GETFL, 0);
//    flags = (flags & ~O_NONBLOCK) | (yes ? 0 : O_NONBLOCK);
//    if (fcntl(fd, F_SETFL, flags) == -1){
//        perror("fcntl()");
//        close(fd);
//        exit(EXIT_FAILURE);
//    }
//}

static void block_until_event(){

    int nfds;
    fd_set rfds, xfds;
//    sigset_t sigmask;

    FD_ZERO(&rfds);
    FD_ZERO(&xfds);

    if (opts.rtsp){
        nfds = rtsp_srv.listen_sockfd;
        FD_SET(rtsp_srv.listen_sockfd, &rfds);
        FD_SET(rtsp_srv.listen_sockfd, &xfds);
        if (rtsp_srv.client_sockfd != -1){
            FD_SET(rtsp_srv.client_sockfd, &rfds);
            FD_SET(rtsp_srv.client_sockfd, &xfds);
            if (rtsp_srv.client_sockfd > rtsp_srv.listen_sockfd){
                nfds = rtsp_srv.client_sockfd;
            }
        }
    }

    int * sockfds;
    size_t count = 0;
    aes67_mdns_getsockfds(mdns, &sockfds, &count);
    for (size_t i = 0; i < count; i++) {
        FD_SET(sockfds[i], &rfds);
        FD_SET(sockfds[i], &xfds);
        if (sockfds[i] > nfds) {
            nfds = sockfds[i];
        }
    }

    nfds++;

    // just wait until something interesting happens
    select(nfds, &rfds, NULL, &xfds, NULL);
}

static int mdns_setup()
{

    mdns = aes67_mdns_new();

    sdpres_t * sdpres = first_sdpres;
    while(sdpres != NULL){

        aes67_mdns_resource_t service = aes67_mdns_service_start(mdns, AES67_RAV_MDNS_SESSION, sdpres->name,
                                                                 NULL, opts.host, opts.port, 0, NULL, publish_callback, NULL);

        if (service == NULL){
            fprintf(stderr, "failed to create service\n");
            return EXIT_FAILURE;
        }

        if (opts.host != NULL){

            struct aes67_net_addr * addr = opts.addr.ipver == aes67_net_ipver_undefined ? &sdpres->addr : &opts.addr;

            u16_t rrtype;
            u16_t rdlen;
            u8_t * rdata;

            if (addr->ipver == aes67_net_ipver_4){
                rrtype = 1;
                rdlen = 4;
            } else { // ipver6
                rrtype = 28;
                rdlen = 16;
            }
            rdata = addr->ip;

            if (aes67_mdns_service_addrecord(mdns, service, rrtype, rdlen, rdata, opts.ttl) == NULL){
                fprintf(stderr, "failed to add A/AAAA record\n");
                return EXIT_FAILURE;
            }

            if (aes67_mdns_service_commit(mdns, service) == NULL){
                fprintf(stderr, "error committing service\n");
                return EXIT_FAILURE;
            }

        }

        sdpres = sdpres->next;
    }

    return EXIT_SUCCESS;
}

static void mdns_teardown()
{
    if (mdns) {
        aes67_mdns_delete(mdns);
    }
}

static void mdns_process()
{
    aes67_mdns_process(mdns, 0);
}

static int rtsp_setup()
{
    aes67_rtsp_srv_init(&rtsp_srv, false, NULL);

    aes67_rtsp_srv_blocking(&rtsp_srv, false);

    sdpres_t * sdpres = first_sdpres;
    while(sdpres != NULL){

        char uri[256];
        u16_t urilen = sizeof("/by-name");

        memcpy(uri, "/by-name/", sizeof("/by-name"));

        urilen += uri_encode(sdpres->name, strlen(sdpres->name), &uri[urilen], sizeof(uri) - urilen - 1);

        uri[urilen] = '\0';

        printf("final uri [%d]: [%s]\n", urilen, uri);

        aes67_rtsp_srv_sdp_add(&rtsp_srv, uri, urilen, sdpres);

        sdpres = sdpres->next;
    }

    if (aes67_rtsp_srv_start(&rtsp_srv, opts.addr.ipver, opts.addr.ip, opts.port)){
        fprintf(stderr, "failed to start rtsp server\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void rtsp_teardown()
{
    if (!opts.rtsp) {
        return;
    }

    aes67_rtsp_srv_deinit(&rtsp_srv);
}

static void rtsp_process()
{
    aes67_rtsp_srv_process(&rtsp_srv);
}

void aes67_rtsp_srv_sdp_getter(struct aes67_rtsp_srv * srv, void * sdpref, u8_t * buf, u16_t * len, u16_t maxlen)
{
    assert(srv);
    assert(sdpref);
    assert(buf);
    assert(len);
    assert(maxlen);

    sdpres_t * sdpres = sdpref;

    fprintf(stderr, "serving rtsp describe for uri %s\n", sdpres->name);

    if (maxlen < sdpres->len){
        fprintf(stderr, "sdp file too big for compiled in buffer size");
        *len = 0;
        return;
    }

    memcpy(buf, sdpres->data, sdpres->len);
    *len += sdpres->len;
}

static int load_sdpres(char * fname, size_t maxlen)
{
    if (access(fname, F_OK) != 0){
        fprintf(stderr, "ERROR file exists? %s\n", fname);
        return EXIT_FAILURE;
    }

    struct stat st;

    if (stat(fname, &st)){
        fprintf(stderr, "ERROR failed to get filesize %s\n", fname);
        return EXIT_FAILURE;
    }

    if (st.st_size > maxlen){
        fprintf(stderr, "ERROR file too big (%lld bytes, max %zu) %s\n", st.st_size, maxlen, fname);
        return EXIT_FAILURE;
    }

    int fd = open(fname, O_RDONLY);
    if (fd == -1){
        fprintf(stderr, "ERROR failed to open file %s\n", fname);
        return EXIT_FAILURE;
    }

    sdpres_t * res = calloc(1, sizeof(sdpres_t));


    res->data = malloc(st.st_size);

    ssize_t len = read(fd, res->data, st.st_size);

    close(fd);

    if (len != st.st_size){
        fprintf(stderr, "ERROR failed to read file?? %s\n", fname);
        free(res->data);
        free(res);
        return EXIT_FAILURE;
    }

    res->len = len;

    struct aes67_sdp sdp;

    int r = aes67_sdp_fromstr(&sdp, (u8_t*)res->data, res->len, NULL);
    if (r != AES67_SDP_OK){
        fprintf(stderr, "ERROR failed to parse SDP %s\n", fname);
        free(res->data);
        free(res);
        return EXIT_FAILURE;
    }

    if (sdp.name.length == 0){
        fprintf(stderr, "ERROR SDP %s does not contain a session name! (required)\n", fname);
        free(res->data);
        free(res);
        return EXIT_FAILURE;
    }

    if (aes67_net_str2addr(&res->addr, sdp.originator.address.data, sdp.originator.address.length) == false){
        fprintf(stderr, "ERROR SDP %s: origin must be an ip!\n", fname);
        free(res->data);
        free(res);
        return EXIT_FAILURE;
    }

    res->name = malloc(sdp.name.length + 1);
    memcpy(res->name, sdp.name.data, sdp.name.length);
    res->name[sdp.name.length] = '\0';

    res->next = first_sdpres;
    first_sdpres = res;

    return EXIT_SUCCESS;
}

static void cleanup_sdpres()
{
    while (first_sdpres != NULL){
        sdpres_t * res = first_sdpres;
        first_sdpres = first_sdpres->next;

        free(res->name);
        free(res->data);
        free(res);


    }
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];


    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"port",  required_argument,       0,  'p' },
                {"host",  required_argument,       0,  1 },
                {"ip",  required_argument,       0,  2 },
                {"no-rtsp",  no_argument,       0,  3 },
                {"ttl", required_argument, 0, 4},
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hvp:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 'v':
                opts.verbose = true;
                break;

            case 1: // --host
                opts.host = optarg;
                break;

            case 2: // --ip
                if (!aes67_net_str2addr(&opts.addr, (u8_t*)optarg, strlen(optarg))){
                    fprintf(stderr, "invalid ip: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

            case 3: // --no-rtsp
                opts.rtsp = false;
                break;

            case 'p':{
                int p = atoi(optarg);
                if (p <= 0 || p > 0xFFFF){
                    fprintf(stderr, "Invalid port\n");
                    return EXIT_FAILURE;
                }
                opts.port = p;
                break;
            }

            case 4:
                opts.ttl = atol(optarg);
                if (opts.ttl == 0){
                    fprintf(stderr, "Invalid TTL\n");
                    return EXIT_FAILURE;
                }
                break;

            case '?':
            case 'h':
                help(stdout);
                return EXIT_SUCCESS;

            default:
                fprintf(stderr, "Unrecognized option %c\n", c);
                return EXIT_FAILURE;
        }
    }

    if ( optind >= argc ){ // 1 < argc &&
        fprintf(stderr, "Missing arguments. %s -h for help\n", argv0);
//        help(stdout);
        return EXIT_FAILURE;
    }

    if (opts.port == 0){
        fprintf(stderr, "No port set\n");
        return EXIT_FAILURE;
    }

    for (int i = optind; i < argc; i++) {
        if (load_sdpres(argv[i], 1024)) {
            fprintf(stderr, "sdp load error\n");
            cleanup_sdpres();
            return EXIT_FAILURE;
        }
    }

    if (opts.rtsp){
        if (rtsp_setup()){
            fprintf(stderr, "failed rtsp setup\n");
            goto shutdown;
        }
    }


    if (mdns_setup()){
        fprintf(stderr, "failed mdns setup\n");
        goto shutdown;
    }



    signal(SIGINT, sig_stop);
    signal(SIGTERM, sig_stop);
    keep_running = true;
    while(keep_running){

        block_until_event();

        mdns_process();
        rtsp_process();
    }

shutdown:

    mdns_teardown();

    rtsp_teardown();

    cleanup_sdpres();

    return EXIT_SUCCESS;
}