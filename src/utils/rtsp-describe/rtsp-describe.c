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

#include "aes67/utils/rtsp.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <netdb.h>

static char * argv0;

static struct {
    bool print_rtsp;
    bool verbose;
} opts;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-vr] [<rtsp-url>]\n"
             "Attempts to retrieve SDP header from given RTSP URL(s) (rtsp://<host>[:<port>][<resource>])\n"
             "and prints to STDOUT. If no <rtsp-url> is given assumes there will be one rtsp-url per line\n"
             "on STDIN.\n"
             "Options:\n"
             "\t -h,-?\t Prints this info\n"
             "\t -r\t Prints RTSP header info to STDERR\n"
             "\t -v\t Print some status info to STDERR\n"
             "Example:\n"
             "./rtsp-describe -r rtsp://192.168.2.138:9090/by-name/here-be-kittens-ravenna_1\n"
            , argv0);
}

static int lookup2(char * rtsp)
{
    // first extract hostname, port and uri which will be used laster...

    int l = strlen(rtsp);
    if (l < sizeof("rtsp://")){
        return EXIT_FAILURE;
    }

    if (memcmp(rtsp, "rtsp://", sizeof("rtsp://")-1) != 0){
        return EXIT_FAILURE;
    }

    char * uri = memchr(&rtsp[sizeof("rtsp://")-1], '/', strlen(rtsp) - sizeof("rtsp://")-1);

    // if not found, just point to '\0'
    if (uri == NULL){
        uri = &rtsp[l - 1];
    }

    char * host = &rtsp[sizeof("rtsp://")-1];
    size_t hostlen = uri - host;

    struct aes67_net_addr addr;

    // if not an <ip>:<port> is given we're dealing with <host>:<port>
    if (aes67_net_str2addr(&addr, (u8_t*)host, hostlen) == false){

        // note: is equal to uri[0] = '\0';
        // so we have to remember to change this back
        bool has_uri = uri[0] != '\0';
        host[hostlen] = '\0';

        char * p = strrchr(host, ':');

        if (p == NULL){
            addr.port = 0;
        } else {
            // terminate host str to not include port
            *p = '\0';

            // just read port
            addr.port = atoi(&p[1]);
        }


        struct hostent * he = gethostbyname(host);

        if (he == NULL){
            return EXIT_FAILURE;
        }
        if (he->h_addrtype == AF_INET){
            addr.ipver = aes67_net_ipver_4;
            *(u32_t*)addr.ip = ((struct in_addr *) he->h_addr_list[0])->s_addr;
        } else if (he->h_addrtype == AF_INET6){
            addr.ipver = aes67_net_ipver_6;
            memcpy(addr.ip, (struct in6_addr *) he->h_addr_list[0], 16);
        } else {
            return EXIT_FAILURE;
        }

//        printf("%d.%d.%d.%d:%d\n", addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3], addr.port);


        // restore uri
        if (has_uri){
            uri[0] = '/';
        }
        // restore port delimiter
        if (p != NULL){
            p[0] = ':';
        }
    }

    // if no port is given, use default port
    if (addr.port == 0){
        addr.port = AES67_RTSP_DEFAULT_PORT;
    }

    // now we get to the actual request
    struct aes67_rtsp_dsc_res_st res;

    aes67_rtsp_dsc_init(&res, true);

    if (aes67_rtsp_dsc_start(&res, addr.ipver, addr.ip, addr.port, uri)){
        return EXIT_FAILURE;
    }

    while(res.state != aes67_rtsp_dsc_state_done){
        aes67_rtsp_dsc_process(&res);
    }

    if (opts.verbose){
        char str[256];
        ssize_t l = snprintf(str, sizeof(str), "RTSP-DESCRIBE %s %s\n", res.statuscode == AES67_RTSP_STATUS_OK ? "OK" : "FAIL", rtsp);
        if (write(STDERR_FILENO,str, l) == -1){
            //
        }
    }

    if (opts.print_rtsp && res.hdrlen > 0){
        if (write(STDERR_FILENO, res.buf, res.hdrlen) == -1){
            //
        }
    }

    if (res.contentlen > 0){
        if (write(STDOUT_FILENO, aes67_rtsp_dsc_content(&res), res.contentlen) == -1){
            //
        }
    }

    aes67_rtsp_dsc_deinit(&res);

    return (res.statuscode == AES67_RTSP_STATUS_OK ? EXIT_SUCCESS : EXIT_FAILURE);
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.print_rtsp = 0;

    int opt;


    while ((opt = getopt(argc, argv, "h?rv")) != -1) {
        switch (opt) {
            case 'r':
                opts.print_rtsp = true;
                break;

            case 'v':
                opts.verbose = true;
                break;

            case 'h':
            case '?':
                help(stdout);
                return EXIT_SUCCESS;

            default: /* '?' */
                exit(EXIT_FAILURE);
        }
    }

    if ( optind + 1 == argc ){
        return lookup2(argv[optind]);
    }


    ssize_t len = 0;
    char line[256];
    ssize_t c;
    while ( (c = read(STDIN_FILENO, &line[len], 1)) != -1) {

        if (c == 0){
            continue;
        }
        if (line[len] == '\r' || line[len] == '\n'){
            line[len] = '\0';

            if (len > 0){
                lookup2(line);
//                usleep(1000);
                len = 0;
            }

        } else {
            len++;
        }

        // buffer limit safety check
        if (len >= sizeof(line)){
            len = 0;
        }
    }

    // in case EOF but something in buffer just try that aswell
    if (len > 0){
        line[len] = '\0';
        lookup2(line);
    }

    return EXIT_SUCCESS;
}