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

//static void rtsp_hdr_handler(u8_t * buf, ssize_t len)
//{
//    if (!opts.print_rtsp){
//        return;
//    }
//
//    u8_t failed = len < 0;
//
//    if (failed){
//        len *= -1;
//    }
//
//    write(STDERR_FILENO, buf, len);
//}

static int lookup(char * rtsp)
{
    u8_t sdp[3000];
    ssize_t sdplen = aes67_rtsp_dsc_easy_url(rtsp, sdp, sizeof(sdp));

    if (opts.verbose){
        fprintf(stderr, "RTSP-DESCRIBE %s %s\n", sdp > 0 ? "OK" : "FAIL", rtsp);
        fflush(stderr);
    }

    if (sdplen <= 0){
        return EXIT_FAILURE;
    }

//    sdp[sdplen] = '\0';
    write(STDOUT_FILENO, sdp, sdplen);

    fflush(stdout);

    return EXIT_SUCCESS;
}


//static int lookup2(u8_t * rtsp)
//{
//    struct aes67_net_addr addr;
//
//    if (memcmp(rtsp, "rtsp://", sizeof("rtsp://")-1) != 0){
//        return EXIT_FAILURE;
//    }
//
//
//
//
//    struct aes67_rtsp_dsc_res_st res;
//
//    aes67_rtsp_dsc_init(&res, true);
//
//    if (aes67_rtsp_dsc_start(&res, addr.ipver, addr.addr, addr.port, "/by-name/here-be-kittens.ravenna_27")){
//        return EXIT_FAILURE;
//    }
//
//    while(res.state != aes67_rtsp_dsc_state_done){
//        aes67_rtsp_dsc_process(&res);
//    }
//
//    if (opts.verbose){
//        fprintf(stderr, "RTSP-DESCRIBE %s %s\n", res.contentlen > 0 ? "OK" : "FAIL", rtsp);
//        fflush(stderr);
//    }
//
//    if (res.contentlen > 0){
//        write(STDOUT_FILENO, aes67_rtsp_dsc_content(&res), res.contentlen);
//    }
//
//    aes67_rtsp_dsc_deinit(&res);
//
//    return (res.contentlen > 0 ? EXIT_SUCCESS : EXIT_FAILURE);
//}


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
        return lookup(argv[optind]);
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
                lookup(line);
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
        lookup(line);
    }

    return EXIT_SUCCESS;
}