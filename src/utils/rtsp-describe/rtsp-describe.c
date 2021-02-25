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

static char * argv0;

static struct {
    u8_t print_rtsp;
} opts;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-r] [<rtsp-url>]\n"
             "Attempts to retrieve SDP header from given RTSP URL(s) (rtsp://<host>[:<port>][<resource>])\n"
             "and prints to STDOUT. If no <rtsp-url> is given assumes there will be one rtsp-url per line\n"
             "on STDIN.\n"
             "Options:\n"
             "\t -h,-?\t Prints this info\n"
             "\t -r\t Prints RTSP header info to STDERR\n"
             "Example:\n"
             "./rtsp-describe -r rtsp://192.168.2.138:9090/by-name/here-be-kittens-ravenna_1\n"
            , argv0);
}

void aes67_rtsp_header(u8_t * buf, ssize_t len)
{
    if (!opts.print_rtsp){
        return;
    }

    u8_t failed = len < 0;

    if (failed){
        len *= -1;
    }

    write(STDERR_FILENO, buf, len);
}

static int lookup(u8_t * rtsp){
    u8_t sdp[3000];
    ssize_t sdplen = aes67_rtsp_describe_url(rtsp, sdp, sizeof(sdp));

    if (sdplen <= 0){
        return EXIT_FAILURE;
    }

    sdp[sdplen] = '\0';
    write(STDOUT_FILENO, sdp, sdplen);

    return EXIT_SUCCESS;
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.print_rtsp = 0;

    int opt;


    while ((opt = getopt(argc, argv, "h?r")) != -1) {
        switch (opt) {
            case 'r':
                opts.print_rtsp = 1;
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
        return lookup((u8_t*)argv[optind]);
    }


    ssize_t len = 0;
    u8_t line[256];
    while (read(STDIN_FILENO, &line[len], 1) == 1) {

        if (line[len] == '\r' || line[len] == '\n'){
            line[len] = '\0';

            if (len > 0){
                lookup(line);
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