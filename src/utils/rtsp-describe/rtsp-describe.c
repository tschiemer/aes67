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

static char * argv0;

static struct {
    u8_t print_rtsp;
} opts;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-d] [<rtsp-URL>]\n"
             "Attempts to retrieve SDP header from given RTSP URL (rtsp://<host>[:<port>][<resource>]) and prints to STDOUT\n"
             "Options:\n"
             "\t -h,-?\t Prints this info\n"
             "\t -d\t Prints RTSP header info to STDERR\n"
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
    u8_t sdp[1500];
    ssize_t sdplen = aes67_rtsp_describe_url(rtsp, sdp, sizeof(sdp));

    if (sdplen <= 0){
        return EXIT_FAILURE;
    }

    write(STDOUT_FILENO, sdp, sdplen);

    return EXIT_SUCCESS;
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.print_rtsp = 0;

    int opt;


    while ((opt = getopt(argc, argv, "h?dtb:r:c:")) != -1) {
        switch (opt) {
            case 'd':
                opts.print_rtsp = 1;
                break;

            case 'h':
            case '?':
            default: /* '?' */
                help(stdout);
                exit(EXIT_FAILURE);
        }
    }

    if ( optind + 1 == argc ){
        return lookup((u8_t*)argv[optind]);
    }

//    ssize_t len;
//    char line[256];
//    getline()
    //TODO

    return EXIT_SUCCESS;
}