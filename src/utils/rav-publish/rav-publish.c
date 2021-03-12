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
#include "dnmfarrell/URI-Encode-C/src/uri_encode.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>

static char * argv0;

static volatile bool keep_running;

static struct {
    bool sessions;
    bool receivers;
    bool senders;
//    bool raw;
    bool verbose;
    enum aes67_mdns_result result_filter;
    bool no_encode;
} opts = {
    .sessions = false,
    .receivers = false,
    .senders = false,
    .result_filter = aes67_mdns_result_discovered,
    .no_encode = false,
    .verbose = false
};

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h?] | [-v] [-p <rtsp-port>] [[--host <host>] [--ip <ip>] | [--no-rtsp]] <sdp-file1> ...\n"
             "Sets up Ravenna style discovery mechanism for provided SDP files.\n"
             "By default sets up a mini-RTSP server serving the given session descriptions.\n"
             "Options:\n"
             "\t -h,-?\t\t Outputs this info\n"
             "\t -v\t\t Some status output to STDERR\n"
             "\t -p <rtsp-port>\t  Port of RTSP server.\n"
             "\t --host <host>\t Host of target device (by default will assume self).\n"
             "\t --ip <ip>\t IPv4/6 address of target device (create an record for host).\n"
             "\t --no-rtsp\t Do not start a RTSP server.\n"
            , argv0);
}


static void sig_int(int sig)
{
    keep_running = false;
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];


    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"sessions",  no_argument,       0,  's' },
                {"receivers",  no_argument,       0,  2 },
                {"senders",  no_argument,       0,  3 },
                {"devices",  no_argument,       0,  'd' },
                {"filter",  required_argument,       0,  'f' },
                {"no-enc",  no_argument,       0,  'n' },
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hsdvf:n",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 's':
                opts.sessions = true;
                break;

            case 'd':
                opts.receivers = true;
                opts.senders = true;
                break;

            case 'v':
                opts.verbose = true;
                break;

            case 2:
                opts.receivers = true;
                break;

            case 3:
                opts.senders = true;
                break;

            case 'f':
                if (strcmp(optarg, "disco") == 0){
                    opts.result_filter = aes67_mdns_result_discovered;
                } else if (strcmp(optarg, "term") == 0){
                    opts.result_filter = aes67_mdns_result_terminated;
                } else {
                    fprintf(stderr, "Invalid filter option\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'n':
                opts.no_encode = true;
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

//    if ( optind < argc ){ // 1 < argc &&
//        fprintf(stderr, "wrong argument count\n");
//        return EXIT_FAILURE;
//    }
//
//    if (!opts.sessions && !opts.receivers && !opts.senders){
//        opts.sessions = true;
//    }

    aes67_mdns_context_t * ctx = aes67_mdns_new();

    aes67_mdns_resource_t * res = aes67_mdns_publish_start(ctx, "_ravenna_session._sub._rtsp._tcp", "Hello my pretty", NULL, NULL, 9191, 0, NULL);

    if (res == NULL){
        aes67_mdns_delete(ctx);
        return EXIT_FAILURE;
    }

    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){
        aes67_mdns_process(ctx, NULL);
    }

    aes67_mdns_delete(ctx);

    return EXIT_SUCCESS;
}