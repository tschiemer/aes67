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

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

static char * argv0;

static struct {
    bool verbose;
} opts;

static bool keep_running;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h?] | [-v] [-s|--sessions] [-d|--devices] [--receivers] [--senders] [--raw]\n"
             "Outputs any found session, receivers or senders as found per mDNS requests to STDOUT.\n"
             "One result per line: <fullname> <host> <port> <txtlen> TODO TXT\n"
             "If neither type is explicitly requested, looks for sessions only.\n"
             "Options:\n"
             "\t -h,-?\t\t Outputs this info\n"
             "\t -v\t\t Some verbose output to STDOUT\n"
             "\t -s,--sessions\t Browse for sessions\n"
             "\t --receivers\t Browse for receiving devices\n"
             "\t --senders\t Browse for sending devices\n"
             "\t -d,--devices\t Browse for senders and receivers (shortcut for --receivers --senders)\n"
            , argv0);
}



void session_resolve_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * fullname, const u8_t * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
    printf("%d %s %s:%hu\n", result, fullname, hosttarget, port);
//    if (result == aes67_mdns_result_ok){
//        if (opts.verbose){
//            fprintf(stderr, "DISCOVERED %s %s %hu\n", fullname, hosttarget, port);
//            fflush(stderr);
//        }
//        if (opts.raw){
//            printf("%s %s %hu ", fullname, hosttarget, port);
//            for (int i = 0; i < txtlen-1; i++){
//                if (isprint(txt[i])){
//                    printf("%c", txt[i]);
//                } else {
//                    printf(" ");
//                }
//            }
//            printf("\n");
//        } else {
//
//            char host[256];
//            size_t hostlen = strlen((char*)hosttarget) - 1;
//
//            assert( hostlen < sizeof(host) - 1);
//
//            memcpy(host, hosttarget, hostlen);
//            host[hostlen] = '\0';
//
//
//            char name[256];
//            size_t namelen = strlen((char*)fullname) - sizeof(AES67_RAV_MDNS_TYPE_SENDER ".local.");
//
//            assert(namelen < sizeof(name));
//
//            memcpy(name, fullname, namelen);
//
//            // space in name are given as \032, let's turn this into URL friendly %20
//            for (int i = 0; i < namelen - 4; i++){
//                if (name[i] == '\\' && name[i+1] == '0' && name[i+2] == '3' && name[i+3] == '2'){
//                    name[i] = '%';
//                    name[i+1] = '2';
//                    name[i+2] = '0';
//                    memmove(&name[i+3], &name[i+4], namelen - i - 4);
//                    namelen --;
//                }
//            }
//
//            name[namelen] = '\0';
//
//            printf("rtsp://%s:%hu/by-name/%s\n", host, port, name);
//        }
//    }
//    fflush(stdout);
}

int main(int argc, char * argv[])
{
    skeleton_daemon();

    while (1)
    {
        //TODO: Insert daemon code here.
        syslog (LOG_NOTICE, "rav2sap started.");
        sleep (20);
        break;
    }

    syslog (LOG_NOTICE, "rav2sap terminated.");
    closelog();

    return EXIT_SUCCESS;

    argv0 = argv[0];

    opts.verbose = false;


    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hv",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 'v':
                opts.verbose = true;
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

    if ( optind < argc ){ // 1 < argc &&
        fprintf(stderr, "wrong argument count\n");
        return EXIT_FAILURE;
    }

//    daemon(1,1);

    return EXIT_SUCCESS;

    aes67_mdns_init();
    atexit(aes67_mdns_deinit);


    if (aes67_mdns_lookup_start((u8_t *) AES67_RAV_MDNS_TYPE_SENDER, (u8_t *) AES67_RAV_MDNS_SUBTYPE_SESSION, NULL, session_resolve_callback, NULL) == NULL){
        return EXIT_FAILURE;
    }

    keep_running = true;
    while( keep_running ){
        aes67_mdns_process(1000);
    }

    return EXIT_SUCCESS;
}