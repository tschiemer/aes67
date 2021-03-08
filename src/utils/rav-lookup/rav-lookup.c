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

static char * argv0;

static volatile bool keep_running;

static struct {
    bool sessions;
    bool receivers;
    bool senders;
//    bool raw;
    bool verbose;
    enum aes67_mdns_result result_filter;
} opts = {
    .sessions = false,
    .receivers = false,
    .senders = false,
    .result_filter = aes67_mdns_result_discovered,
    .verbose = false
};

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h?] | [-v] [-s|--sessions] [-d|--devices] [--receivers] [--senders] [--filter (disco|term)]\n"
             "Outputs any found session, receivers or senders as found per mDNS requests to STDOUT.\n"
             "One result per line: <fullname> <host> <port> [<txt>]\n"
             "If neither type is explicitly requested, looks for sessions only.\n"
             "Options:\n"
             "\t -h,-?\t\t Outputs this info\n"
             "\t -v\t\t Some status output to STDERR\n"
             "\t -s,--sessions\t Browse for sessions\n"
             "\t --receivers\t Browse for receiving devices\n"
             "\t --senders\t Browse for sending devices\n"
             "\t -d,--devices\t Browse for senders and receivers (shortcut for --receivers --senders)\n"
             "\t -f,--filter (disco|term) \t Show discovered or terminated services only (default disco)\n"
//             "\t -r, --raw\t Output raw mDNS results\n"
            , argv0);
}


static void sig_int(int sig)
{
    keep_running = false;
}

void session_lookup_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * type, const u8_t * name, const u8_t * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
//    printf("%d %s.%s @ %s:%hu\n", result, name, type, hosttarget, port);

    if (result == aes67_mdns_result_error){
        fprintf(stderr, "ERROR %d\n", aes67_mdns_geterrcode(res));
    } else {
        if (opts.verbose){

            fprintf(stderr, "%s %s._session_ravenna._rtsp._tcp @ %s:%hu [%d](", result == aes67_mdns_result_discovered ? "DISCOVERED" : "TERMINATED", name, hosttarget, port, txtlen);

            for (int i = 0; i < txtlen-1; i++){
                if (isprint(txt[i])){
                    fprintf(stderr, "%c", txt[i]);
                } else {
                    fprintf(stderr, " ");
                }
            }
            fprintf(stderr, ")\n");
            fflush(stderr);

        }
        if (result == opts.result_filter){

            char host[256];
            size_t hostlen = strlen((char*)hosttarget) - 1;

            assert( hostlen < sizeof(host) - 1);

            memcpy(host, hosttarget, hostlen);
            host[hostlen] = '\0';


            char name_enc[256];
            size_t namelen = strlen((char*)name);

            assert(namelen < sizeof(name_enc));

            memcpy(name_enc, name, namelen);

            // TODO do actual url encode....

            for (int i = 0; i < namelen; i++){
                if (name_enc[i] == ' '){
//                    printf("SP @ %d\n",i);
                    memmove(&name_enc[i+3], &name_enc[i+1], namelen - i);
                    name_enc[i] = '%';
                    name_enc[i+1] = '2';
                    name_enc[i+2] = '0';
                    namelen += 2;
                }
            }

            name_enc[namelen] = '\0';

            printf("rtsp://%s:%hu/by-name/%s\n", host, port, name_enc);
            fflush(stdout);
        }
    }
}
void receiver_lookup_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * type, const u8_t * name, const u8_t * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
    if (result == aes67_mdns_result_error){
        fprintf(stderr, "ERROR %d\n", aes67_mdns_geterrcode(res));
    } else {

        if (opts.verbose){
            fprintf(stderr, "DISCOVERED %s._ravenna._http._tcp @ %s:%hu [%d](", name, hosttarget, port, txtlen);

            for (int i = 0; i < txtlen-1; i++){
                if (isprint(txt[i])){
                    fprintf(stderr, "%c", txt[i]);
                } else {
                    fprintf(stderr, " ");
                }
            }
            fprintf(stderr, ")\n");
            fflush(stderr);

        }
        if (result == opts.result_filter){
            char host[256];
            size_t hostlen = strlen((char*)hosttarget) - 1;

            assert( hostlen < sizeof(host) - 1);

            memcpy(host, hosttarget, hostlen);
            host[hostlen] = '\0';


            printf("http://%s:%hu\n", host, port);
        }
    }
    fflush(stdout);
}
void sender_lookup_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const u8_t * type, const u8_t * name, const u8_t * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, void * context)
{
    if (result == aes67_mdns_result_error){
        fprintf(stderr, "ERROR %d\n", aes67_mdns_geterrcode(res));
    } else {

        if (opts.verbose){
            fprintf(stderr, "DISCOVERED %s._ravenna._rtsp._tcp @ %s:%hu [%d](", name, hosttarget, port, txtlen);

            for (int i = 0; i < txtlen-1; i++){
                if (isprint(txt[i])){
                    fprintf(stderr, "%c", txt[i]);
                } else {
                    fprintf(stderr, " ");
                }
            }
            fprintf(stderr, ")\n");
            fflush(stderr);

        }
        if (result == opts.result_filter){

            char host[256];
            size_t hostlen = strlen((char*)hosttarget) - 1;

            assert( hostlen < sizeof(host) - 1);

            memcpy(host, hosttarget, hostlen);
            host[hostlen] = '\0';


            printf("rtsp://%s:%hu\n", host, port);
        }
    }
    fflush(stdout);


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
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hsdvf:",
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

//            case 'r':
//                opts.raw = true;
//                break;

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

    if (!opts.sessions && !opts.receivers && !opts.senders){
        opts.sessions = true;
    }

    aes67_mdns_context_t * ctx = aes67_mdns_new();

    if (ctx == NULL){
        fprintf(stderr, "could not create mdns context\n");
        return EXIT_FAILURE;
    }
    if (opts.sessions){
        if (aes67_mdns_lookup_start(ctx, (u8_t *) AES67_RAV_MDNS_TYPE_SENDER, (u8_t *) AES67_RAV_MDNS_SUBTYPE_SESSION,
                                    NULL, session_lookup_callback, NULL) == NULL){
            return EXIT_FAILURE;
        }
    }
    if (opts.receivers){
        if (aes67_mdns_lookup_start(ctx, (u8_t *) AES67_RAV_MDNS_TYPE_RECEIVER, (u8_t *) AES67_RAV_MDNS_SUBTYPE_DEVICE,
                                    NULL, session_lookup_callback, NULL) == NULL){
            return EXIT_FAILURE;
        }
    }
    if (opts.senders){
        if (aes67_mdns_lookup_start(ctx, (u8_t *) AES67_RAV_MDNS_TYPE_SENDER, (u8_t *) AES67_RAV_MDNS_SUBTYPE_DEVICE,
                                    NULL, session_lookup_callback, NULL) == NULL){
            return EXIT_FAILURE;
        }
    }


    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){
        aes67_mdns_process(ctx, NULL);
    }

    aes67_mdns_delete(ctx);

    return EXIT_SUCCESS;
}