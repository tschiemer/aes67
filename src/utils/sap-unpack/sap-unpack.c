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

#include "aes67/sap.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/errno.h>


static char * argv0;

struct {
  bool print_headers;
} opts;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h?a]\n"
             "Attempts to parse SAP packets incoming on STDIN and prints to STDOUT in the following format:\n"
             "\t (announce|delete) <hash> <ip> <payload-type>\n"
             "\t <payload-data>\n"
             "\t <newline>\n"
             "Options:\n"
             "\t -a\t Print SAP headers\n"
             "\t -h,-?\t Prints this help.\n"
             , argv0);
}


void
aes67_sap_service_event(enum aes67_sap_event event, u16_t hash, enum aes67_net_ipver ipver, u8_t *ip, u8_t *payloadtype,
                        u16_t payloadtypelen, u8_t *payload, u16_t payloadlen, void *user_data)
{
    if (opts.print_headers){
        printf("%s ", event == aes67_sap_event_new ? "announce" : "delete");
        printf("%d ", hash);

        u8_t ipstr[64];
        uint16_t l = aes67_net_addr2a(ipstr, ipver, ip, 0);
        ipstr[l] = '\0';

        printf("%s", ipstr);

        printf(" %s", (payloadtype == NULL ? AES67_SDP_MIMETYPE : (char*)payloadtype) );

        printf("\n");
    }

    printf("%s\n", payload);

    fflush(stdout);
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.print_headers = false;

    int opt;

    while ((opt = getopt(argc, argv, "h?a")) != -1) {
        switch (opt) {
            case 'a':
                opts.print_headers = true;
                break;

            case 'h':
            case '?':
            default: /* '?' */
                help(stdout);
                exit(EXIT_FAILURE);
        }
    }

    if ( optind < argc ){ // 1 < argc &&
        fprintf(stderr, "ERROR too many arguments\n");
        return EXIT_FAILURE;
    }

    // set non-blocking stdin
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "Couldn't nonblock stdin\n");
        return 1;
    }

    u8_t rbuf[1024];

    while(feof(stdin) == 0){

        ssize_t r = read(STDIN_FILENO, rbuf, sizeof(rbuf));

        if (r == -1){
            // EAGAIN -> currently no data available
            if (errno != EAGAIN){
                printf("err %d\n", errno);
                break;
            }
        } else if (r > 0){ // data read

            aes67_sap_service_handle(NULL, rbuf, r, NULL);

        } else { // r == 0 if stdin closed
            break;
        }
    }


    return 0;
}