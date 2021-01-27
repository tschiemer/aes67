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

//#include <getopt.h>
#include <stdio.h>

static struct {
    uint8_t status;
    uint16_t hash;
    struct aes67_net_addr origin;
    struct aes67_sdp sdp;
} opts;

static char * argv0;
static struct aes67_sap_service sap;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s (announce|delete) <msg-hash> <origin-ip> <sdp-file>\n"
             "Writes SAPv2 packet to STDOUT.\n"
             , argv0);
}

static void load_from_args(char * argv[])
{
    opts.status = 0;

    if (strcmp(argv[1], "announce") == 0){
        opts.status |= AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
    } else if (strcmp(argv[1], "announce") == 0){
        opts.status |= AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
    } else {
        fprintf(stderr, "ERROR invalid option %s\n", argv[1]);
        exit(1);
    }

    opts.hash = atoi(argv[2]);

    if (opts.hash == 0){
        fprintf(stderr, "ERROR invalid hash %s (must be uint16_t as decimal)\n", argv[2]);
        exit(1);
    }

    if (0 == aes67_net_str2addr(&opts.origin, (uint8_t*)argv[3], strlen(argv[3]))){
        fprintf(stderr, "ERROR invalid originating source %s (must be ipv4/6)\n", argv[3]);
        exit(1);
    }

    FILE * fd = fopen(argv[4], "rb");
    if (fd == NULL){
        fprintf(stderr, "ERROR failed to open file %s\n", argv[4]);
        exit(1);
    }

    uint16_t len = 0;
    uint8_t sdp[1024];

    int c;
    while( (c = fgetc(fd)) != EOF ){
        sdp[len++] = c;
    }

    fclose(fd);


    aes67_sdp_fromstr(&opts.sdp, sdp, len);
}

static void load_from_fd(FILE * fd)
{

}

static void aes67_deinit()
{
    aes67_sap_service_deinit(&sap);
}

static void aes67_init()
{
    aes67_time_init_system();
    atexit(aes67_time_deinit_system);

    aes67_timer_init_system();
    atexit(aes67_timer_deinit_system);

    aes67_sap_service_init(&sap, NULL);
    atexit(aes67_deinit);
}
void aes67_sap_service_event(enum aes67_sap_event event, struct aes67_sap_session * session, u8_t * payloadtype, u16_t payloadtypelen, u8_t * payload, u16_t payloadlen, void * user_data)
{
    // do nothing
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    if ( argc != 5){ // 1 < argc &&
        help(stdout);
        return 0;
    }

    if (argc == 5){
        load_from_args(argv);
    } else {
        load_from_fd(stdin);
    }

    uint8_t packet[1024];

    uint16_t len = aes67_sap_service_msg(&sap, packet, sizeof(packet), opts.status, opts.hash, &opts.origin, &opts.sdp);

    if (len == 0){
        fprintf(stderr, "ERROR failed to generate packet\n");
        return 1;
    }

    for(int i = 0; i < len; i++){
        fwrite(packet, 1, len, stdout);
    }

    fclose(stdout);

    return 0;
}