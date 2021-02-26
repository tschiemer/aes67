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
#include "aes67/sdp.h"

#include <getopt.h>
#include <stdio.h>

static struct {
    uint8_t status;
    s32_t hash;
    struct aes67_net_addr origin;
    uint8_t * payloadtype;
    bool is_sdp;
    bool verbose;
} opts;

static const char sdp_mimetype[] = AES67_SDP_MIMETYPE;

static char * argv0;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h|-?] | [-a|-d] [--hash <hash>] [-o <origin-ip>] [-p <payloadtype> | -n] [<file>]\n"
             "Writes SAPv2 packet to STDOUT.\n"
             "If a <file> is given assumes it is a single SDP file.\n"
             "If no <file> is given tries to read from STDIN (does not look for SDP start, goes by timing (remember to flush buffers nicely).\n"
             "Options:\n"
             "\t -h,-?\t\t Prints this info.\n"
             "\t -a\t\t Announcement message (default)\n"
             "\t -d\t\t Delelete message (note: expects but an originator line)\n"
             "\t --hash <hash>\t Use this has id (otherwise tries to extract from SDP file, session id)\n"
             "\t -o <origin-ip>\t Use this originating IP (if not given tries to extract from SDP file, originating addr)\n"
             "\t -p <payloadtype>\t Use this particular (MIME) payload type (if not given uses 'application/sdp')\n"
             "\t -n\t\t Do NOT use any payload type at all\n"
             "\t -v\t\t Print some basic info to STDERR\n"
             "Examples:\n"
             "./sap-pack test.sdp | socat -u - UDP4-DATAGRAM:224.2.127.254:9875\n"
             "watch -t 300 \"./sap-pack  test.sdp | socat -u -v - UDP4-DATAGRAM:224.2.127.254:9875\"\n"
             , argv0);
}


static size_t readfile(char * fname, u8_t * buf, size_t maxlen)
{
    FILE * fd = fopen(fname, "rb");
    if (fd == NULL){
        fprintf(stderr, "ERROR failed to open file %s\n", fname);
        exit(EXIT_FAILURE);
    }

    int c;
    ssize_t len = 0;
    while( (c = fgetc(fd)) != EOF ){
        if (len >= maxlen){
            fprintf(stderr, "ERROR overflow\n");
            exit(EXIT_FAILURE);
        }
        buf[len++] = c;
    }

    fclose(fd);

    return len;
}



static int generate_packet(u8_t * payload, size_t plen, size_t typelen)
{
    uint8_t packet[1500];

    size_t totallen = plen+typelen;

    bool is_sdp = opts.is_sdp || (typelen && strcmp((char*)payload, AES67_SDP_MIMETYPE));

    struct aes67_sdp sdp;
    if (is_sdp){
        int r = aes67_sdp_fromstr(&sdp, &payload[typelen], plen, NULL);
        if (r != AES67_SDP_OK && r != AES67_SDP_INCOMPLETE){
            fprintf(stderr, "SAP-PACK sdp parse error %d\n", r);
            return EXIT_FAILURE;
        }
    }

    u16_t hash;

    if (opts.hash != -1){
        hash = opts.hash;
    } else {
        hash = atoi((char*)sdp.originator.session_id.data);
    }

    struct aes67_net_addr ip;

    if (opts.origin.ipver != aes67_net_ipver_undefined){
        aes67_net_addrcp(&ip, &opts.origin);
    } else {

        if (aes67_net_str2addr(&ip, (u8_t*)sdp.originator.address.data, sdp.originator.address.length) == false){
            fprintf(stderr, "SAP-PACK addr fail\n");
            return EXIT_FAILURE;
        }
    }

    if (opts.verbose){
        u8_t ipstr[64];
        size_t l = aes67_net_addr2str(ipstr, &ip);
        ipstr[l] = '\0';
        fprintf(stderr, "SAP-PACK %s %hu %s\n", opts.status == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ? "announce" : "delete", hash, ipstr);
        fflush(stderr);
    }


    uint16_t len = aes67_sap_service_msg(NULL, packet, sizeof(packet), opts.status, hash, ip.ipver, ip.addr,
                                         payload, totallen, NULL);

    if (len == 0){
        fprintf(stderr, "ERROR failed to generate packet\n");
        return EXIT_FAILURE;
    }

    write(STDOUT_FILENO, packet, len);

    return EXIT_SUCCESS;
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
    opts.origin.ipver = aes67_net_ipver_undefined;
    opts.hash = -1;
    opts.payloadtype = (u8_t *)sdp_mimetype;
    opts.verbose = false;
    opts.is_sdp = false;

    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"hash",  required_argument,       0,  1 },
                {"announce",  no_argument,       0,  'a' },
                {"delete",  no_argument,       0,  'd' },
                {"origin",  no_argument,       0,  'o' },
                {"payloadtype",  no_argument,       0,  'p' },
                {"no-payloadtype",  no_argument,       0,  'n' },
                {"sdp",  no_argument,       0,  's' },
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hadponsv",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 1:
                opts.hash = atoi(optarg);
                if (opts.hash == 0){
                    fprintf(stderr, "ERROR invalid hash %d", opts.hash);
                    return EXIT_FAILURE;
                }
                break;

            case 'a':
                opts.status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
                break;

            case 'd':
                opts.status = AES67_SAP_STATUS_MSGTYPE_DELETE;
                break;

            case 'p':
                opts.payloadtype = (u8_t*)optarg;
                break;

            case 'n':
                opts.payloadtype = NULL;
                break;

            case 's':
                opts.is_sdp = true;
                break;

            case 'o':
                if (0 == aes67_net_str2addr(&opts.origin, (uint8_t*)optarg, strlen(optarg))){
                    fprintf(stderr, "ERROR invalid originating source %s (must be ipv4/6)\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

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

    if ( optind + 1 < argc ){ // 1 < argc &&
        fprintf(stderr, "wrong argument count\n");
        return EXIT_FAILURE;
    }

    u8_t inbuf[1500];

    size_t typelen = opts.payloadtype == NULL ? 0 : strlen((char*)opts.payloadtype);

    if (typelen > 0){
        strcpy((char*)inbuf, (char*)opts.payloadtype);
    }


    if (optind + 1 == argc){
        size_t plen = readfile(argv[optind], &inbuf[typelen], sizeof(inbuf) - typelen - 1 );
        generate_packet(inbuf, plen, typelen);
        return EXIT_SUCCESS;
    }


    // set non-blocking stdin
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "Couldn't nonblock stdin\n");
        return EXIT_FAILURE;
    }

    u8_t * payload = &inbuf[typelen];

    size_t maxlen = sizeof(inbuf) - typelen;

    ssize_t r;

    while( (r = read(STDIN_FILENO, payload, maxlen)) ){

        if (r > 0) {
            generate_packet(inbuf, r, typelen);
        }
    }

    return 0;
}