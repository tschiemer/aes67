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

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>

enum extract_mode {
    explicit_with_sdp_fallback,
    sdp_with_explicit_fallback
};

static struct {
    uint8_t status;
    s32_t hash;
    struct aes67_net_addr origin;
    uint8_t * payloadtype;
    bool verbose;
    bool v1;
    enum extract_mode extractMode;
} opts;

static bool is_sdp;

static const char sdp_mimetype[] = AES67_SDP_MIMETYPE;

static char * argv0;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h|-?] | [-a|-d] [--hash <hash>] [-o <origin-ip>] [-p <payloadtype> | --v1] [<file> ...]\n"
             "Writes SAP packet to STDOUT.\n"
             "If a <file> is given assumes it is a single payload file.\n"
             "If no <file> is given tries to read from STDIN (if SDP payload is assumed looks for SDP start, ie \"v=0\").\n"
             "Options:\n"
             "\t -h,-?\t\t Prints this info.\n"
             "\t -a\t\t Announcement type message (default)\n"
             "\t -d\t\t Delete type message (note: expects but an originator line)\n"
             "\t --hash <hash>\t Force this hash id (if not given tries to extract from SDP file, session id)\n"
             "\t -o <origin-ip>\t Force this originating IP (if not given tries to extract from SDP file, originating addr)\n"
             "\t -p <payloadtype>\t Use this particular (MIME) payload type (if not given uses 'application/sdp')\n"
             "\t --v1\t\t Use a SAPv1 packet format (implies SDP payload, allows a zero-hash, requires IPv4 origin)\n"
             "\t --xf\t\t Attempt to parse SDP payload, on fail fallback to given hash and origin-ip\n"
             "\t -v\t\t Print some basic info to STDERR\n"
             "Examples:\n"
             "./sap-pack test.sdp | socat -u - UDP4-DATAGRAM:239.255.255.255:9875\n"
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

static bool get_originator(u8_t * payload, size_t len, struct aes67_sdp_originator * origin)
{
    if (len < sizeof("v=0\r\no=- 1 1 IN IP4 1")){
        return false;
    }

    // try to detect originator start
    u8_t * o;
    if (payload[0] == 'v' && payload[1] == '=' && payload[2] == '0'){
        if (payload[3] == '\n'){
            o = &payload[4];
        } else if (payload[4] == '\n'){
            o = &payload[5];
        } else {
            return false;
        }
    } else if (payload[0] == 'o' && payload[1] == '='){
        o = payload;
    } else {
        return false;
    }

    return AES67_SDP_OK == aes67_sdp_origin_fromstr(origin, o, &payload[len] - o);
}

static int generate_packet(u8_t * payload, size_t plen, size_t typelen)
{
    uint8_t packet[1500];

    size_t totallen = plen+typelen;

    struct aes67_sdp_originator origin;
    bool parsed_sdp = false;

    if (is_sdp){
        parsed_sdp = get_originator(&payload[typelen], plen, &origin);
    }

    u16_t hash = 0;

    if (opts.extractMode == sdp_with_explicit_fallback){
        if (parsed_sdp){
            hash = atoi((char*)origin.session_id.data);
        } else if (opts.hash != -1){
            hash = opts.hash;
        } else {
            fprintf(stderr, "SAP-PACK sdp parse failed, no hash fallback given\n");
            return EXIT_FAILURE;
        }
    }
    else if (opts.extractMode == explicit_with_sdp_fallback){
        if (opts.hash != -1){
            hash = opts.hash;
        } else if (parsed_sdp){
            hash = atoi((char*)origin.session_id.data);
        } else {
            fprintf(stderr, "SAP-PACK no hash given, sdp parse fallback failed\n");
            return EXIT_FAILURE;
        }
    }


    struct aes67_net_addr ip;

    if (opts.extractMode == sdp_with_explicit_fallback){
        if (aes67_net_str2addr(&ip, (u8_t*)origin.address.data, origin.address.length)){
            // success!
        }
        else if (opts.origin.ipver != aes67_net_ipver_undefined){
            aes67_net_addrcp(&ip, &opts.origin);
        } else {
            fprintf(stderr, "SAP-PACK sdp parse failed, no origin-ip fallback given\n");
            return EXIT_FAILURE;
        }
    }
    else if (opts.extractMode == explicit_with_sdp_fallback){
        if (opts.origin.ipver != aes67_net_ipver_undefined){
            aes67_net_addrcp(&ip, &opts.origin);
        } else if (aes67_net_str2addr(&ip, (u8_t*)origin.address.data, origin.address.length)){
            // success!
        } else {
            fprintf(stderr, "SAP-PACK no origin given, sdp parse fallback failed\n");
            return EXIT_FAILURE;
        }
    }

    // sanity check
    if (opts.v1 && ip.ipver != aes67_net_ipver_4){
        fprintf(stderr, "SAP-PACK v1 requires ipv4\n");
        return EXIT_FAILURE;
    }


    if (opts.verbose){
        u8_t ipstr[128];
        size_t l = aes67_net_addr2str(ipstr, &ip);
        ipstr[l] = '\0';
        fprintf(stderr, "SAP-PACK %s %hu %s\n", opts.status == AES67_SAP_STATUS_MSGTYPE_ANNOUNCE ? "announce" : "delete", hash, ipstr);
        fflush(stderr);
    }


    uint16_t len = aes67_sap_service_msg(NULL, packet, sizeof(packet), opts.status, hash, ip.ipver, ip.ip,
                                         payload, totallen, NULL);

    if (len == 0){
        // should only happen if the max packet size was too small.
        fprintf(stderr, "ERROR failed to generate packet\n");
        return EXIT_FAILURE;
    }

    if (write(STDOUT_FILENO, packet, len) == -1){
        fprintf(stderr, "error writing to stdout\n");
    }

    return EXIT_SUCCESS;
}

int set_stdin_blocking(bool enabled)
{
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);

  if (enabled){ // blocking
      if (fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK) == -1){
          fprintf(stderr, "Couldn't block stdin\n");
          return EXIT_FAILURE;
      }
  } else { // non-blocking
    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "Couldn't nonblock stdin\n");
        return EXIT_FAILURE;
    }
  }
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
    opts.v1 = false;
    opts.extractMode = explicit_with_sdp_fallback;

    is_sdp = true;

    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"hash",  required_argument,       0,  1 },
                {"announce",  no_argument,       0,  'a' },
                {"delete",  no_argument,       0,  'd' },
                {"origin",  no_argument,       0,  'o' },
                {"payloadtype",  no_argument,       0,  'p' },
                {"v1", no_argument, 0, 2},
                {"xf", no_argument, 0, 3},
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hadponsv",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 1:
                opts.hash = atoi(optarg);
                break;

            case 2:
                opts.v1 = true;
                break;

            case 3:
                opts.extractMode = sdp_with_explicit_fallback;
                break;

            case 'a':
                opts.status = AES67_SAP_STATUS_MSGTYPE_ANNOUNCE;
                break;

            case 'd':
                opts.status = AES67_SAP_STATUS_MSGTYPE_DELETE;
                break;

            case 'p':
                opts.payloadtype = (u8_t*)optarg;
                is_sdp = strcmp(optarg, sdp_mimetype) == 0;
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


    if (opts.v1 == false && opts.hash == 0){
        fprintf(stderr, "ERROR zero hash only allowed for SAPv1\n");
        return EXIT_FAILURE;
    }

    u8_t inbuf[1500];

    size_t typelen = (opts.v1 || opts.payloadtype == NULL) ? 0 : (strlen((char*)opts.payloadtype) + 1);

    if (typelen > 0){
        strcpy((char*)inbuf, (char*)opts.payloadtype);
    }


    if (optind < argc){
        for (int i = optind; i < argc; i++){
            size_t plen = readfile(argv[i], &inbuf[typelen], sizeof(inbuf) - typelen - 1 );
            if (generate_packet(inbuf, plen, typelen)){
                return EXIT_FAILURE; // really exit on error?
            }
        }
        return EXIT_SUCCESS;
    }


    // set non-blocking stdin
    set_stdin_blocking(false);

    u8_t * payload = &inbuf[typelen];

    size_t maxlen = sizeof(inbuf) - typelen;

    ssize_t r;

    u8_t ch;
    size_t len = 0;

    // get char by char, try to locate "v=0"
    while( (r = read(STDIN_FILENO, &ch, 1)) ){

        // timeout
        if (r == -1){
            if (len > 0){
                generate_packet(inbuf, len, typelen);
                len = 0;

                // set blocking stdin
                set_stdin_blocking(true);
            }
        }
        if (r > 0) {

            if (len >= maxlen){
                fprintf(stderr, "SAP-PACK inbuffer overflow, discarding data\n");

                len = 0;
            }

            payload[len++] = ch;

            if (len > 8 && memcmp(&payload[len-4], "\nv=0", 4) == 0){
                payload[len-3] = '\0'; // not needed, but makes it nicer in debug
                generate_packet(inbuf, len - 3, typelen);
                memcpy(payload, "v=0", 3);
                len = 3;
            }
        }
    }

    // in case STDIN was closed see if there might be something to be processed still
    if (len > 0){
        generate_packet(inbuf, len, typelen);
    }

    return 0;
}
