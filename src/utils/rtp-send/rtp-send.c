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
#include "aes67/rtp.h"
#include "aes67/rtp-avp.h"

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

static struct {
    struct aes67_net_addr ip;
    uint16_t port;
    struct aes67_sdp_attr_encoding encoding;
    ptime_t ptime;
} opts = {
    .ip = {
        .ipver = aes67_net_ipver_undefined
    },
    .port = AES67_RTP_AVP_PORT_DEFAULT,
    .encoding = {
        .payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START,
        .encoding = aes67_audio_encoding_undefined,
        .nchannels = 0,
        .samplerate = 0,
    },
    .ptime = 1000
};

static char * argv0;

static volatile bool keep_running;

static struct {
    int fd;
    struct sockaddr_in addr_in;
} sock = {
    .fd = -1
};

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage:\n"
             "%s -h|-?\n"
             "%s --sdp <sdp-file>\n"
             "%s --i <ipv4> -p <port> -r <samplerate> -c <channels> -b <bits> --ptime <ptime> [--payloadtype <type>]\n"
             "Options:\n"
             "\t --sdp <sdp-file>\t Load all parameters from given SDP\n"
             "\t --ip, -i <ipv4>\t Send to given sink address (uni- or multicast)\n"
             "\t --port, -p <port>\t Send to given sink port (default %d)\n"
             "\t --channels, -c <channels>\n"
             "\t\t\t\t\t\t Channel count\n"
             "\t --bits, -b <bits>\t Sample bits (8,16,24,32)\n"
             "\t --ptime, -p <ptime> ptime value as millisec float (default 1.0)"

            , argv0, argv0, argv0, AES67_RTP_AVP_PORT_DEFAULT);
}

static void sig_stop(int sig)
{
    keep_running = false;
}

static void block_until_event(){
//
//    int nfds = 0;
//    fd_set rfds, xfds;
////    sigset_t sigmask;
//
//    FD_ZERO(&rfds);
//    FD_ZERO(&xfds);
//
//    if (opts.rtsp){
//        nfds = rtsp_srv.listen_sockfd;
//        FD_SET(rtsp_srv.listen_sockfd, &rfds);
//        FD_SET(rtsp_srv.listen_sockfd, &xfds);
//        if (rtsp_srv.client_sockfd != -1){
//            FD_SET(rtsp_srv.client_sockfd, &rfds);
//            FD_SET(rtsp_srv.client_sockfd, &xfds);
//            if (rtsp_srv.client_sockfd > rtsp_srv.listen_sockfd){
//                nfds = rtsp_srv.client_sockfd;
//            }
//        }
//    }
//
//    int * sockfds;
//    size_t count = 0;
//    aes67_mdns_getsockfds(mdns, &sockfds, &count);
//    for (size_t i = 0; i < count; i++) {
//        FD_SET(sockfds[i], &rfds);
//        FD_SET(sockfds[i], &xfds);
//        if (sockfds[i] > nfds) {
//            nfds = sockfds[i];
//        }
//    }
//
//    nfds++;
//
//    // just wait until something interesting happens
//    select(nfds, &rfds, NULL, &xfds, NULL);
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

static int loadsdp(char * fname)
{
    u8_t fbuf[1500];

    int flen = readfile(fname, fbuf, sizeof(fbuf));
    if (flen == 0){
        return EXIT_FAILURE;
    }

    struct aes67_sdp sdp;

    int r = aes67_sdp_fromstr(&sdp, (u8_t*)fbuf, flen, NULL);
    if (r != AES67_SDP_OK){
        fprintf(stderr, "failed to parse SDP %s\n", fname);
        return EXIT_FAILURE;
    }

    if (sdp.streams.count != 1){
        fprintf(stderr, "invalid stream/media count in SDP\n");
    }

    if (sdp.streams.data[0].nencodings != 1){
        fprintf(stderr, "please only provide one encoding for stream/media in SDP\n");
        return EXIT_FAILURE;
    }

    if (sdp.encodings.count != 1){
        fprintf(stderr, "there should really only be one encoding for one SDP\n");
        return EXIT_FAILURE;
    }

    if (sdp.connections.count != 1){
        fprintf(stderr, "there should only be one connection in SDP\n");
        return EXIT_FAILURE;
    }

    if (aes67_net_str2addr(&opts.ip, sdp.connections.data[0].address.data, sdp.connections.data[0].address.length) == false){
        fprintf(stderr, "connection must be an ip (not doing lookups)!\n");
        return EXIT_FAILURE;
    }

    opts.port = sdp.streams.data[0].port;
    opts.ptime = sdp.streams.data[0].ptime;
    memcpy(&opts.encoding, sdp.encodings.data, sizeof(struct aes67_sdp_attr_encoding));


    return EXIT_SUCCESS;
}

static int socket_setup()
{
    sock.fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock.fd == -1){
        perror("socket()");
        return EXIT_FAILURE;
    }

    memset(&sock.addr_in, 0, sizeof(struct sockaddr_in));

    sock.addr_in.sin_family = AF_INET;
    sock.addr_in.sin_addr.s_addr = *(in_addr_t*)opts.ip.ip;
    sock.addr_in.sin_port = htons(opts.port);

    int on = 1;
    // inform the kernel do not fill up the packet structure, we will build our own
    if(setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() error");
        return EXIT_FAILURE;
    }

    // if multicast address join group
    if (aes67_net_ismcastip_addr(&opts.ip)){

        struct ip_mreq mreq;
        mreq.imr_interface.s_addr = INADDR_ANY;
        mreq.imr_multiaddr.s_addr = *(in_addr_t*)opts.ip.ip;

        if (setsockopt(sock.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) < 0){
            perror("setsockopt(.. IP_ADD_MEMBERSHIP..)");
            return EXIT_FAILURE;
        }

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void socket_teardown()
{
    if (sock.fd == -1){
        return;
    }
    // if multicast address leave group
    if (aes67_net_ismcastip_addr(&opts.ip)){

        struct ip_mreq mreq;
        mreq.imr_interface.s_addr = INADDR_ANY;
        mreq.imr_multiaddr.s_addr = *(in_addr_t*)opts.ip.ip;

        if (setsockopt(sock.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) < 0){
            perror("setsockopt(.. IP_DROP_MEMBERSHIP..)");
            return;
        }

        return;
    }

    close(sock.fd);

    sock.fd = -1;
}

int main(int argc, char * argv[])
{
    argv0 = argv[0];

    if (argc == 1){
        help(stdout);
        return EXIT_SUCCESS;
    }


    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"sdp",  required_argument,       0,  1 },
                {"bits",  required_argument,       0,  'b' },
                {"channels",  required_argument,       0,  'c' },
                {"rate",  required_argument,       0,  'r' },
                {"payloadtype",  required_argument,       0,  2 },
                {"port", required_argument, 0, 'p'},
                {"rtcp", no_argument, 0, 3},
                {"ip", required_argument, 0, 'i'},
//                {"v1", no_argument, 0, 2},
//                {"xf", no_argument, 0, 3},
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hb:c:r:p:i:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 1: // --sdp
                if (loadsdp(optarg)){
                    fprintf(stderr, "failed to load sdp: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

            case 'b': { // --bits
                int t = atoi(optarg);
                if (t == 8) {
                    opts.encoding.encoding = aes67_audio_encoding_L8;
                } else if (t == 16) {
                    opts.encoding.encoding = aes67_audio_encoding_L16;
                } else if (t == 24) {
                    opts.encoding.encoding = aes67_audio_encoding_L24;
                } else if (t == 32) {
                    opts.encoding.encoding = aes67_audio_encoding_L32;
//                } else if (strcmp(AES67_AUDIO_ENC_AM824_STR, optarg) == 0){
//                    opts.encoding.encoding = aes67_audio_encoding_AM824;
                } else {
                    fprintf(stderr, "invalid --bitrate\n");
                    return EXIT_FAILURE;
                }
                break;
            }

            case 'r':{ // --rate
                int t = atoi(optarg);
                if (t == 0){ // wellllly well
                    fprintf(stderr, "invalid --rate\n");
                    return EXIT_FAILURE;
                }
                opts.encoding.samplerate = t;
                break;
            }

            case 'c':{ // --rate
                int t = atoi(optarg);
                if (t == 0){ // well...
                    fprintf(stderr, "invalid --nchannel\n");
                    return EXIT_FAILURE;
                }
                opts.encoding.nchannels = t;
                break;
            }

            case 2: { // --payloadtype
                int t = atoi(optarg);
                if ((t & ~0x7f) != t) {
                    fprintf(stderr, "invalid payloadtype, must be in 0 - 127\n");
                    return EXIT_FAILURE;
                }
                opts.encoding.payloadtype = t;
                break;
            }

            case 'p': {// --port <port>
                int t = atoi(optarg);
                if ( t <= 0 || 0xffff < t){
                    fprintf(stderr, "invalid port!\n");
                    return EXIT_FAILURE;
                }
                opts.port = t;
                break;
            }

            case 'i': // --ip
                if (0 == aes67_net_str2addr(&opts.ip, (uint8_t*)optarg, strlen(optarg))){
                    fprintf(stderr, "ERROR invalid originating source %s (must be ipv4)\n", optarg);
                    return EXIT_FAILURE;
                }
                if (opts.ip.port != 0){
                    opts.port = opts.ip.port;
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


    if (optind != argc){
        fprintf(stderr, "too many arguments\n");
        return EXIT_FAILURE;
    }

    // parameter checking

    if (opts.ip.ipver != aes67_net_ipver_4){
        fprintf(stderr, "sink must be ipv4\n");
        return EXIT_FAILURE;
    }

    if (!AES67_AUDIO_ENCODING_ISVALID(opts.encoding.encoding) && opts.encoding.encoding != aes67_audio_encoding_AM824){
        fprintf(stderr, "invalid audio encoding\n");
        return EXIT_FAILURE;
    }
    if (opts.encoding.samplerate == 0){ /// ... TODO
        fprintf(stderr, "invalid samplerate\n");
        return EXIT_FAILURE;
    }
    if (opts.encoding.nchannels == 0){
        fprintf(stderr, "invalid channel count\n");
        return EXIT_FAILURE;
    }
    if (opts.ptime == 0){
        fprintf(stderr, "invalid ptime\n");
        return EXIT_FAILURE;
    }


    if (socket_setup()){
        goto shutdown;
    }




    signal(SIGINT, sig_stop);
    signal(SIGTERM, sig_stop);
    keep_running = true;
//    while(keep_running){
//        block_until_event();
//    }

shutdown:

    socket_teardown();

//
//    // set non-blocking stdin
//    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
//    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1){
//        fprintf(stderr, "Couldn't nonblock stdin\n");
//        return EXIT_FAILURE;
//    }
//
//
//
//    u8_t * payload = &inbuf[typelen];
//
//    size_t maxlen = sizeof(inbuf) - typelen;
//
//    ssize_t r;
//
//    u8_t ch;
//    size_t len = 0;
//
//    // get char by char, try to locate "v=0"
//    while( (r = read(STDIN_FILENO, &ch, 1)) ){
//
//        // timeout
//        if (r == -1){
//            if (len > 0){
//                generate_packet(inbuf, len, typelen);
//            }
//        }
//        if (r > 0) {
//
//            if (len >= maxlen){
//                fprintf(stderr, "SAP-PACK inbuffer overflow, discarding data\n");
//
//                len = 0;
//            }
//
//            payload[len++] = ch;
//
//            if (len > 8 && memcmp(&payload[len-4], "\nv=0", 4) == 0){
//                payload[len-3] = '\0'; // not needed, but makes it nicer in debug
//                generate_packet(inbuf, len - 3, typelen);
//                memcpy(payload, "v=0", 3);
//                len = 3;
//            }
//        }
//    }
//
//    // in case STDIN was closed see if there might be something to be processed still
//    if (len > 0){
//        generate_packet(inbuf, len, typelen);
//    }

    return 0;
}