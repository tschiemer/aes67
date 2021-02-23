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

#include "aes67/sdp.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static char * argv0;

static struct aes67_sdp sdp;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage:\n"
             "\t %s [-h?]\n"
             "\t %s [options...] <src-host> <dst-ip>[:<rtp-port>] \n"
             "Generator for quick and dirty single-stream SDP generation.\n"
             "Arguments:\n"
             "\t <src-host>\t\t\t IPv4/v6 or hostname of SDP originator host (see --src-ipver to explicitly set ip version)\n"
             "\t <target-ip-port>\t\t IPv4/v6 of sending/receiving host\n"
             "Options:\n"
             "\t -h, -?\t\t\t\t Prints this info\n"
             "\t --src-ipver <ipver>\t\t Explicitly sets SDP originator IP version (4, default, or 6)\n"
             "\t --id <id>\t\t\t Session ID (U32, default 1)\n"
             "\t --version <version>\t\t Session version (U32, default 1)\n"
             "\t -n, --name <name>\t\t Name of session (default none)\n"
             "\t -i, --info <info>\t\t Further session info (default none)\n"
             "\t --ptp-domain <domain>\t\t (RAVENNA) PTP domain (u7, default none)\n"
             "\t -m, --mode <mode>\t\t Stream mode, most likely you will use \"recv\" (default, for recipient to be receiving only, ie you will be sending)\n"
             "\t -b <samplebitsize>\t\t 'Bitrate' of encoding, values 8/16/24/32 accepted only (default 24)\n"
             "\t -r <rate>\t\t\t Samplerate (default 48000)\n"
             "\t -c <nchannels>\t\t\t Number of channels (default 2)\n"
             "\t --ttl <ttl>\t\t\t IPv4 multicasting TTL override (default 32)\n"
             "\t --ptime <ptime>\t\t ptime value as millisec float (default 1.0)\n"
             "\t --refclk-localmac <mac>\n"
             "\t --ptp-traceable\t\t Default reference clock!\n"
             "\t --ptp-clock <ptp-std>:<ptp-eui64>[:<domain>]\n"
             "\t --mediaclk-offset <offset>\t Mediaclock offset (default 0)\n"
            , argv0, argv0);
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];

    if (argc <= 1){
        help(stdout);
        return EXIT_SUCCESS;
    }

    aes67_sdp_init(&sdp);

    // setup default options

    sdp.originator.session_id.data[0] = '1';
    sdp.originator.session_id.length = 1;
    sdp.originator.session_version.data[0] = '1';
    sdp.originator.session_version.length = 1;
    sdp.originator.ipver = aes67_net_ipver_4;

    struct aes67_sdp_connection * con = aes67_sdp_add_connection(&sdp, AES67_SDP_FLAG_DEFLVL_SESSION);

    con->ipver = aes67_net_ipver_4;

    u8_t si = 0;
    struct aes67_sdp_stream * stream = aes67_sdp_add_stream(&sdp, &si);

    stream->port = AES67_RTP_AVP_PORT_DEFAULT;
    stream->ptime = AES67_SDP_PTIME_SET | 1000;
    stream->mediaclock.set = 1;
    stream->mediaclock.offset = 0;

    struct aes67_sdp_attr_encoding * encoding = aes67_sdp_add_stream_encoding(&sdp, 0);

    encoding->payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START;
    encoding->encoding = aes67_audio_encoding_L24;
    encoding->samplerate = 48000;
    encoding->nchannels = 2;

    struct aes67_sdp_attr_refclk * clk = aes67_sdp_add_refclk(&sdp, AES67_SDP_FLAG_DEFLVL_STREAM | 0);

    clk->type = aes67_sdp_refclktype_ptptraceable;

    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"src-ipver",  required_argument,       0,  0 },
                {"id",  required_argument,       0,  1 },
                {"version",  required_argument,       0,  2 },
                {"name",  required_argument,       0,  'n' },
                {"info",  required_argument,       0,  'i' },
                {"ptp-domain",  required_argument,       0,  3 },
                {"mode",     required_argument, 0,  'm' },
                {"bitrate",     required_argument, 0,  'b' },
                {"rate",     required_argument, 0,  'r' },
                {"nchannels",     required_argument, 0,  'c' },
                {"ttl",     required_argument, 0,  4 },
                {"ptime",  required_argument, 0,  5 },
                {"refclk-localmac",  required_argument, 0,  6 },
                {"ptp-traceable", no_argument, 0,  7 },
                {"ptp-clock", required_argument,0,  8 },
                {"mediaclk-offset", required_argument,0,  9 },
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hsn:i:m:b:r:c:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 0:{ // --src-ip-ver
                int t = atoi(optarg);
                if (t == 4){
                    sdp.originator.ipver = aes67_net_ipver_4;
                } else if (t == 6){
                    sdp.originator.ipver = aes67_net_ipver_6;
                } else {
                    fprintf(stderr, "invalid --src-ipver\n");
                    return EXIT_FAILURE;
                }
                break;
            }
//                printf("option %s", long_options[option_index].name);
//                if (optarg)
//                    printf(" with arg %s", optarg);
//                printf("\n");

            case 1: { // --id
                memcpy(sdp.originator.session_id.data, optarg, strlen(optarg));
                sdp.originator.session_id.length = strlen(optarg);
                break;
            }

            case 2: { // --version
                memcpy(sdp.originator.session_version.data, optarg, strlen(optarg));
                sdp.originator.session_version.length = strlen(optarg);
                break;
            }

            case 'n': { // --name
                memcpy(sdp.name.data, optarg, strlen(optarg));
                sdp.name.length = strlen(optarg);
                break;
            }

            case 'i': { // --info
                memcpy(sdp.info.data, optarg, strlen(optarg));
                sdp.info.length = strlen(optarg);
                break;
            }

            case 3:{ // --ptp-domain
                int t = atoi(optarg);
                if (t > 127){
                    fprintf(stderr, "invalid --ptp-domain\n");
                    return EXIT_FAILURE;
                }
                aes67_sdp_set_ptpdomain(&sdp, t);
                break;
            }

            case 'm':{ // --mode recv|send|inactive|sendrecv

                if (strcmp("recv", optarg) == 0) {
                    sdp.mode = aes67_sdp_attr_mode_recvonly;
                } else if (strcmp("send", optarg) == 0) {
                    sdp.mode = aes67_sdp_attr_mode_sendonly;
                } else if (strcmp("sendrecv", optarg) == 0) {
                    sdp.mode = aes67_sdp_attr_mode_sendrecv;
                } else if (strcmp("inactive", optarg) == 0) {
                    sdp.mode = aes67_sdp_attr_mode_inactive;
                } else {
                    fprintf(stderr, "invalid --ptp-domain\n");
                    return EXIT_FAILURE;
                }
                break;
            }

            case 'b':{ // --bitrate
                int t = atoi(optarg);
                if (t == 8){
                    encoding->encoding = aes67_audio_encoding_L8;
                } else if (t == 16){
                    encoding->encoding = aes67_audio_encoding_L16;
                } else if (t == 24){
                    encoding->encoding = aes67_audio_encoding_L24;
                } else if (t == 32){
                    encoding->encoding = aes67_audio_encoding_L32;
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
                encoding->samplerate = t;
                break;
            }

            case 'c':{ // --rate
                int t = atoi(optarg);
                if (t == 0){ // well...
                    fprintf(stderr, "invalid --nchannel\n");
                    return EXIT_FAILURE;
                }
                encoding->nchannels = t;
                break;
            }

            case 4:{ // --ttl
                int t = atoi(optarg);
                if (t > 127){ // well...
                    fprintf(stderr, "invalid --ttl\n");
                    return EXIT_FAILURE;
                }
                con->ttl = t;
                break;
            }

            case 5:{ // --ptime
                float f = atof(optarg);
                if (f == 0.0){ // well...
                    fprintf(stderr, "invalid --ttl\n");
                    return EXIT_FAILURE;
                }
                stream->ptime = AES67_SDP_PTIME_SET | ((u16_t)(1000.0 * f));
                break;
            }

            case 6: { // refclk-localmac
                clk->type = aes67_sdp_refclktype_localmac;

                if (strlen(optarg) != sizeof("01-02-03-04-05-06")-1){
                    fprintf(stderr, "invalid localmac\n");
                    return EXIT_FAILURE;
                }
                for(int i = 0; i < 6; i++){
                    char * end;
                    uint32_t t = strtoul(&optarg[3*i], &end, 16);
                    if (end != &optarg[3*i+2]){
                        fprintf(stderr, "invalid localmac\n");
                        return EXIT_FAILURE;
                    }
                    clk->data.localmac[i] = t;
                }
                break;
            }

            case 7: { // ptp-traceable
                clk->type = aes67_sdp_refclktype_ptptraceable;
                break;
            }

            case 8: { // ptp-clock
                clk->type = aes67_sdp_refclktype_ptpclock;

                char * delim = strchr(optarg, ':');

                if (delim == NULL){
                    fprintf(stderr, "invalid ptp clock1\n");
                    return EXIT_FAILURE;
                }
                delim[0] = '\0';

                if (strcmp(&AES67_PTP_TYPE_STR_IEEE1588_2002[4], optarg) == 0){
                    clk->data.ptp.type = aes67_ptp_type_IEEE1588_2002;
                } else if (strcmp(&AES67_PTP_TYPE_STR_IEEE1588_2008[4], optarg) == 0){
                    clk->data.ptp.type = aes67_ptp_type_IEEE1588_2008;
                } else if (strcmp(&AES67_PTP_TYPE_STR_IEEE1588_2019[4], optarg) == 0){
                    clk->data.ptp.type = aes67_ptp_type_IEEE1588_2019;
                } else if (strcmp(&AES67_PTP_TYPE_STR_IEEE802AS_2011[4], optarg) == 0){
                    clk->data.ptp.type = aes67_ptp_type_IEEE802AS_2011;
                } else {
                    fprintf(stderr, "invalid ptp clock2\n");
                    return EXIT_FAILURE;
                }
                delim++;

                if (strlen(delim) < sizeof("01-02-03-04-05-06-07-08")-1){
                    fprintf(stderr, "invalid ptp clock3\n");
                    return EXIT_FAILURE;
                }

                for(int i = 0; i < 8; i++, delim+=3){
                    char * end;
                    uint32_t t = strtoul(delim, &end, 16);
                    if (end != &delim[2]){
                        fprintf(stderr, "invalid ptp clock4\n");
                        return EXIT_FAILURE;
                    }
                    clk->data.ptp.gmid.u8[i] = t;
                }

                if (clk->data.ptp.type == aes67_ptp_type_IEEE1588_2008 || clk->data.ptp.type == aes67_ptp_type_IEEE1588_2019){
                    if (strlen(delim) < 1){
                        fprintf(stderr, "invalid ptp clock5\n");
                        return EXIT_FAILURE;
                    }

                    int t = atoi(delim);
                    if (t > 127){
                        fprintf(stderr, "invalid ptp clock6\n");
                        return EXIT_FAILURE;
                    }
                    clk->data.ptp.domain = t;
                }

                break;
            }

            case 9: { // mediaclk-offset
                stream->mediaclock.set = 1;
                stream->mediaclock.offset = atol(optarg);
                break;
            }

            case '?':
            case 'h':
                help(stdout);
                return EXIT_SUCCESS;

            default:
                fprintf(stderr, "Unrecognized option %c\n", c);
                return EXIT_FAILURE;
        }
    }

    if ( optind + 2 != argc ){ // 1 < argc &&
        fprintf(stderr, "wrong argument count\n");
        return EXIT_FAILURE;
    }

    struct aes67_net_addr ip;

    if (aes67_net_str2addr(&ip, (u8_t*)argv[optind], strlen(argv[optind]))){
        ip.port = 0; // just safety..
        sdp.originator.address.length = aes67_net_addr2str(sdp.originator.address.data, &ip);
    } else {
        strcpy((char*)sdp.originator.address.data, argv[optind]);
        sdp.originator.address.length = strlen(argv[optind]);
    }
    optind++;

    if (aes67_net_str2addr(&ip, (u8_t*)argv[optind], strlen(argv[optind]))){

        if (ip.port > 0) {
            stream->port = ip.port;
        }

        ip.port = 0; // unset
        con->address.length = aes67_net_addr2str(con->address.data, &ip);

        // for ipv4 multicast addresses set default ttl if not set
        if (ip.ipver == aes67_net_ipver_4 && aes67_net_ismcastip_addr(&ip) && con->ttl == 0){
            con->ttl = 32;
        }
    } else {
        fprintf(stderr, "please designate an ipaddress as target (no hostname)\n");
        return EXIT_FAILURE;
    }

    u8_t str[1500];

    memset(str, 0, sizeof(str));

    int len = aes67_sdp_tostr(str, sizeof(str), &sdp, NULL);

    if (len == 0){
        fprintf(stderr, "Some error occurcced, no idea!\n");
        return EXIT_FAILURE;
    }

    write(STDOUT_FILENO, str, len);

    return EXIT_SUCCESS;
}