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
#include <fcntl.h>
#include <sys/errno.h>
#include <string.h>
#include <stdbool.h>

static char * argv0;

static struct {
    bool print_debug;
    bool test;
    enum aes67_audio_encoding encoding;
    int samplerate;
    int nchannels;
} opts;

//static bool use_filter(){
//    return (opts.encoding != aes67_audio_encoding_undefined || opts.samplerate != 0 || opts.nchannels != 0);
//}

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s ([-h?] | [-t [-brc]])\n"
             "Attempts to parse SDP incoming on STDIN (primarily useful to validate SDP files quickly).\n"
             "Options:\n"
             "\t -h\t Prints this info\n"
             "\t -d\t Prints some debug info to STDERR\n"
             "\t -t\t Test if the first (SDP) packet (and only the first) contains at least one valid stream; return 0 if valid, >0 otherwise\n"
             "\t -b\t Filter by bitwidth/encoding (8/16/24/32/AM824, representing L8, L16, L24, L32, AM824 respectively)\n"
             "\t -r\t Filter by sampling rate (frequency); ex. 48000\n"
             "\t -c\t Filter by number of channels required\n"
             , argv0);
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];

    opts.print_debug = false;
    opts.test = false;
    opts.encoding = aes67_audio_encoding_undefined;
    opts.samplerate = 0;
    opts.nchannels = 0;

    int opt;

    while ((opt = getopt(argc, argv, "h?dtb:r:c:")) != -1) {
        switch (opt) {
            case 'd':
                opts.print_debug = true;
                break;

            case 't':
                opts.test = true;
                break;

            case 'b':{
                int e = atoi(optarg);
                if (e == 8){
                    opts.encoding = aes67_audio_encoding_L8;
                } else if (e == 16){
                    opts.encoding = aes67_audio_encoding_L16;
                } else if (e == 24){
                    opts.encoding = aes67_audio_encoding_L24;
                } else if (e == 32){
                    opts.encoding = aes67_audio_encoding_L32;
                } else if (strcmp(AES67_AUDIO_ENC_AM824_STR, optarg) == 0){
                    opts.encoding = aes67_audio_encoding_AM824;
                }else {
                    fprintf(stderr, "ERROR: invalid bitwidth option %s\n", optarg);
                    return EXIT_FAILURE;
                }
            }
                break;


            case 'r':
                opts.samplerate = atoi(optarg);
                break;

            case 'c':
                opts.nchannels = atoi(optarg);
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
        help(stdout);
        return EXIT_FAILURE;
    }

    // set non-blocking stdin
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "Couldn't nonblock stdin\n");
        return 1;
    }

    u8_t rbuf[1500];

    while(feof(stdin) == 0){

        ssize_t r = read(STDIN_FILENO, rbuf, sizeof(rbuf));

        if (r == -1){
            // EAGAIN -> currently no data available
            if (errno != EAGAIN){
                printf("err %d\n", errno);
                break;
            }
        } else if (r > 0){ // data read

            struct aes67_sdp sdp;

            r = aes67_sdp_fromstr(&sdp, rbuf, r, NULL);

            if (opts.test){

                if (r != AES67_SDP_OK){
                    return r;
                }

                // if either no connections, streams, refclock, or encodings given, it is an invalid (unusable) SDP
                if (sdp.connections.count == 0 || sdp.streams.count == 0 || sdp.refclks.count == 0 || sdp.encodings.count == 0){
                    return EXIT_FAILURE;
                }

                for( int s = 0; s < sdp.streams.count; s++){

                    // skip stream if no valid connection given (shouldn't be the case in a valid SDP packet)
                    if (NULL == aes67_sdp_get_connection(&sdp, s)){
                        continue;
                    }

                    // skip if stream has no valid refclock
                    if (0 == aes67_sdp_get_refclk_count(&sdp, s)){
                        continue;
                    }

                    // skip if stream has no encoding
                    if (0 == aes67_sdp_get_stream_encoding_count(&sdp, s)){
                        continue;
                    }

                    struct aes67_sdp_attr_encoding * encoding = aes67_sdp_get_stream_encoding(&sdp, s, 0);

                    if (opts.nchannels > 0 && opts.nchannels != encoding->nchannels){
                        continue;
                    }
                    if (opts.encoding != aes67_audio_encoding_undefined && opts.encoding != encoding->encoding){
                        continue;
                    }
                    if (opts.samplerate != 0 && opts.samplerate != encoding->samplerate){
                        continue;
                    }


                    return EXIT_SUCCESS;
                }

                return EXIT_FAILURE;
            } // no test


            if (r == AES67_SDP_OK){

                sdp.originator.username.data[sdp.originator.username.length] = '\0';
                sdp.originator.address.data[sdp.originator.address.length] = '\0';
                sdp.originator.session_id.data[sdp.originator.session_id.length] = '\0';
                sdp.originator.session_version.data[sdp.originator.session_version.length] = '\0';

                printf("SESSION %s@%s %s.%s", sdp.originator.username.data, sdp.originator.address.data, sdp.originator.session_id.data, sdp.originator.session_version.data);

                if ((sdp.ptp_domain & AES67_SDP_PTPDOMAIN_SET) == AES67_SDP_PTPDOMAIN_SET) {
                    printf(" ptp-domain=%d", sdp.ptp_domain & AES67_SDP_PTPDOMAIN_VALUE);
                }

#if 0 < AES67_SDP_MAXSESSIONNAME
//                    if (sdp.name.length){
                    sdp.name.data[sdp.name.length] = '\0';
                    printf(" \"%s\"", sdp.name.data);
//                    }
#endif
#if 0 < AES67_SDP_MAXSESSIONINFO
//                    if (sdp.info.length){
                    sdp.info.data[sdp.info.length] = '\0';
                    printf(" \"%s\"", sdp.info.data);
//                    }
#endif
#if 0 < AES67_SDP_MAXTOOL
//                    if (sdp.tool.length){
                    sdp.tool.data[sdp.tool.length] = '\0';
                    printf(" tool=%s", sdp.tool.data);
//                    }
#endif

                printf("\n");

                for(int i = 0; i < sdp.streams.count; i++){
                    struct aes67_sdp_stream * stream = &sdp.streams.data[i];

                    printf(" stream#%d ", i);

                    struct aes67_sdp_connection * con = aes67_sdp_get_connection(&sdp, i);

                    con->address.data[con->address.length] = '\0';
                    printf("%s:%d/%d IP%c ", con->address.data, stream->port, stream->nports, con->ipver == aes67_net_ipver_4 ? '4' : '6');

                    enum aes67_sdp_attr_mode mode = aes67_sdp_get_mode(&sdp, i);

                    if (mode == aes67_sdp_attr_mode_inactive){
                        printf("mode=inactive ");
                    } else if (mode == aes67_sdp_attr_mode_recvonly){
                        printf("mode=recvonly ");
                    } else if (mode == aes67_sdp_attr_mode_sendonly){
                        printf("mode=sendonly ");
                    } else if (mode == aes67_sdp_attr_mode_sendrecv){
                        printf("mode=sendrecv ");
                    } else {
                        printf("mode= ");
                    }

                    struct aes67_sdp_attr_mediaclk * mediaclk = aes67_sdp_get_mediaclock(&sdp, i);
                    if (mediaclk && mediaclk->set) {
                        printf("clk-offset=%u", mediaclk->offset);
                    }

                    if ( (stream->ptime & AES67_SDP_PTIME_SET) == AES67_SDP_PTIME_SET){
                        printf(" ptime=%d", stream->ptime & AES67_SDP_PTIME_VALUE);
                    } else {
                        printf(" ptime=0");
                    }

                    printf(" nenc=%d nrefclk=%d", stream->nencodings, aes67_sdp_get_refclk_count(&sdp, i));

#if 0 < AES67_SDP_MAXPTIMECAPS
                    printf( " nptime-cap=%d", stream->ptime_cap.count);
#endif
#if 0 < AES67_SDP_MAXSTREAMINFO
                    stream->info.data[stream->info.length] = '\0';
                    printf(" \"%s\"", stream->info.data);
#endif

                    printf("\n");

                    for (int e = 0; e < sdp.streams.data[i].nencodings; e++){

                        printf("  enc#%d.%d ", i, e);

                        struct aes67_sdp_attr_encoding * enc = aes67_sdp_get_stream_encoding(&sdp, i, e);

                        if (enc->encoding == aes67_audio_encoding_L8){
                            printf("%s ", AES67_AUDIO_ENC_L8_STR);
                        } else if (enc->encoding == aes67_audio_encoding_L16){
                            printf("%s ", AES67_AUDIO_ENC_L16_STR);
                        } else if (enc->encoding == aes67_audio_encoding_L24){
                            printf("%s ", AES67_AUDIO_ENC_L24_STR);
                        } else if (enc->encoding == aes67_audio_encoding_L32){
                            printf("%s ", AES67_AUDIO_ENC_L32_STR);
                        } else if (enc->encoding == aes67_audio_encoding_AM824){
                            printf("%s ", AES67_AUDIO_ENC_AM824_STR);
                        }

                        printf("%d %d\n", enc->samplerate, enc->nchannels);
                    }

                    int np = aes67_sdp_get_refclk_count(&sdp, i);
                    for(int p = 0; p < np; p++){

                        printf("  refclk#%d.%d ", i, p);

                        struct aes67_sdp_attr_refclk * clk = aes67_sdp_get_refclk(&sdp, i, p);

                        if (clk->type == aes67_sdp_refclktype_localmac){
                            printf("localmac %02x-%02x-%02x-%02x-%02x-%02x\n", clk->data.localmac[0], clk->data.localmac[1], clk->data.localmac[2], clk->data.localmac[3], clk->data.localmac[4], clk->data.localmac[5]);
                        }
                        else if (clk->type == aes67_sdp_refclktype_ptptraceable){
                            printf("ptp-traceable\n");
                        }
                        else if (clk->type == aes67_sdp_refclktype_ptpclock){

                            printf("ptp-clock ");

                            if (clk->data.ptp.type == aes67_ptp_type_IEEE1588_2002){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2002);
                            } else if (clk->data.ptp.type == aes67_ptp_type_IEEE1588_2008){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2008);
                            } else if (clk->data.ptp.type == aes67_ptp_type_IEEE1588_2019){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2019);
                            } else if (clk->data.ptp.type == aes67_ptp_type_IEEE802AS_2011){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE802AS_2011);
                            }

                            printf("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X", clk->data.ptp.gmid.u8[0], clk->data.ptp.gmid.u8[1], clk->data.ptp.gmid.u8[2], clk->data.ptp.gmid.u8[3], clk->data.ptp.gmid.u8[4], clk->data.ptp.gmid.u8[5], clk->data.ptp.gmid.u8[6], clk->data.ptp.gmid.u8[7]);

                            if (clk->data.ptp.type == aes67_ptp_type_IEEE1588_2008 || clk->data.ptp.type == aes67_ptp_type_IEEE1588_2019){
                                printf(" %d", clk->data.ptp.domain);
                            }

                            printf("\n");
                        }

                    }

#if 0 < AES67_SDP_MAXPTIMECAPS
                    if ((stream->ptime_cap.cfg & AES67_SDP_CAP_SET) == AES67_SDP_CAP_ACTIVE){
                        printf("  ptime-acfg#%d %d\n", i, stream->ptime_cap.cfg & AES67_SDP_CAP_VALUE);
                    }
                    if ((stream->ptime_cap.cfg & AES67_SDP_CAP_SET) == AES67_SDP_CAP_PROPOSED){

                        for (int j = 0; j < stream->ptime_cap.count; j++){
                            printf("  ptime-pcap#%d.%d ptime=%d %s\n", i, stream->ptime_cap.data[j].cap, stream->ptime_cap.data[j].ptime, (stream->ptime_cap.cfg_a == stream->ptime_cap.data[j].cap) ? "proposed" : "");
                        }
                    }
#endif // 0 < AES67_SDP_MAXPTIMECAPS

//                        printf("\n");
                }
            } else if (memcmp("o=", rbuf, 2) == 0){

                struct aes67_sdp_originator origin;

                r = aes67_sdp_origin_fromstr(&origin, rbuf, r-1);


                if (r == AES67_SDP_OK){

                    origin.username.data[origin.username.length] = '\0';
                    origin.address.data[origin.address.length] = '\0';
                    origin.session_id.data[origin.session_id.length] = '\0';
                    origin.session_version.data[origin.session_version.length] = '\0';

                    printf("ORIGIN %s@%s %s.%s\n", origin.username.data, origin.address.data, origin.session_id.data, origin.session_version.data);

                }
            }

            if (opts.print_debug){

                if (r != AES67_SDP_OK){
                    switch(r){
                        case AES67_SDP_ERROR:
                            fprintf(stderr, "ERROR generic\n");
                            break;

                        case AES67_SDP_NOTSUPPORTED:
                            fprintf(stderr, "ERROR features not supported\n");
                            break;

                        case AES67_SDP_NOMEMORY:
                            fprintf(stderr, "ERROR not enough memory\n");
                            break;

                        case AES67_SDP_INCOMPLETE:
                            fprintf(stderr, "ERROR incomplete parsing\n");
                            break;

                        default:
                            fprintf(stderr, "ERROR\n");
                    }
                }
            }


        } else { // r == 0 if stdin closed
            break;
        }
    }


    return 0;
}