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

//#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <string.h>


static char * argv0;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s \n"
             "Attempts to parse SDP incoming on STDIN\n"
             , argv0);
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];

    if ( argc != 1 ){ // 1 < argc &&
        help(stdout);
        return 0;
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

            if (memcmp("v=0", rbuf, 3) == 0){

                struct aes67_sdp sdp;


                r = aes67_sdp_fromstr(&sdp, rbuf, r);

                if (r == AES67_SDP_OK){

                    sdp.originator.address.data[sdp.originator.address.length] = '\0';
                    printf("src=%s nstream=%d nptp=%d ", sdp.originator.address.data, sdp.streams.count, sdp.ptps.count);

                    if ((sdp.ptp_domain & AES67_SDP_PTP_DOMAIN_SET) == AES67_SDP_PTP_DOMAIN_SET) {
                        printf("ptp-domain=%d ", sdp.ptp_domain & AES67_SDP_PTP_DOMAIN_VALUE);
                    }

                    printf("\n");

                    for(int i = 0; i < sdp.streams.count; i++){
                        struct aes67_sdp_stream * stream = &sdp.streams.data[i];

                        printf(" stream#%d ", i);

                        struct aes67_sdp_connection * con = aes67_sdp_get_connection(&sdp, i);

                        con->address.data[con->address.length] = '\0';
                        printf("%s:%d ", con->address.data, stream->port);

                        if (stream->mode == aes67_sdp_attr_mode_inactive){
                            printf("mode=inactive ");
                        } else if (stream->mode == aes67_sdp_attr_mode_recvonly){
                            printf("mode=recvonly ");
                        } else if (stream->mode == aes67_sdp_attr_mode_sendonly){
                            printf("mode=sendonly ");
                        } else if (stream->mode == aes67_sdp_attr_mode_sendrecv){
                            printf("mode=sendrecv ");
                        }

                        printf("nenc=%d clk-offset=%u", stream->nencodings, stream->mediaclock_offset);

                        if ( (stream->ptime.cap & AES67_SDP_CAP_SET) == AES67_SDP_CAP_SET){
                            printf(" ptime=%d", stream->ptime.msec);
                            if (stream->ptime.msec_frac){
                                printf(".%d", stream->ptime.msec_frac);
                            }
                        }

                        printf("\n");

                        for (int e = 0; e < sdp.streams.data[i].nencodings; e++){

                            printf("  enc#%d.%d ", i, e);

                            struct aes67_sdp_attr_encoding * enc = aes67_sdp_get_stream_encoding(&sdp, i, e);

                            if (enc->encoding == aes67_audio_encoding_L8){
                                printf("L8/");
                            } else if (enc->encoding == aes67_audio_encoding_L16){
                                printf("L16/");
                            } else if (enc->encoding == aes67_audio_encoding_L24){
                                printf("L24/");
                            } else if (enc->encoding == aes67_audio_encoding_L32){
                                printf("L32/");
                            } else {
                                printf("?/");
                            }

                            printf("%d/%d\n", enc->samplerate, enc->nchannels);
                        }

                        int np = aes67_sdp_get_ptp_count(&sdp, i);
                        for(int p = 0; p < np; p++){

                            printf("  ptp#%d.%d ", i, p);

                            struct aes67_ptp * ptp = &aes67_sdp_get_ptp(&sdp, i, p)->ptp;

                            if (ptp->type == aes67_ptp_type_IEEE1588_2002){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2002);
                            } else if (ptp->type == aes67_ptp_type_IEEE1588_2008){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2008);
                            } else if (ptp->type == aes67_ptp_type_IEEE1588_2019){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE1588_2019);
                            } else if (ptp->type == aes67_ptp_type_IEEE802AS_2011){
                                printf("%s ", AES67_PTP_TYPE_STR_IEEE802AS_2011);
                            }

                            printf("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X", ptp->gmid.u8[0], ptp->gmid.u8[1], ptp->gmid.u8[2], ptp->gmid.u8[3], ptp->gmid.u8[4], ptp->gmid.u8[5], ptp->gmid.u8[6], ptp->gmid.u8[7]);

                            if (ptp->type == aes67_ptp_type_IEEE1588_2008 || ptp->type == aes67_ptp_type_IEEE1588_2019){
                                printf(" %d", ptp->domain);
                            }

                            printf("\n");
                        }

                        printf("\n");
                    }
                }

            } else if (memcmp("o=", rbuf, 2) == 0){

                struct aes67_sdp_originator origin;

                r = aes67_sdp_origin_fromstr(&origin, rbuf, r);

                if (r == AES67_SDP_OK){

                }
            }

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


        } else { // r == 0 if stdin closed
            break;
        }
    }


    return 0;
}