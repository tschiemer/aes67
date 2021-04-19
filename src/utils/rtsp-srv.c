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

#include "aes67/utils/rtsp-srv.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <search.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

static int sock_nonblock(int sockfd){
    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1){
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void aes67_rtsp_srv_init(struct aes67_rtsp_srv * srv, bool http_enabled, void * user_data)
{
    assert(srv);

    srv->state = aes67_rtsp_srv_state_init;
    srv->first_res = NULL;

    srv->http_enabled = http_enabled;
    srv->user_data = user_data;

    srv->listen_sockfd = -1;
    srv->client_sockfd = -1;
}

void aes67_rtsp_srv_deinit(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    aes67_rtsp_srv_stop(srv);

    while(srv->first_res){
        aes67_rtsp_srv_sdp_remove(srv, srv->first_res);
    }

    srv->state = aes67_rtsp_srv_state_init;
}

int aes67_rtsp_srv_start(struct aes67_rtsp_srv * srv, const enum aes67_net_ipver ipver, const u8_t *ip, u16_t port)
{
    assert(srv);
    assert(ipver != aes67_net_ipver_4);
//    assert(ip);
    assert(port);

    aes67_rtsp_srv_stop(srv);

    srv->listen_sockfd = socket (AF_UNIX, SOCK_STREAM, 0);

    if (srv->listen_sockfd < 0){
        perror ("socket()");
        return EXIT_FAILURE;
    }

    memset(&srv->listen_addr, 0, sizeof(struct sockaddr_in));

    srv->listen_addr.sin_family = AF_INET;
    srv->listen_addr.sin_port = htons(port);
    if (ip){
        srv->listen_addr.sin_addr.s_addr = *(uint32_t*)ip;
    } else {
        srv->listen_addr.sin_addr.s_addr = INADDR_ANY;
    }


    if (bind (srv->listen_sockfd, (struct sockaddr *) &srv->listen_addr, sizeof(struct sockaddr_in)) < 0){
        close(srv->listen_sockfd);
        srv->listen_sockfd = -1;
        perror ("bind()");
        return EXIT_FAILURE;
    }


    if (listen(srv->listen_sockfd, AES67_RTSPSRV_LISTEN_BACKLOG) == -1){
        close(srv->listen_sockfd);
        srv->listen_sockfd = -1;
        perror ("listen()");
        return EXIT_FAILURE;
    }


    if (sock_nonblock(srv->listen_sockfd)){
        fprintf(stderr, "Couldn't change non-/blocking\n");
        return EXIT_FAILURE;
    }

    srv->state = aes67_rtsp_srv_state_listening;

    return EXIT_SUCCESS;
}

void aes67_rtsp_srv_stop(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    if (srv->client_sockfd != -1){
        close(srv->client_sockfd);
        srv->client_sockfd = -1;
    }

    if (srv->listen_sockfd != -1){
        close(srv->listen_sockfd);
        srv->listen_sockfd = -1;
    }
}

void aes67_rtsp_srv_process(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    if (srv->state == aes67_rtsp_srv_state_init){
        return;
    }
    if (srv->state == aes67_rtsp_srv_state_listening) {

        if ((srv->client_sockfd = accept(srv->listen_sockfd, (struct sockaddr *) &srv->client_sockfd,
                                         sizeof(srv->client_sockfd))) != -1) {

            srv->state = aes67_rtsp_srv_state_receiving;
            srv->req.proto = aes67_rtsp_srv_proto_undefined;
            srv->req.data_len = 0;
            srv->req.header_len = 0;
            srv->req.content_length = 0;
            srv->req.CR = 0;
            srv->res.status_code = 0;

            u8_t ipstr[AES67_NET_ADDR_STR_MAX];
            u8_t iplen = aes67_net_ip2str(ipstr, aes67_net_ipver_4, srv->client_addr.sin_addr.s_addr, ntohs(srv->client_addr.sin_port));
            ipstr[iplen] = '\0';

            fprintf(stderr, "RTSP SRV connection from %s\n", ipstr);
        }
    }
    if (srv->state == aes67_rtsp_srv_state_receiving){

        ssize_t r; // read result
        u8_t c; // read buf
        u16_t rl; // readlen
        int CR = srv->req.CR;

        // read first line

        if (srv->req.proto == aes67_rtsp_srv_proto_undefined){
            // read only a meaningful max
            while(srv->req.data_len < 256 ){

                r = read(srv->client_sockfd, &c, 1);

                if (r == -1){ // timeout
                    return;
                } else if (r == 0) { // closed
                    close(srv->client_sockfd);
                    srv->client_sockfd = -1;
                    srv->state = aes67_rtsp_srv_state_listening;
                    return;
                } else if (r == 1) {
                    srv->req.data[srv->req.data_len++] = c;

                    // if EOL
                    if (c == '\n'){

                        // basic sanity check
                        if (srv->req.data_len < 32){
                            close(srv->client_sockfd);
                            srv->client_sockfd = -1;
                            srv->state = aes67_rtsp_srv_state_listening;
                            return;
                        }
                        // check if using carriage return
                        if (srv->req.data[srv->req.data_len - 2] == '\r'){
                            CR = srv->req.CR = 1;
                        }

                        u8_t * s = srv->req.data_len - CR - sizeof("HTTP/1.0");

                        if (s[0] == 'H' &&
                            s[1] == 'T' &&
                            s[2] == 'T' &&
                            s[3] == 'P' &&
                            s[4] == '/' &&
                            s[6] == '.'
                        ){

                            if (!srv->http_enabled){
                                close(srv->client_sockfd);
                                srv->client_sockfd = -1;
                                srv->state = aes67_rtsp_srv_state_listening;
                                return;
                            }

                            srv->req.proto = aes67_rtsp_srv_proto_http;
                        }
                        else if (s[0] == 'R' &&
                                 s[1] == 'T' &&
                                 s[2] == 'S' &&
                                 s[3] == 'P' &&
                                 s[4] == '/' &&
                                 s[6] == '.'
                                ){

                            srv->req.proto = aes67_rtsp_srv_proto_rtsp;
                        }
                        // client error, just terminate connection without response
                        else {
                            close(srv->client_sockfd);
                            srv->client_sockfd = -1;
                            srv->state = aes67_rtsp_srv_state_listening;
                            return;
                        }

                        srv->req.version.major = s[5] - '0';
                        srv->req.version.minor = s[7] - '0';

                        s = srv->req.data;

                        if (srv->req.proto = aes67_rtsp_srv_proto_rtsp &&
                            s[0] == 'D' &&
                            s[1] == 'E' &&
                            s[2] == 'S' &&
                            s[3] == 'C' &&
                            s[4] == 'R' &&
                            s[5] == 'I' &&
                            s[6] == 'B' &&
                            s[7] == 'E'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_describe;
                        }
                        else if (s[0] == 'O' && // supported by both rtsp and http
                                 s[1] == 'P' &&
                                 s[2] == 'T' &&
                                 s[3] == 'I' &&
                                 s[4] == 'O' &&
                                 s[5] == 'N' &&
                                 s[6] == 'S'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_options;
                        }
                        else if (srv->req.proto = aes67_rtsp_srv_proto_http &&
                                 s[0] == 'G' &&
                                 s[1] == 'E' &&
                                 s[2] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_get;
                        }
                        else if (srv->req.proto = aes67_rtsp_srv_proto_http &&
                                 s[0] == 'P' &&
                                 s[1] == 'O' &&
                                 s[2] == 'S' &&
                                 s[3] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_post;
                        }
                        else if (srv->req.proto = aes67_rtsp_srv_proto_http &&
                                 s[0] == 'P' &&
                                 s[1] == 'U' &&
                                 s[2] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_put;
                        }
                        else if (srv->req.proto = aes67_rtsp_srv_proto_http &&
                                 s[0] == 'D' &&
                                 s[1] == 'E' &&
                                 s[2] == 'L' &&
                                 s[3] == 'E' &&
                                 s[4] == 'T' &&
                                 s[5] == 'E'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_delete;
                        }
                        else {
                            // method not supported/recognized, terminate without response
                            close(srv->client_sockfd);
                            srv->client_sockfd = -1;
                            srv->state = aes67_rtsp_srv_state_listening;
                            return;
                        }


                        // set line start
                        srv->req.line = &srv->req.data[srv->req.data_len];
                        srv->req.llen = 0;

                        break;
                    }
                }
            }
            // fail if using too much memory
            if (srv->req.data_len >= 256){
                close(srv->client_sockfd);
                srv->client_sockfd = -1;
                srv->state = aes67_rtsp_srv_state_listening;
                return;
            }
        } // read first line


        // read complete header
        if (srv->req.header_len == 0) {

            while (srv->req.data_len < AES67_RTSP_SRV_RXBUFSIZE) {

                r = read(srv->client_sockfd, &c, 1);

                if (r == -1) { // timeout
                    return;
                } else if (r == 0) { // closed
                    close(srv->client_sockfd);
                    srv->client_sockfd = -1;
                    srv->state = aes67_rtsp_srv_state_listening;
                    printf("closed!\n");
                    return;
                } else if (r == 1) {
                    srv->req.data[srv->req.data_len++] = c;
                    srv->req.llen++;

                    // if EOL
                    if (c == '\n') {

                        // end of header? ([CR]NL)
                        if (srv->req.llen == 1 + CR && (!CR || srv->req.line[0] == '\r') && srv->req.line[1] == '\n') {
                            srv->req.header_len = srv->req.data_len;
                            // break to start reading body
                            break;
                        }


                        // expect a header line: "<attr>: <value>\r\n"
                        u8_t *delim = aes67_memchr(srv->req.line, ':', srv->req.line - &srv->req.data[srv->req.data_len]);
                        if (delim != NULL) {

//                            res->buf[res->buflen] = '\0';
//                            printf("line %d [%s]\n", res->llen, res->line);
//                            printf("%d\n", aes67_ischar_insensitive(res->line[8], 'l'));

                            // verify cseq?
                            if (delim - srv->req.line == sizeof("CSeq") - 1 &&
                                srv->req.llen >= sizeof("CSeq: 1") + CR &&
                                aes67_ischar_insensitive(srv->req.line[0], 'c') &&
                                aes67_ischar_insensitive(srv->req.line[1], 's') &&
                                srv->req.line[2] == 'e' &&
                                srv->req.line[3] == 'q'
                                    ) {
                                srv->req.cseq = aes67_atoi(delim + 2, srv->req.llen - sizeof("cseq: ") - CR, 10, &rl);
                            }

                            // look for content-length field
                            if (delim - srv->req.line == sizeof("Content-Length") - 1 &&
                                srv->req.llen >= sizeof("Content-Length: 1") + CR &&
                                aes67_ischar_insensitive(srv->req.line[0], 'c') &&
                                srv->req.line[1] == 'o' &&
                                srv->req.line[2] == 'n' &&
                                srv->req.line[3] == 't' &&
                                srv->req.line[4] == 'e' &&
                                srv->req.line[5] == 'n' &&
                                srv->req.line[6] == 't' &&
                                srv->req.line[7] == '-' &&
                                aes67_ischar_insensitive(srv->req.line[8], 'l') &&
                                srv->req.line[9] == 'e' &&
                                srv->req.line[10] == 'n' &&
                                srv->req.line[11] == 'g' &&
                                srv->req.line[12] == 't' &&
                                srv->req.line[13] == 'h'
                                    ) {
                                srv->req.content_length = aes67_atoi(delim + 2, srv->req.llen - sizeof("content-length: \r"), 10,
                                                                     &rl);
                            }

                        }

                        // reset line start
                        srv->req.line = &srv->req.data[srv->req.data_len];
                        srv->req.llen = 0;
                    }
                }
                // fail if using too much memory
                if (srv->req.data_len >= AES67_RTSP_SRV_RXBUFSIZE) {
                    close(srv->client_sockfd);
                    srv->client_sockfd = -1;
                    srv->state = aes67_rtsp_srv_state_listening;
                    printf("overflow\n");
                    return;
                }
            }
        } // header

        // read body
    }
}

WEAK_FUN void aes67_rtsp_srv_sdp_getter(struct aes67_rtsp_srv * srv, void * sdpref, u8_t * buf, u16_t * len, u16_t maxlen)
{
    assert(false);
}

WEAK_FUN void aes67_rtsp_srv_http_handler(struct aes67_rtsp_srv * srv, const enum aes67_rtsp_srv_method method, const char * uri, const u8_t urilen, u8_t * buf, u16_t * len, u16_t maxlen, void * response_data)
{

}


struct aes67_rtsp_srv_resource * aes67_rtsp_srv_sdp_add(struct aes67_rtsp_srv * srv, const char * uri, const u8_t urilen, const void * sdpref)
{
    assert(srv);
    assert(uri);
    assert(sdpref);

    struct aes67_rtsp_srv_resource * res = malloc(sizeof(struct aes67_rtsp_srv_resource));

    aes67_memcpy(res->uri, uri, urilen);
    res->uri[urilen] = '\0';
    res->urilen = urilen;

    res->sdpref = sdpref;

    res->next = srv->first_res;
    srv->first_res = res;

    return res;
}

void aes67_rtsp_srv_sdp_remove(struct aes67_rtsp_srv * srv, void * sdpref)
{
    assert(srv);
    assert(sdpref);

    struct aes67_rtsp_srv_resource * res = srv->first_res;

    // locate resource
    while (res && res->sdpref != sdpref){
        res = res->next;
    }

    // safety check
    if (!res){
        return;
    }

    // now free resource
    if (srv->first_res == res){
        srv->first_res = res->next;
    } else {
        struct aes67_rtsp_srv_resource * before = srv->first_res;
        while(before != NULL){

            if (before->next == res){
                before->next = res->next;
                break;
            }

            before = before->next;
        }
    }

    free(res);
}