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

static int sock_set_blocking(int sockfd, bool blocking){
    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    flags = (flags & ~O_NONBLOCK ) | (blocking ? 0 : O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, flags) == -1){
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static struct aes67_rtsp_srv_resource * rtsp_resource_by_uri(struct aes67_rtsp_srv * srv, const u8_t * uri, u8_t urilen)
{
    assert(srv);
    assert(uri);
    assert(urilen);

    struct aes67_rtsp_srv_resource * res = srv->first_res;

    while(res != NULL){

        if (res->urilen == urilen && aes67_memcmp(res->uri, uri, urilen) == 0){
            return res;
        }

        res = res->next;
    }

    return NULL;
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
    srv->blocking = true;
}

void aes67_rtsp_srv_deinit(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    aes67_rtsp_srv_stop(srv);

    while(srv->first_res){
        aes67_rtsp_srv_sdp_remove(srv, srv->first_res->sdpref);
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

    srv->listen_sockfd = socket (AF_INET, SOCK_STREAM, 0);

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


    if (sock_set_blocking(srv->listen_sockfd, srv->blocking)){
        fprintf(stderr, "Couldn't change non-/blocking\n");
        return EXIT_FAILURE;
    }

    srv->state = aes67_rtsp_srv_state_listening;

    return EXIT_SUCCESS;
}

void aes67_rtsp_srv_stop(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    if (srv->listen_sockfd != -1){
        sock_set_blocking(srv->listen_sockfd, true);
        close(srv->listen_sockfd);
        srv->listen_sockfd = -1;
    }

    if (srv->client_sockfd != -1){
        sock_set_blocking(srv->client_sockfd, true);
        close(srv->client_sockfd);
        srv->client_sockfd = -1;
    }

}


void aes67_rtsp_srv_blocking(struct aes67_rtsp_srv * srv, bool blocking)
{
    assert(srv);

    if (srv->blocking == blocking){
        return;
    }
    srv->blocking = blocking;

    if (srv->listen_sockfd != -1){
        sock_set_blocking(srv->listen_sockfd, blocking);
    }
    if (srv->client_sockfd != -1){
        sock_set_blocking(srv->client_sockfd, blocking);
    }
}

void aes67_rtsp_srv_process(struct aes67_rtsp_srv * srv)
{
    assert(srv);

    if (srv->state == aes67_rtsp_srv_state_init){
        return;
    }
    if (srv->state == aes67_rtsp_srv_state_listening) {

        socklen_t socklen;
        if ((srv->client_sockfd = accept(srv->listen_sockfd, (struct sockaddr *) &srv->client_sockfd,
                                         &socklen)) != -1) {

            srv->state = aes67_rtsp_srv_state_receiving;
            srv->req.proto = aes67_rtsp_srv_proto_undefined;
            srv->req.data_len = 0;
            srv->req.header_len = 0;
            srv->req.content_length = 0;
            srv->req.CR = 0;
//            srv->res.status_code = 0;

            sock_set_blocking(srv->client_sockfd, srv->blocking);

            u8_t ipstr[AES67_NET_ADDR_STR_MAX];
            u8_t iplen = aes67_net_ip2str(ipstr, aes67_net_ipver_4, (u8_t*)&srv->client_addr.sin_addr.s_addr, ntohs(srv->client_addr.sin_port));
            ipstr[iplen] = '\0';

            fprintf(stderr, "RTSP SRV connection from %s\n", ipstr);
        }
        return;
    }

    //sanity check
    if (srv->client_sockfd == -1){
        srv->state = aes67_rtsp_srv_state_listening;
        return;
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
                        if (srv->req.data_len < 15){
                            close(srv->client_sockfd);
                            srv->client_sockfd = -1;
                            srv->state = aes67_rtsp_srv_state_listening;
                            return;
                        }
                        // check if using carriage return
                        if (srv->req.data[srv->req.data_len - 2] == '\r'){
                            CR = srv->req.CR = 1;
                        }

                        u8_t * s = &srv->req.data[srv->req.data_len - CR - sizeof("HTTP/1.0")];

//                        printf("[%s] [%s]\n", srv->req.data, s);

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

                        // without proper validation
                        srv->req.version.major = s[5] - '0';
                        srv->req.version.minor = s[7] - '0';

                        s = srv->req.data;

                        srv->req.data[srv->req.data_len] = '\0';
                        fprintf(stderr, "REQUEST %s", s);

                        if (srv->req.proto == aes67_rtsp_srv_proto_rtsp &&
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
                            srv->req.uri = &s[9];
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
                            srv->req.uri = &s[8];
                        }
                        else if (srv->req.proto == aes67_rtsp_srv_proto_http &&
                                 s[0] == 'G' &&
                                 s[1] == 'E' &&
                                 s[2] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_get;
                            srv->req.uri = &s[4];
                        }
                        else if (srv->req.proto == aes67_rtsp_srv_proto_http &&
                                 s[0] == 'P' &&
                                 s[1] == 'O' &&
                                 s[2] == 'S' &&
                                 s[3] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_post;
                            srv->req.uri = &s[5];
                        }
                        else if (srv->req.proto == aes67_rtsp_srv_proto_http &&
                                 s[0] == 'P' &&
                                 s[1] == 'U' &&
                                 s[2] == 'T'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_put;
                            srv->req.uri = &s[4];
                        }
                        else if (srv->req.proto == aes67_rtsp_srv_proto_http &&
                                 s[0] == 'D' &&
                                 s[1] == 'E' &&
                                 s[2] == 'L' &&
                                 s[3] == 'E' &&
                                 s[4] == 'T' &&
                                 s[5] == 'E'
                                ) {
                            srv->req.method = aes67_rtsp_srv_method_delete;
                            srv->req.uri = &s[7];
                        }
                        else {
                            // method not supported/recognized, terminate without response
                            close(srv->client_sockfd);
                            srv->client_sockfd = -1;
                            srv->state = aes67_rtsp_srv_state_listening;
                            fprintf(stderr, "method not recognized\n");
                            return;
                        }

                        // "RTSP/1.0" - "METHOD .."
                        srv->req.urilen = &srv->req.data[srv->req.data_len - CR - sizeof(" HTTP/1.0")] - srv->req.uri;

                        srv->req.uri[srv->req.urilen] = '\0';
//                        printf("uri[%d] = [%s]\n", srv->req.urilen, srv->req.uri);
                        // if  rtsp, discard scheme and host
                        if (srv->req.proto == aes67_rtsp_srv_proto_rtsp){

                            // basic validation
                            if (srv->req.uri[0] != 'r' ||
                                srv->req.uri[1] != 't' ||
                                srv->req.uri[2] != 's' ||
                                srv->req.uri[3] != 'p' ||
                                srv->req.uri[4] != ':' ||
                                srv->req.uri[5] != '/' ||
                                srv->req.uri[6] != '/'
                                    ){
                                close(srv->client_sockfd);
                                srv->client_sockfd = -1;
                                srv->state = aes67_rtsp_srv_state_listening;
                                return;
                            }
                            srv->req.uri += 7;
                            srv->req.urilen -= 7;

                            u8_t * delim = aes67_memchr(srv->req.uri, '/', srv->req.urilen);
                            if (delim == NULL){
                                close(srv->client_sockfd);
                                srv->client_sockfd = -1;
                                srv->state = aes67_rtsp_srv_state_listening;
                                return;
                            }

                            srv->req.urilen -= delim - srv->req.uri;
                            srv->req.uri = delim;
                        }
                        else if (srv->req.proto == aes67_rtsp_srv_proto_http){
                            // sanity check
                            if (srv->req.uri[0] != '/'){
                                close(srv->client_sockfd);
                                srv->client_sockfd = -1;
                                srv->state = aes67_rtsp_srv_state_listening;
                                return;
                            }
                        }
//                        printf("uri[%d] = [%s]\n", srv->req.urilen, srv->req.uri);

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
//                    printf("closed!\n");
                    return;
                } else if (r == 1) {
                    srv->req.data[srv->req.data_len++] = c;
                    srv->req.llen++;

                    // if EOL
                    if (c == '\n') {

                        // end of header? ([CR]NL)
                        if (srv->req.llen == 1 + CR && (!CR || srv->req.line[0] == '\r') && srv->req.line[CR] == '\n') {
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
                    fprintf(stderr, "overflow\n");
                    return;
                }
            }
        } // header

        // read body (if total data is less than header and expected content length..)
        u16_t missing = srv->req.content_length - (srv->req.data_len - srv->req.header_len);
        if (missing > 0) {

            // boundary check
            if (srv->req.data_len + missing >= AES67_RTSP_SRV_RXBUFSIZE){
                close(srv->client_sockfd);
                srv->client_sockfd = -1;
                srv->state = aes67_rtsp_srv_state_listening;
                fprintf(stderr, "would overflow (has %d, hdr %d, content %d, missing %d)\n", srv->req.data_len, srv->req.header_len, srv->req.content_length, missing);
                return;
            }

            r = read(srv->client_sockfd, &srv->req.data[srv->req.data_len], missing);

            if (r == -1){ // timeout
                return;
            } else if (r == 0) { // closed prematurely
                close(srv->client_sockfd);
                srv->client_sockfd = -1;
                srv->state = aes67_rtsp_srv_state_listening;
                return;
            } else if (r > 0) {
                srv->req.data_len += r;
                missing -= r;
            }
        }

        if (missing == 0){
            srv->state = aes67_rtsp_srv_state_processing;
        }
    } // state == aes67_rtsp_srv_state_receiving


    if (srv->state == aes67_rtsp_srv_state_processing){
        if (srv->req.proto == aes67_rtsp_srv_proto_rtsp){
//            fprintf(stderr, "is rtsp\n");

            u16_t status_code = AES67_RTSP_STATUS_INTERNAL_ERROR;
            struct aes67_rtsp_srv_resource * res = NULL;

            switch (srv->req.method){

                case aes67_rtsp_srv_method_options:
                    status_code = AES67_RTSP_STATUS_OK;
                    break;

                case aes67_rtsp_srv_method_describe:
                    res = rtsp_resource_by_uri(srv, srv->req.uri, srv->req.urilen);
                    if (res == NULL){
                        status_code  = AES67_RTSP_STATUS_NOT_FOUND;
                    } else {
                        status_code = AES67_RTSP_STATUS_OK;
                    }
                    break;

                default:
                    // well, in principle this is what would be the answer (not necessarily RFC conform)
                    // but this case should be caught earlier on and execution should never reach here
                    status_code = AES67_RTSP_STATUS_NOT_IMPLEMENTED;
            }


            u8_t * d = srv->res.data;
            u16_t l = 0;

            d[0] = 'R';
            d[1] = 'T';
            d[2] = 'S';
            d[3] = 'P';
            d[4] = '/';
            d[5] = '0' + srv->req.version.major;
            d[6] = '.';
            d[7] = '0' + srv->req.version.minor;
            d[8] = ' ';
            l = 9;

            l += aes67_itoa(status_code, d + l , 10);

            d[l++] = ' ';

            switch(status_code){
                case AES67_RTSP_STATUS_OK:
                    d[l++] = 'O';
                    d[l++] = 'K';
                    break;
                case AES67_RTSP_STATUS_NOT_FOUND:
                    d[l++] = 'N';
                    d[l++] = 'O';
                    d[l++] = 'T';
                    d[l++] = ' ';
                    d[l++] = 'F';
                    d[l++] = 'O';
                    d[l++] = 'U';
                    d[l++] = 'N';
                    d[l++] = 'D';
                    break;
                case AES67_RTSP_STATUS_NOT_IMPLEMENTED:
                    d[l++] = 'N';
                    d[l++] = 'O';
                    d[l++] = 'T';
                    d[l++] = ' ';
                    d[l++] = 'I';
                    d[l++] = 'M';
                    d[l++] = 'P';
                    d[l++] = 'L';
                    d[l++] = 'E';
                    d[l++] = 'M';
                    d[l++] = 'T';
                    d[l++] = 'E';
                    d[l++] = 'D';
                    break;
                default:
                    d[l++] = '?';
            }

            d[l++] = '\r';
            d[l++] = '\n';

            d[l++] = 'C';
            d[l++] = 'S';
            d[l++] = 'e';
            d[l++] = 'q';
            d[l++] = ':';
            d[l++] = ' ';
            l += aes67_itoa(srv->req.cseq, d + l, 10);
            d[l++] = '\r';
            d[l++] = '\n';

            switch (srv->req.method){

                case aes67_rtsp_srv_method_options:
                    aes67_memcpy(d + l, "Public: DESCRIBE\r\n\r\n", sizeof("Public: DESCRIBE\r\n\r\n")-1);
                    l += sizeof("Public: DESCRIBE\r\n\r\n")-1;
                    break;

                case aes67_rtsp_srv_method_describe:
                    if (res){
                        l += aes67_rtsp_srv_sdp_getter(srv, res->sdpref, d + l, AES67_RTSP_SRV_TXBUFSIZE - l);
                    } else {
                        // add end of header / empty line
                        d[l++] = '\r';
                        d[l++] = '\n';
                    }
                    break;

                default:
                    // add end of header / empty line
                    d[l++] = '\r';
                    d[l++] = '\n';
                    break;
            }

            srv->res.len = l;
            srv->res.sent = 0;

            srv->state = aes67_rtsp_srv_state_sending;

        } // proto == aes67_rtsp_srv_proto_rtsp
        else if (srv->req.proto == aes67_rtsp_srv_proto_http){

            srv->res.more = false;
            srv->res.len = 0;
            srv->res.sent = 0;
            srv->res.response_state = NULL;

            // NULL-terminate just to make simpler for processor (note, we're altering the buffer hereby, obviously..)
//            srv->req.uri[srv->req.urilen] = '\0';

            aes67_rtsp_srv_http_handler(srv, srv->req.method, (char*)srv->req.uri, srv->req.urilen, srv->res.data, &srv->res.len, AES67_RTSP_SRV_TXBUFSIZE, &srv->res.more, &srv->res.response_state);

            if (srv->res.len == 0){
//                fprintf(stderr, "no http data, closing\n");

                close(srv->client_sockfd);
                srv->client_sockfd = -1;
                srv->state = aes67_rtsp_srv_state_listening;
            } else {
                srv->state = aes67_rtsp_srv_state_sending;
            }

        } // proto == aes67_rtsp_srv_proto_http
    } // state == aes67_rtsp_srv_state_processing

    if (srv->state == aes67_rtsp_srv_state_sending){

        if (srv->res.sent < srv->res.len){
//            fprintf(stderr, "Sending %d bytes..\n", srv->res.len - srv->res.sent);

            int r = write(srv->client_sockfd, srv->res.data + srv->res.sent, srv->res.len - srv->res.sent);

            if (r > 0){
                srv->res.sent += r;

                // just some sanity check because I'm not sure how this behaves in real life
                assert(r == srv->res.len);

                srv->res.len = 0;

                // if http with more data to send, call handler again
                if (srv->req.proto == aes67_rtsp_srv_proto_http && srv->res.more) {
                    aes67_rtsp_srv_http_handler(srv, srv->req.method, (char *) srv->req.uri, srv->req.urilen, srv->res.data,
                                                &srv->res.len, AES67_RTSP_SRV_TXBUFSIZE, &srv->res.more,
                                                &srv->res.response_state);
                }

                // no more data, terminate
                if (srv->res.len == 0){

                    close(srv->client_sockfd);
                    srv->client_sockfd = -1;

                    srv->state = aes67_rtsp_srv_state_listening;
                }
            }
            // if socket closed
            else if (r == 0){

                if (srv->req.proto == aes67_rtsp_srv_proto_http){
                    aes67_rtsp_srv_http_handler(srv, aes67_rtsp_srv_method_undefined, NULL, 0, NULL, NULL, 0, &srv->res.more, &srv->res.response_state);
                }

                close(srv->client_sockfd);
                srv->client_sockfd = -1;

                srv->state = aes67_rtsp_srv_state_listening;
            }


        }

    } //state == aes67_rtsp_srv_state_sending
}

WEAK_FUN u16_t aes67_rtsp_srv_sdp_getter(struct aes67_rtsp_srv * srv, void * sdpref, u8_t * buf, u16_t maxlen)
{
    assert(false);
}

WEAK_FUN void aes67_rtsp_srv_http_handler(struct aes67_rtsp_srv * srv, const enum aes67_rtsp_srv_method method, char * uri, u8_t urilen, u8_t * buf, u16_t * len, u16_t maxlen, bool * more, void ** response_state)
{
    assert(false);
}


struct aes67_rtsp_srv_resource * aes67_rtsp_srv_sdp_add(struct aes67_rtsp_srv * srv, const char * uri, const u8_t urilen, void * sdpref)
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