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

#include "aes67/utils/rtsp.h"

//#include "aes67/debug.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <search.h>
#include <errno.h>
#include <fcntl.h>

void aes67_rtsp_dsc_init(struct aes67_rtsp_dsc_res_st * res, bool blocking)
{
    assert(res != NULL);

    res->state = aes67_rtsp_dsc_state_bored;
    res->sockfd = -1;
    res->blocking = blocking;
}

void aes67_rtsp_dsc_deinit(struct aes67_rtsp_dsc_res_st * res)
{
    aes67_rtsp_dsc_stop(res);
}

int aes67_rtsp_dsc_start(
        struct aes67_rtsp_dsc_res_st * res,
        const enum aes67_net_ipver ipver,
        const u8_t *ip,
        const u16_t port,
        const char * encoded_uri
)
{
    assert(res != NULL);
    assert(AES67_NET_IPVER_ISVALID(ipver));
    assert(ip != NULL);
    assert(encoded_uri != NULL);

    // can not start when an operation is pending
    if (res->state == aes67_rtsp_dsc_state_querying || res->state == aes67_rtsp_dsc_state_awaiting_response){
        return EXIT_FAILURE;
    }
    // mark as busy
    res->state = aes67_rtsp_dsc_state_querying;

    struct sockaddr_storage server;

    if (ipver == aes67_net_ipver_4){
        ((struct sockaddr_in *)&server)->sin_len = sizeof(struct sockaddr_in);
        ((struct sockaddr_in *)&server)->sin_family = AF_INET;
        ((struct sockaddr_in *)&server)->sin_port = htons(port);
        ((struct sockaddr_in *)&server)->sin_addr.s_addr = *(u32_t *) ip;
//        server.s
    } else if (ipver == aes67_net_ipver_6){
        ((struct sockaddr_in6 *)&server)->sin6_len = sizeof(struct sockaddr_in6);
        ((struct sockaddr_in6 *)&server)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&server)->sin6_port = htons(port);
        memcpy(&((struct sockaddr_in6 *)&server)->sin6_addr, ip, AES67_NET_IPVER_SIZE(ipver));
    }

    res->sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (res->sockfd == -1) {
        res->resultcode = errno;
        res->state = aes67_rtsp_dsc_state_done;
        return EXIT_FAILURE;
    }

    if (connect(res->sockfd, (struct sockaddr *) &server, server.ss_len) < 0) {
        res->resultcode = errno;
        res->state = aes67_rtsp_dsc_state_done;
        return EXIT_FAILURE;
    }

    if (!res->blocking){
        // set non-blocking
        int flags = fcntl(res->sockfd, F_GETFL, 0);
        if (fcntl(res->sockfd, F_SETFL, flags | O_NONBLOCK) == -1){
            fprintf(stderr, "couldn't non-block\n");
            return EXIT_FAILURE;
        }
    }

    size_t len = aes67_strncpy((char*)res->buf, "DESCRIBE rtsp://", AES67_RTSP_BUFSIZE);

    len += aes67_net_ip2str(&res->buf[len], (enum aes67_net_ipver)ipver, (u8_t*)ip, (u16_t)port);

    len += aes67_strncpy((char*)&res->buf[len], encoded_uri, AES67_RTSP_BUFSIZE - len);

    len += aes67_strncpy((char*)&res->buf[len], " RTSP/1.0\r\n"
                                         "CSeq: 1\r\n"
                                         "Accept: application/sdp\r\n"
                                         "\r\n", AES67_RTSP_BUFSIZE - len);

    res->buflen = len;


    // writing to the socket could also be done in the process function (this here is, in principle, a blocking call..)
    if (write(res->sockfd, res->buf, res->buflen) == -1) {
        close(res->sockfd);
        res->resultcode = errno;
        res->state = aes67_rtsp_dsc_state_done;
        return EXIT_FAILURE;
    }

    res->buflen = 0;
    res->resultcode = 0;
    res->hdrlen = 0;
    res->contentlen = 0;

    res->state = aes67_rtsp_dsc_state_awaiting_response;

    return EXIT_SUCCESS;
}

void aes67_rtsp_dsc_stop(struct aes67_rtsp_dsc_res_st * res)
{
    assert(res != NULL);

    if (res->sockfd != -1){
        close(res->sockfd);
        res->sockfd = -1;
    }

    res->state = aes67_rtsp_dsc_state_bored;
}

void aes67_rtsp_dsc_process(struct aes67_rtsp_dsc_res_st * res)
{
    assert(res != NULL);

    // basic state guards
    if (res->state == aes67_rtsp_dsc_state_bored){
        // do nothing
        return;
    }
    if (res->state == aes67_rtsp_dsc_state_done){
        // do nothing
        return;
    }
    if (res->state == aes67_rtsp_dsc_state_querying){
        // should only reach here on here or if multithreading
        return;
    }
    if (res->state == aes67_rtsp_dsc_state_awaiting_response){
        ssize_t r; // read result
        u8_t c; // read buf
        u16_t rl; // readlen

        // read first line
        if (res->resultcode == 0){
            // read only a meaningful max
            while( res->buflen < 256 ){

                r = read(res->sockfd, &c, 1);

                if (r == -1){ // timeout
                    return;
                } else if (r == 0) { // closed
                    close(res->sockfd);
                    res->sockfd = -1;
                    res->state = aes67_rtsp_dsc_state_done;
                    return;
                } else if (r == 1) {
                    res->buf[res->buflen++] = c;

                    // if EOL
                    if (c == '\n'){
                        // protocol check
                        if (res->buf[0] != 'R' ||
                            res->buf[1] != 'T' ||
                            res->buf[2] != 'S' ||
                            res->buf[3] != 'P' ||
                            res->buf[4] != '/' ||
                            (res->buf[5] != '1' && res->buf[5] != '2') ||
                            res->buf[6] != '.' ||
                            res->buf[7] != '0' ||
                            res->buf[8] != ' ')
                        {
                            close(res->sockfd);
                            res->sockfd = -1;
                            res->state = aes67_rtsp_dsc_state_done;
                            return;
                        }

                        res->resultcode = aes67_atoi(&res->buf[9], 3, 10, &rl);
                        if (res->resultcode == 0){
                            close(res->sockfd);
                            res->sockfd = -1;
                            res->state = aes67_rtsp_dsc_state_done;
                            return;
                        }

                        // set line start
                        res->line = &res->buf[res->buflen];
                        res->llen = 0;

                        break;
                    }
                }
            }
            // fail if using too much memory
            if (res->buflen >= 256){
                close(res->sockfd);
                res->sockfd = -1;
                res->contentlen = 0;
                res->state = aes67_rtsp_dsc_state_done;
                return;
            }
        } // read first line

        // read complete header
        if (res->hdrlen == 0){

            while( res->buflen < AES67_RTSP_BUFSIZE ){

                r = read(res->sockfd, &c, 1);

                if (r == -1){ // timeout
                    return;
                } else if (r == 0) { // closed
                    close(res->sockfd);
                    res->sockfd = -1;
                    res->state = aes67_rtsp_dsc_state_done;
                    printf("closed!\n");
                    return;
                } else if (r == 1) {
                    res->buf[res->buflen++] = c;
                    res->llen++;

                    // if EOL
                    if (c == '\n'){

                        // end of header?
                        if (res->llen == 2 && res->line[0] == '\r' && res->line[1] == '\n'){
                            res->hdrlen = res->buflen;
                            // break to start reading body
                            break;
                        }


                        // expect a header line: "<attr>: <value>\r\n"
                        u8_t * delim = aes67_memchr(res->line, ':', res->line - &res->buf[res->buflen]);
                        if (delim != NULL){

//                            res->buf[res->buflen] = '\0';
//                            printf("line %d [%s]\n", res->llen, res->line);
//                            printf("%d\n", aes67_ischar_insensitive(res->line[8], 'l'));

                            // verify cseq?
                            if (delim - res->line == sizeof("CSeq")-1 &&
                                res->llen >= sizeof("CSeq: 1\r") &&
                                aes67_ischar_insensitive(res->line[0], 'c') &&
                                aes67_ischar_insensitive(res->line[1], 's') &&
                                res->line[2] == 'e' &&
                                res->line[3] == 'q'
                            ){
//                                s32_t cseq = aes67_atoi(delim + 2, res->llen - sizeof("cseq: \r"), 10, &rl);
                            }

                            // look for content-length field
                            if (delim - res->line == sizeof("Content-Length")-1 &&
                                res->llen >= sizeof("Content-Length: 1\r") &&
                                aes67_ischar_insensitive(res->line[0], 'c') &&
                                res->line[1] == 'o' &&
                                res->line[2] == 'n' &&
                                res->line[3] == 't' &&
                                res->line[4] == 'e' &&
                                res->line[5] == 'n' &&
                                res->line[6] == 't' &&
                                res->line[7] == '-' &&
                                aes67_ischar_insensitive(res->line[8], 'l') &&
                                res->line[9] == 'e' &&
                                res->line[10] == 'n' &&
                                res->line[11] == 'g' &&
                                res->line[12] == 't' &&
                                res->line[13] == 'h'
                            ){
                                res->contentlen = aes67_atoi(delim+2, res->llen - sizeof("content-length: \r"), 10, &rl);
                            }

                        }

                        // reset line start
                        res->line = &res->buf[res->buflen];
                        res->llen = 0;
                    }
                }
                // fail if using too much memory
                if (res->buflen >= AES67_RTSP_BUFSIZE){
                    close(res->sockfd);
                    res->sockfd = -1;
                    res->contentlen = 0;
                    res->state = aes67_rtsp_dsc_state_done;
                    printf("overflow\n");
                    return;
                }
            } // header

            // require content length to be set
            if (res->contentlen == 0) {
                close(res->sockfd);
                res->sockfd = -1;
                res->state = aes67_rtsp_dsc_state_done;
                printf("no content length\n");
                return;
            }

            // sanity check
            if (res->hdrlen + res->contentlen > AES67_RTSP_BUFSIZE){
                printf("too small buffer to receive complete content!\n");
                close(res->sockfd);
                // mark as no content;
                res->contentlen = 0;

                res->state = aes67_rtsp_dsc_state_done;

                printf("too little content\n");
                return;
            }

            u16_t missing = res->contentlen - (res->buflen - res->hdrlen);

            r = read(res->sockfd, &res->buf[res->buflen], missing);

            if (r == -1){ // timeout
                return;
            } else if (r == 0) { // closed prematurely
                close(res->sockfd);
                res->sockfd = -1;
                // invalidate content
                res->contentlen = 0;
                res->state = aes67_rtsp_dsc_state_done;
                return;
            } else if (r > 0) {
                res->buflen += r;

                if (r == missing){
                    close(res->sockfd);
                    res->sockfd = -1;
                    res->state = aes67_rtsp_dsc_state_done;
                }
            }

            return;
        } // state == awaiting_response
    }
}


ssize_t aes67_rtsp_dsc_easy(
        const u8_t *ip,
        const enum aes67_net_ipver ipver,
        const u16_t port,
        const char *uri,
        u8_t *sdp,
        size_t maxlen
) {

    struct aes67_net_addr addr;

    addr.ipver = ipver;
    memcpy(addr.addr, ip, AES67_NET_IPVER_SIZE(ipver));
    addr.port = port;

    struct aes67_rtsp_dsc_res_st res;

    aes67_rtsp_dsc_init(&res, true);

    if (aes67_rtsp_dsc_start(&res, addr.ipver, addr.addr, addr.port, uri)){
        return EXIT_FAILURE;
    }

    while(res.state != aes67_rtsp_dsc_state_done){
        aes67_rtsp_dsc_process(&res);
    }

    if (res.contentlen > 0){
        memcpy(sdp, aes67_rtsp_dsc_content(&res), res.contentlen);
    }

    aes67_rtsp_dsc_deinit(&res);

    return (res.contentlen > 0 ? res.contentlen : 0);

}


ssize_t aes67_rtsp_dsc_easy_url(const char *url, u8_t *sdp, size_t maxlen)
{
    assert(url != NULL);
    assert(sdp != NULL);

    size_t len = strlen((char*)url);

    if (len < sizeof(AES67_RTSP_SCHEME "://") || aes67_memcmp(url, AES67_RTSP_SCHEME "://", sizeof(AES67_RTSP_SCHEME "://")-1)){
        return -1;
    }

    url += sizeof(AES67_RTSP_SCHEME "://")-1;
    len -= sizeof(AES67_RTSP_SCHEME "://")-1;

    char * uri = (char*)url;

    for(int i = 0; i < len && *uri != '/'; i++, uri++){
        // looking for start of remaining resource path
    }

    size_t hostlen = uri - url;
    size_t urilen = len - hostlen;

    struct aes67_net_addr ip;

    // if not an <ip>:<port> is given we're dealing with <host>:<port>
    if (aes67_net_str2addr(&ip, (u8_t*)url, hostlen) == false){

        // locate port delimiter (hoping for an ipv4....)
        // TODO ipv6 (?)

        u8_t * delim = aes67_memchr(url, ':', hostlen);

        if (delim == NULL){
            ip.port = 0;
        } else {
            *delim++ = '\0'; /// ooooooh, writing to a const....

            u16_t readlen = 0;

            ip.port = aes67_atoi(delim, (u8_t*)uri - delim, 10, &readlen);
            if (readlen == 0){
                // no valid port read
                return -1;
            }
        }

        uri[0] = '\0';

        struct hostent * he = gethostbyname((char*)url);

        if (delim != NULL){
            *--delim = ':';
        }
        if (urilen > 0){
            uri[0] = '/';
        }

        if (he == NULL){
            return -1;
        }

        ip.ipver = aes67_net_ipver_4;
        *(u32_t*)ip.addr = ((struct in_addr **)he->h_addr_list)[0]->s_addr;
    }

    // if no port is given, use default port
    if (ip.port == 0){
        ip.port = AES67_RTSP_DEFAULT_PORT;
    }

//    printf("%d.%d.%d.%d:%d (%d) %s (%lu)\n", ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3], ip.port, ip.ipver, (char*)uri, strlen((char*)uri));
//    return 0;
    return aes67_rtsp_dsc_easy(ip.addr, ip.ipver, ip.port, uri, sdp, maxlen);
}
