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

#include "aes67/debug.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <search.h>

WEAK_FUN void aes67_rtsp_header(u8_t * buf, ssize_t len)
{
    // do nothing
}

ssize_t  aes67_rtsp_describe(const u8_t * ip, const enum aes67_net_ipver ipver, const u16_t port, const u8_t * uri, u8_t * sdp, size_t maxlen) {
    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        return -1;
    }


    struct sockaddr_in server;
    server.sin_addr.s_addr = *(u32_t *) ip;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
        close(sockfd);
        return -1;
    }

    u8_t buf[1500];

    u8_t host[64];
    size_t hlen = aes67_net_ip2str(host, (enum aes67_net_ipver)ipver, (u8_t*)ip, (u16_t)port);
    host[hlen] = '\0';

    u8_t *p = (uri == NULL) ? (u8_t *) "" : (u8_t*)uri;

    size_t len = sprintf((char *) buf,
                         "DESCRIBE rtsp://%s%s RTSP/1.0\r\n"
                         "CSeq: 1\r\n"
                         "Accept: application/sdp\r\n"
                         "\r\n", host, p);

    if (write(sockfd, buf, len) == -1) {
        close(sockfd);
        return -1;
    }

    ssize_t r = read(sockfd, buf, sizeof(buf));
    if (r == -1) {
        close(sockfd);
        return -1;
    }
    close(sockfd);

    // basic protocol check
    if (r < 20 || memcmp(buf, "RTSP/", 5) != 0) {
        return -1;
    }

    // get RTSP status code
    s32_t res = atoi((char *) &buf[9]);

    if (res != AES67_RTSP_STATUS_OK) {
        return -res;
    }

    //locate body
    u8_t *body = buf;
    for (int i = 0; i < r; i++, body++) {
        if (body[0] == '\r' && body[1] == '\n' && body[2] == '\r' && body[3] == '\n') {
            break;
        }
    }

    // move to actual body start
    body += 4;

    // body not found
    if (body >= &buf[r]) {
        aes67_rtsp_header(buf, r);

        return -1;
    }

    size_t contentLength = r - (body - buf);

    aes67_rtsp_header(buf, r - contentLength - 2);

    if (contentLength > maxlen){
        contentLength = maxlen;
    }

    memcpy(sdp, body, contentLength);

    return contentLength;
}


ssize_t aes67_rtsp_describe_url(const u8_t * url, u8_t * sdp, size_t maxlen)
{
    AES67_ASSERT("url != NULL", url != NULL);
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    size_t len = strlen((char*)url);

    if (len < sizeof(AES67_RTSP_SCHEME "://") || aes67_memcmp(url, AES67_RTSP_SCHEME "://", sizeof(AES67_RTSP_SCHEME "://")-1)){
        return -1;
    }

    url += sizeof(AES67_RTSP_SCHEME "://")-1;
    len -= sizeof(AES67_RTSP_SCHEME "://")-1;

    u8_t * uri = (u8_t*)url;

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
            *delim++ = '\0';

            u16_t readlen = 0;

            ip.port = aes67_atoi(delim, uri - delim, 10, &readlen);
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

        *(u32_t*)ip.addr = ((struct in_addr **)he->h_addr_list)[0]->s_addr;
        ip.ipver = aes67_net_ipver_4;

    }

    // if no port is given, use default port
    if (ip.port == 0){
        ip.port = AES67_RTSP_DEFAULT_PORT;
    }

//    printf("%d.%d.%d.%d:%d (%d) %s (%lu)\n", ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3], ip.port, ip.ipver, (char*)uri, strlen((char*)uri));
//    return 0;
    return aes67_rtsp_describe(ip.addr, ip.ipver, ip.port, uri, sdp, maxlen);
}
