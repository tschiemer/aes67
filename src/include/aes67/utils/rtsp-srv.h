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

#ifndef AES67_RTSP_UTILS_SRV_H
#define AES67_RTSP_UTILS_SRV_H

#include "aes67/arch.h"
#include "aes67/net.h"
#include "aes67/rtsp.h"

#include <stdbool.h>
#include <netinet/in.h>

#ifndef AES67_RTSP_SRV_MAXURILEN
#define AES67_RTSP_SRV_MAXURILEN 256
#endif

#ifndef AES67_RTSPSRV_LISTEN_BACKLOG
#define AES67_RTSPSRV_LISTEN_BACKLOG 10
#endif

#ifndef AES67_RTSP_SRV_RXBUFSIZE
#define AES67_RTSP_SRV_RXBUFSIZE 1500
#endif

#ifndef AES67_RTSP_SRV_TXBUFSIZE
#define AES67_RTSP_SRV_TXBUFSIZE AES67_RTSP_SRV_RXBUFSIZE
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum aes67_rtsp_srv_state {
    aes67_rtsp_srv_state_init = 0,
    aes67_rtsp_srv_state_listening,
    aes67_rtsp_srv_state_receiving,
    aes67_rtsp_srv_state_processing,
    aes67_rtsp_srv_state_sending
};

enum aes67_rtsp_srv_proto {
    aes67_rtsp_srv_proto_undefined = 0,
    aes67_rtsp_srv_proto_rtsp,
    aes67_rtsp_srv_proto_http
};

enum aes67_rtsp_srv_method {
    aes67_rtsp_srv_method_options   = 1,
    aes67_rtsp_srv_method_describe  = 2,
    aes67_rtsp_srv_method_get       = 4,
    aes67_rtsp_srv_method_post      = 8,
    aes67_rtsp_srv_method_delete    = 16,
    aes67_rtsp_srv_method_put       = 32,
};

struct aes67_rtsp_srv_http_response {
    u16_t status_code;
    u16_t has_more;
    u16_t datalen;
    u8_t * data;
};


struct aes67_rtsp_srv_resource {
    struct aes67_rtsp_srv_resource * next;

    u8_t urilen;
    char uri[AES67_RTSP_SRV_MAXURILEN];

    void * sdpref;
};

struct aes67_rtsp_srv {

    enum aes67_rtsp_srv_state state;

    bool http_enabled;
    void * user_data;

    struct sockaddr_in listen_addr;
    int listen_sockfd;

    struct sockaddr_in client_addr;
    int client_sockfd;

    bool blocking;

    struct aes67_rtsp_srv_resource * first_res;


    struct {

        u8_t data[AES67_RTSP_SRV_RXBUFSIZE];
        u16_t data_len;

        // helper
        u8_t * line;
        u16_t llen;
        int CR;

        enum aes67_rtsp_srv_proto proto;
        struct {
            u16_t major;
            u16_t minor;
        } version;
        enum aes67_rtsp_srv_method method;
        u8_t * uri;
        u8_t urilen;
        u16_t header_len;
        u16_t content_length;

        u16_t cseq;

    } req; // request

    struct {
        u16_t status_code;
        u16_t sent;
        u16_t len;
        u8_t data[AES67_RTSP_SRV_TXBUFSIZE];
    } res; // response
};

void aes67_rtsp_srv_init(struct aes67_rtsp_srv * srv, bool http_enabled, void * user_data);
void aes67_rtsp_srv_deinit(struct aes67_rtsp_srv * srv);

int aes67_rtsp_srv_start(struct aes67_rtsp_srv * srv, const enum aes67_net_ipver ipver, const u8_t *ip, u16_t port);
void aes67_rtsp_srv_stop(struct aes67_rtsp_srv * srv);

void aes67_rtsp_srv_blocking(struct aes67_rtsp_srv * srv, bool blocking);

void aes67_rtsp_srv_process(struct aes67_rtsp_srv * srv);

void aes67_rtsp_srv_sdp_getter(struct aes67_rtsp_srv * srv, void * sdpref, u8_t * buf, u16_t * len, u16_t maxlen);
void aes67_rtsp_srv_http_handler(struct aes67_rtsp_srv * srv, const enum aes67_rtsp_srv_method method, const char * uri, const u8_t urilen, u8_t * buf, u16_t * len, u16_t maxlen, void * response_data);

struct aes67_rtsp_srv_resource * aes67_rtsp_srv_sdp_add(struct aes67_rtsp_srv * srv, const char * uri, const u8_t urilen, void * sdpref);
void aes67_rtsp_srv_sdp_remove(struct aes67_rtsp_srv * srv, void * sdpref);


#ifdef __cplusplus
}
#endif

#endif //AES67_RTSP_UTILS_SRV_H
