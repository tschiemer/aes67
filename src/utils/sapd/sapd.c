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

#include "aes67/utils/sapd.h"

#include "aes67/utils/sapsrv.h"
#include "aes67/utils/daemonize.h"
#include "aes67/sap.h"

#if AES67_SAPD_WITH_RAV == 1
#include "aes67/utils/mdns.h"
#include "aes67/rav.h"
#include "dnmfarrell/URI-Encode-C/src/uri_encode.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <assert.h>

//#define BUFSIZE 1024
#define MAX_CMDLINE 256

#define DEFAULT_LISTEN_SCOPES   (AES67_SAPSRV_SCOPE_IPv4 | AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL)
#define DEFAULT_SEND_SCOPES     AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED


#define MSG_VERSIONWELCOME         AES67_SAPD_MSGU_INFO " " AES67_SAPD_NAME_LONG

#if AES67_SAPD_WITH_RAV == 1

#define RAV_MAX_PUBLISH_DELAY   360
#define RAV_MAX_UPDATE_INTERVAL 360


enum rav_state {
    rav_state_error = 0,
    rav_state_discovered,
    rav_state_sdp_available,
    rav_state_sdp_published,
    rav_state_sdp_updated,
    rav_state_sdp_not_published,
};
struct rav_session_st {
    char * name;
    char * hosttarget;
    struct aes67_net_addr addr;
    u32_t ttl;

    struct aes67_sdp_originator origin;
    u8_t * sdp;
    u16_t sdplen;

    enum rav_state state;
    time_t last_activity;

    struct rav_session_st * next;
};
#endif //AES67_SAPD_WITH_RAV == 1

struct connection_st {
    int sockfd;
    struct sockaddr_un addr;
    socklen_t socklen;

    uid_t euid;
    gid_t egid;

    struct connection_st * next;
};

typedef void (*cmd_handler)(struct connection_st * con, u8_t * cmdline, size_t len);

struct cmd_st {
    u8_t cmdlen;
    const u8_t * cmd;
    cmd_handler handler;
};

#define CMD_INIT(str, _handler_) { \
    .cmdlen = sizeof(str)-1,     \
    .cmd = (const u8_t*)str,                  \
    .handler = _handler_           \
}


static void help(FILE * fd);

static void sig_int(int sig);
static void sig_alrm(int sig);

static int sock_nonblock(int sockfd);

static void block_until_event();

static int sapsrv_setup();
static void sapsrv_teardown();
static void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sapsrv_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data);

#if AES67_SAPD_WITH_RAV == 1
static struct rav_session_st * rav_session_find(const char * name);
static struct rav_session_st * rav_session_new(const char * name, const char * hosttarget, enum aes67_net_ipver ipver, const u8_t * ip, u16_t port, u32_t ttl);
static void rav_session_delete(struct rav_session_st * session);
static int rav_setup();
static void rav_teardown();
static void rav_process();
//static void rav_browse_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * domain, void * context);
static void rav_resolve_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, enum aes67_net_ipver ipver, const u8_t * ip, u32_t ttl, void * context);
#endif //AES67_SAPD_WITH_RAV == 1

static struct connection_st * connection_new(int sockfd, struct sockaddr_un * addr, socklen_t socklen);
static void connection_close(struct connection_st * con);

static int local_setup(const char * fname);
static void local_teardown();
static void local_accept();
static void local_process();

static void write_error(struct connection_st * con, const u32_t code, const char * str);
static void write_ok(struct connection_st * con);
static void write_toall_except(u8_t * msg, u16_t len, struct connection_st * except);

//static void cmd_help(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_list(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_set(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_unset(struct connection_st * con, u8_t * cmdline, size_t len);




static char * argv0;

static struct {
    bool daemonize;
    bool verbose;
    u32_t listen_scopes;
    u32_t send_scopes;
    s32_t port;
    unsigned int ipv6_if;
#if AES67_SAPD_WITH_RAV == 1
    bool rav_enabled;
    uint16_t rav_publish_delay;
    uint16_t rav_update_interval;
#endif// AES67_SAPD_WITH_RAV == 1

} opts = {
        .daemonize = false,
        .verbose = false,
        .listen_scopes = 0,
        .send_scopes = 0,
        .port = AES67_SAP_PORT,
        .ipv6_if = 0,
#if AES67_SAPD_WITH_RAV == 1
        .rav_enabled = false,
        .rav_publish_delay = AES67_SAPD_RAV_PUBLISH_DELAY_DEFAULT,
        .rav_update_interval = AES67_SAPD_RAV_UPDATE_INTERVAL_DEFAULT
#endif // AES67_SAPD_WITH_RAV == 1
};

static volatile bool keep_running;

static aes67_sapsrv_t * sapsrv = NULL;

#if AES67_SAPD_WITH_RAV == 1
static struct {
    aes67_mdns_context_t mdns_context;
    aes67_mdns_resource_t mdns_browse_res;
    struct rav_session_st * first_session;
    struct aes67_rtsp_dsc_res_st rtsp;
    struct rav_session_st * rtsp_session;
    struct aes67_timer publish_timer;
    struct aes67_timer update_timer;
} rav = {
    .mdns_context = NULL,
    .mdns_browse_res = NULL,
    .first_session = NULL,
    .rtsp_session = NULL
};

#endif //AES67_SAPD_WITH_RAV == 1

static struct {
    const char * fname;

    int sockfd;
    struct sockaddr_un addr;

    int nconnections;
    struct connection_st * first_connection;
} local = {
    .fname = NULL,
    .sockfd = -1
};


static const struct cmd_st commands[] = {
//        CMD_INIT(AES67_SAPD_CMD_HELP, cmd_help),
        CMD_INIT(AES67_SAPD_CMD_LIST, cmd_list),
        CMD_INIT(AES67_SAPD_CMD_SET, cmd_set),
        CMD_INIT(AES67_SAPD_CMD_UNSET, cmd_unset)
};

#define COMMAND_COUNT (sizeof(commands) / sizeof(struct cmd_st))

static const char * error_msg[] = {
        "Generic error",          // AES67_SAPD_ERROR
        "Unrecognized command",   // AES67_SAPD_ERR_UNRECOGNIZED
        "Missing args",           // AES67_SAPD_ERR_MISSING
        "Syntax error",           // AES67_SAPD_ERR_SYNTAX
        "Unknown session",        // AES67_SAPD_ERR_UNKNOWN
        "SDP too big",            // AES67_SAPD_ERR_TOOBIG
        "Invalid..",                // AES67_SAPD_ERR_INVALID
};

#define ERROR_COUNT (sizeof(error_msg) / sizeof(char *))

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h|-?] | [-d] [-p <port>] [--l <mcast-scope>] [--s <mcast-scope>] [--ipv6-if <ifname>] ..\n"
             "Starts an (SDP-only) SAP server that maintains incoming SDPs, informs about updates and keeps announcing\n"
             "specified SDPs on network.\n"
             "Communicates through local port (" AES67_SAPD_LOCAL_SOCK ")\n"
             "Logs to syslog (identity " AES67_SAPD_SYSLOG_IDENT ")\n"
             "\nOptions:\n"
             "\t -h,-?\t\t Prints this info.\n"
             "\t -d,--daemonize\t Daemonize\n"
             "\t -v\t\t Also print syslog to STDERR\n"
             "\t -p,--port <port>\t Listen on this port (default %hu)\n"
             "\t --l<mcast-scope>, --s<mcast-scope>\n"
             "\t\t\t Listens, sends respectively on these IPv4/6 multicast scopes (multiple possible). Scopes:\n"
             "\t\t\t\t 4g\t IPv4 SAP global (" AES67_SAP_IPv4_GLOBAL_STR ")\n"
             "\t\t\t\t 4a\t IPv4 SAP administered (" AES67_SAP_IPv4_ADMIN_STR ")\n"
             "\t\t\t\t 6ll\t IPv6 SAP link local (" AES67_SAP_IPv6_LL_STR ")\n"
             "\t\t\t\t 6ip4\t IPv6 SAP ip4 scope local (" AES67_SAP_IPv6_IP4_STR ")\n"
            "\t\t\t\t 6al\t IPv6 SAP admin local (" AES67_SAP_IPv6_AL_STR ")\n"
            "\t\t\t\t 6sl\t IPv6 SAP site local (" AES67_SAP_IPv6_SL_STR ")\n"
            "\t\t\t Default listen: 4g + 4a + 6ll\n"
            "\t\t\t Default send: 4a\n"
            "\t --ipv6-if\t IPv6 interface to listen on (default interface can fail)\n"
 #if AES67_SAPD_WITH_RAV == 1
            "\t --rav\t\t Enable Ravenna session lookups\n"
             "\t --rav-pub-delay <delay-sec>\n"
             "\t\t\t Wait for this many seconds before publishing discovered ravenna devices through SAP (0 .. %d, default %d)\n"
             "\t --rav-upd-interval <interval-sec>\n"
             "\t\t\t Wait for this many seconds checking for SDP change of already published ravenna device (0 .. %d, default %d)\n"
 #endif
            "\nCompile time options:\n"
            "\t AES67_SAP_MIN_INTERVAL_SEC %d \t // +- announce time, depends on SAP traffic\n"
            "\t AES67_SAP_MIN_TIMEOUT_SEC %d \n"
            "\t AES67_SAPD_WITH_RAV %d\n"
             "\nExamples:\n"
             "sudo %s -v --ipv6-if en7 & socat - UNIX-CONNECT:" AES67_SAPD_LOCAL_SOCK ",keepalive\n"
            , argv0,
            (u16_t)AES67_SAP_PORT,
            RAV_MAX_PUBLISH_DELAY, AES67_SAPD_RAV_PUBLISH_DELAY_DEFAULT,
            RAV_MAX_UPDATE_INTERVAL, AES67_SAPD_RAV_UPDATE_INTERVAL_DEFAULT,
            AES67_SAP_MIN_INTERVAL_SEC,
            AES67_SAP_MIN_TIMEOUT_SEC,
             AES67_SAPD_WITH_RAV,
             argv0);
}

static void sig_int(int sig)
{
    keep_running = false;
}

static void sig_alrm(int sig)
{
    // do nothing, hurray!
}

static int sock_nonblock(int sockfd){
    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "local. Couldn't change non-/blocking\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void block_until_event()
{
    int nfds = 0;
    struct fd_set fds;
//    sigset_t sigmask;

    FD_ZERO(&fds);

    // set all AF_LOCAL sockets
    FD_SET(local.sockfd, &fds);
    nfds = local.sockfd;

    struct connection_st * con = local.first_connection;
    for(;con != NULL; con = con->next){
        FD_SET(con->sockfd, &fds);
        if (con->sockfd > nfds){
            nfds = con->sockfd;
        }
    }

    int * sockfds;
    size_t count = 0;
    aes67_sapsrv_getsockfds(sapsrv, &sockfds, &count);
    for(size_t i = 0; i < count; i++){
        FD_SET(sockfds[i], &fds);
        if (sockfds[i] > nfds){
            nfds = sockfds[i];
        }
    }

#if AES67_SAPD_WITH_RAV == 1
    if (opts.rav_enabled) {

        aes67_mdns_getsockfds(rav.mdns_context, &sockfds, &count);
        for (size_t i = 0; i < count; i++) {
            FD_SET(sockfds[i], &fds);
            if (sockfds[i] > nfds) {
                nfds = sockfds[i];
            }
        }

        if (rav.rtsp.state == aes67_rtsp_dsc_state_awaiting_response && rav.rtsp.sockfd != -1){
            FD_SET(rav.rtsp.sockfd, &fds);
            if (rav.rtsp.sockfd > nfds){
                nfds = rav.rtsp.sockfd;
            }
        }
    }
#endif //AES67_SAPD_WITH_RAV == 1


    nfds++;

    // just wait until something interesting happens
    select(nfds, &fds, NULL, &fds, NULL);
}

static int sapsrv_setup()
{
    aes67_time_init_system();
    aes67_timer_init_system();

    // set SIGALRM handler (triggered by timer)
    signal(SIGALRM, sig_alrm);

    sapsrv = aes67_sapsrv_start(opts.send_scopes, opts.port, opts.listen_scopes, opts.ipv6_if, sapsrv_callback, NULL);

    if (sapsrv == NULL){
        syslog(LOG_ERR, "Failed to start sapsrv ..");

        aes67_timer_deinit_system();
        aes67_time_deinit_system();

        return EXIT_FAILURE;
    }

    aes67_sapsrv_setblocking(sapsrv, false);

    // pretty log message
//    u8_t listen_str[64];
//    u8_t iface_str[64];
//
//    u16_t listen_len = aes67_net_addr2str(listen_str, &opts.listen_addr);
//    u16_t iface_len = aes67_net_addr2str(iface_str, &opts.iface_addr);
//
////    printf("%hu\n", opts.listen_addr.port);
//
//    listen_str[listen_len] = '\0';
//    iface_str[iface_len] = '\0';
//
//    syslog(LOG_NOTICE, "SAP listening on %s (if %s)", listen_str, iface_len ? (char*)iface_str : "default" );
//    syslog(LOG_NOTICE, "SAP listening...");

    return EXIT_SUCCESS;
}

static void sapsrv_teardown()
{
    if (sapsrv == NULL){
        aes67_sapsrv_stop(sapsrv);
        sapsrv = NULL;
    }

    aes67_timer_deinit_system();
    aes67_time_deinit_system();
}

static void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sapsrv_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data)
{
//    printf("asdf %d\n", event);

    u8_t ostr[256];
    s32_t olen = aes67_sdp_origin_tostr(ostr, sizeof(ostr)-1, (struct aes67_sdp_originator *)origin);

    if (olen >= 0){
        olen -= 2; // remove CRNL
        ostr[olen] = '\0';
    } else {
        strncpy((char*)ostr, "internal error", sizeof(ostr));
    }

    u8_t msg[1500];
    ssize_t mlen;

    if (event == aes67_sapsrv_event_discovered){
        syslog(LOG_INFO, "SAP: discovered (payload %d): %s", payloadlen, ostr);

        mlen = snprintf((char*)msg, sizeof(msg), "%s %d %s\n",
                        AES67_SAPD_MSGU_NEW,
                        payloadlen,
                        ostr
        );

        if (mlen + payloadlen + 1 >= sizeof(msg)){
            syslog(LOG_ERR, "not enough memory");
            return;
        }

        memcpy(&msg[mlen], payload, payloadlen);
        mlen += payloadlen;

//        msg[mlen++] = '\n'; // always add a newline?

        write_toall_except(msg, mlen, NULL);
    }
    else if (event == aes67_sapsrv_event_updated){
        syslog(LOG_INFO, "SAP: updated (payload %d): %s", payloadlen, ostr);

        mlen = snprintf((char*)msg, sizeof(msg), "%s %d %s\n",
                        AES67_SAPD_MSGU_UPDATED,
                        payloadlen,
                        ostr
        );

        if (mlen + payloadlen + 1 >= sizeof(msg)){
            syslog(LOG_ERR, "not enough memory");
            return;
        }

        memcpy(&msg[mlen], payload, payloadlen);
        mlen += payloadlen;

//        msg[mlen++] = '\n'; // always add a newline?

        write_toall_except(msg, mlen, NULL);
    }
    else if (event == aes67_sapsrv_event_deleted){
        syslog(LOG_INFO, "SAP: deleted: %s", ostr);

        mlen = snprintf((char*)msg, sizeof(msg), "%s %s\n",
                        AES67_SAPD_MSGU_DELETED,
                        ostr
        );

        write_toall_except(msg, mlen, NULL);
    }
    else if (event == aes67_sapsrv_event_timeout){
        syslog(LOG_INFO, "SAP: timeout: %s", ostr);

        mlen = snprintf((char*)msg, sizeof(msg), "%s %s\n",
                        AES67_SAPD_MSGU_TIMEOUT,
                        ostr
        );

        write_toall_except(msg, mlen, NULL);
    }
    else {
        syslog(LOG_INFO, "SAP: ???: %s", ostr);
    }
}

#if AES67_SAPD_WITH_RAV == 1

static struct rav_session_st * rav_session_find(const char * name)
{
    struct rav_session_st * session = rav.first_session;

    for(;session != NULL; session = session->next){
        if (strcmp(session->name, name) == 0){
            return session;
        }
    }

    return NULL;
}

static struct rav_session_st * rav_session_new(const char * name, const char * hosttarget, enum aes67_net_ipver ipver, const u8_t * ip, u16_t port, u32_t ttl)
{
    assert(name != NULL);
    assert(hosttarget != NULL);
    assert(AES67_NET_IPVER_ISVALID(ipver));
    assert(ip != NULL);

    struct rav_session_st * session = malloc(sizeof(struct rav_session_st));

    session->name = calloc(1, strlen(name)+1);
    strcpy(session->name, name);

    session->hosttarget = calloc(1, strlen(hosttarget)+1);
    strcpy(session->hosttarget, hosttarget);

    session->addr.ipver = ipver;
    memcpy(session->addr.addr, ip, AES67_NET_IPVER_SIZE(ipver));
    session->addr.port = port;

    session->ttl = ttl;

    aes67_sdp_origin_init(&session->origin);
    session->sdp = NULL;
    session->sdplen = 0;

    session->last_activity = 0;

    session->next = rav.first_session;
    rav.first_session = session;

    return session;
}

static void rav_session_delete(struct rav_session_st * session)
{
    assert(session != NULL);

    if (session == rav.first_session){
        rav.first_session = session->next;
    } else {
        struct rav_session_st * current = rav.first_session;
        while(current != NULL){
            if (current->next == session){
                current->next = session->next;
            }
            current = current->next;
        }
    }

    // if currently SDP lookup is in process with given session, abort
    if (rav.rtsp_session == session){
        aes67_rtsp_dsc_stop(&rav.rtsp);
        rav.rtsp_session = NULL;
    }

    // if registered with sapsrv, remove
    if (session->state == rav_state_sdp_updated || session->state == rav_state_sdp_published){
        //TODO
    }

    if (session->sdp != NULL){
        free(session->sdp);
        session->sdp = NULL;
        session->sdplen = 0;
    }

    free(session->name);
    free(session->hosttarget);
    free(session);
}

static int rav_setup()
{
    rav.mdns_context = aes67_mdns_new();
    if (rav.mdns_context == NULL){
        return EXIT_FAILURE;
    }

    rav.mdns_browse_res = aes67_mdns_resolve2_start(rav.mdns_context, AES67_RAV_MDNS_SUBTYPE_SESSION "._sub." AES67_RAV_MDNS_TYPE_SENDER, NULL, rav_resolve_callback, NULL );
    if (rav.mdns_browse_res == NULL){
        return EXIT_FAILURE;
    }

    aes67_rtsp_dsc_init(&rav.rtsp, false);

    aes67_timer_init(&rav.publish_timer);
    aes67_timer_init(&rav.update_timer);

    syslog(LOG_INFO, "Browsing for Ravenna sessions");

    return EXIT_SUCCESS;
}

static void rav_teardown()
{
    aes67_timer_deinit(&rav.publish_timer);
    aes67_timer_deinit(&rav.update_timer);

    aes67_rtsp_dsc_deinit(&rav.rtsp);

    if (rav.mdns_context == NULL){
        return;
    }

    aes67_mdns_delete(rav.mdns_context);
    rav.mdns_context = NULL;
}

static void rav_process()
{
    //// update sessions according to mDNS
    struct timeval tv = {
            .tv_sec = 0,
            .tv_usec = 0
    };
    // non-blocking processing
    aes67_mdns_process(rav.mdns_context, &tv);

    //// check if rtsp sdp lookup has anything to do
    // first process pending
    if (rav.rtsp.state == aes67_rtsp_dsc_state_awaiting_response){
        aes67_rtsp_dsc_process(&rav.rtsp);
    }
    // if done
    if (rav.rtsp.state == aes67_rtsp_dsc_state_done){

        // update last activity?
        rav.rtsp_session->last_activity = time(NULL);

        // checking for some meaningful min-length
        if (rav.rtsp.statuscode == AES67_RTSP_STATUS_OK && rav.rtsp.contentlen > 32){

            u8_t *sdp = (u8_t*)aes67_rtsp_dsc_content(&rav.rtsp);
            assert(sdp != NULL); // should not occur

            // get origin (o=..) offset v=0\r\n
            u8_t * o = sdp[4] == '\n' ? &sdp[5] : &sdp[4];

            sdp[rav.rtsp.contentlen] = '\0';

//            printf("%s\n", o);
//            printf("origin %c%c%c %d\n", o[0], o[1] ,o[2], rav.rtsp.contentlen - (o - sdp));

            struct aes67_sdp_originator origin;

            if (aes67_sdp_origin_fromstr(&origin, o, rav.rtsp.contentlen - (o - sdp)) == AES67_SDP_ERROR){
                rav.rtsp_session->state = rav_state_error;
                syslog(LOG_ERR, "rav failed to extract originator");
            }
            // if originators are equal (and same version!) this implies that nothing has changed
            // and that this rav session actually previously retrieved the SDP data
            else if (aes67_sdp_origin_eq(&rav.rtsp_session->origin, &origin) == 0 && aes67_sdp_origin_cmpversion(&rav.rtsp_session->origin, &origin) == 0){
                // nothing to do, hurray!
//                rav.rtsp_session->state = rav_state_error;
                fprintf(stderr, "???\n");
            }
            else {

                // if originators are equal (but newer version!) this implies that nothing has changed
                // and that this rav session actually previously retrieved the SDP data
                if (aes67_sdp_origin_eq(&rav.rtsp_session->origin, &origin) == 0 && aes67_sdp_origin_cmpversion(&rav.rtsp_session->origin, &origin) == -1){
                    free(rav.rtsp_session->sdp);
                    rav.rtsp_session->sdp = NULL;
                    rav.rtsp_session->sdplen = 0;
                }

                // update SDP info
                memcpy(&rav.rtsp_session->origin, &origin, sizeof(struct aes67_sdp_originator));

                rav.rtsp_session->sdp = malloc(rav.rtsp.contentlen + 1);

                assert(rav.rtsp_session->sdp != NULL);

                memcpy(rav.rtsp_session->sdp, sdp, rav.rtsp.contentlen);
                rav.rtsp_session->sdp[rav.rtsp.contentlen] = '\0'; // not needed, but in case dumping
                rav.rtsp_session->sdplen = rav.rtsp.contentlen;


                if (rav.rtsp_session->state == rav_state_discovered){
                    rav.rtsp_session->state = rav_state_sdp_available;
                } else if (rav.rtsp_session->state == rav_state_sdp_published){
                    rav.rtsp_session->state = rav_state_sdp_updated;
                } else {
                    // should not reach here
                    rav.rtsp_session->state = rav_state_error;
                }
            }

        } else {
            rav.rtsp_session->state = rav_state_error;
            syslog(LOG_ERR, "rtsp describe fail: %s", rav.rtsp_session->name);
        }

        // make available for next describe operation
        rav.rtsp_session = NULL;
        rav.rtsp.state = aes67_rtsp_dsc_state_bored;
    }
    // if actually nothing to do
    if (rav.rtsp.state == aes67_rtsp_dsc_state_bored){

        struct rav_session_st * session = rav.first_session;
        struct rav_session_st * oldest = NULL;

        // try to find sessions whose SDP yet has to be retrieved (and look for oldest
        while(session != NULL){
            if (session->state == rav_state_discovered){
                break;
            }

            // consider only published sdps that might have to be updated
            if (opts.rav_update_interval > 0 && session->state == rav_state_sdp_published && (oldest == NULL || session->last_activity < oldest->last_activity )){
                oldest = session;
            }

            session = session->next;
        }

        if (session == NULL && oldest != NULL){
            // if the oldest is too old, let's update it directly
            // otherwise set an alarm
            if (oldest->last_activity < time(NULL) - opts.rav_update_interval){
                //session = oldest;
            } else {
                //TODO set alarm to trigger update
            }
        }

        if (session != NULL ){
            char name[128];
            uri_encode(session->name, strlen(session->name), name, sizeof(name));

            char uri[256];
            snprintf(uri, sizeof(uri), "/by-name/%s", name);

            if (aes67_rtsp_dsc_start(&rav.rtsp, session->addr.ipver, session->addr.addr, session->addr.port, uri)){
                syslog(LOG_ERR, "rtsp_dsc_start() fail");

            } else {
                rav.rtsp_session = session;
            }
        }
    }

    //// check if we now should publish
    time_t publish_if_older = time(NULL) - opts.rav_publish_delay;
    struct rav_session_st * session = rav.first_session;
    struct rav_session_st * oldest = NULL;
    while(session != NULL){
        if (session->state == rav_state_sdp_available){

            if (session->last_activity <= publish_if_older){

                assert(session->sdp != NULL);

                aes67_sapsrv_session_t sapsrvSession = aes67_sapsrv_session_by_origin(sapsrv, &session->origin);

                // if it already exists, the device has published the SDp itself
                if (sapsrvSession != NULL){
                    session->state = rav_state_sdp_not_published;
                } else {

                    u16_t hash = atoi((char*)session->origin.session_id.data);

                    aes67_sapsrv_session_add(sapsrv, hash, session->addr.ipver, session->addr.addr, session->sdp, session->sdplen);

                    session->state = rav_state_sdp_published;
                }
            } else if (oldest == NULL || session->last_activity < oldest->last_activity ){
                oldest = session;
            }

        }
        else if (session->state == rav_state_sdp_updated){

            aes67_sapsrv_session_t sapsrvSession = aes67_sapsrv_session_by_origin(sapsrv, &session->origin);

            if (sapsrvSession != NULL){

                aes67_sapsrv_session_update(sapsrv, sapsrvSession, session->sdp, session->sdplen);

                session->state = rav_state_sdp_published;
            }

        }

        session = session->next;
    }

    // if oldest is set, this means we should set an alarm
    if (oldest != NULL){
        u32_t wait_sec = opts.rav_publish_delay - (time(NULL) - oldest->last_activity);
        aes67_timer_set(&rav.publish_timer, 1000 * wait_sec);
    }
}

//static void rav_browse_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * domain, void * context)
//{
//
//}

static void rav_resolve_callback(aes67_mdns_resource_t res, enum aes67_mdns_result result, const char * type, const char * name, const char * hosttarget, u16_t port, u16_t txtlen, const u8_t * txt, enum aes67_net_ipver ipver, const u8_t * ip, u32_t ttl, void * context)
{
//    printf("rav_resolved %d\n", result);

    // ignore (?) errors
    if (result == aes67_mdns_result_error){
        return;
    }

    // only mind ipv4
    // TODO ipv6?
    if (ipver != aes67_net_ipver_4){
        return;
    }

    struct rav_session_st * session = rav_session_find(name);

    if (result == aes67_mdns_result_discovered){

        // if the session is known already, don't bother about it except for updating it's timestamp
        if (session != NULL){
            session->last_activity = time(NULL);
            return;
        }

        session = rav_session_new(name, hosttarget, ipver, ip, port, ttl);
        session->last_activity = time(NULL);
        session->state = rav_state_discovered;

        u8_t ipstr[AES67_NET_ADDR_STR_MAX];

        u16_t len = aes67_net_ip2str(ipstr, ipver, (u8_t*)ip, 0);
        ipstr[len] = '\0';

        u8_t msg[256];

        len = snprintf((char*)msg, sizeof(msg), AES67_SAPD_MSGU_RAV_NEW_FMT "\n", hosttarget, ipstr, port, name);

        write_toall_except(msg, len, NULL);

        syslog(LOG_INFO, "RAV session discovered: %s@%s:%hu", name, hosttarget, port);
    }
    else if (result == aes67_mdns_result_terminated){

        // ignore unknown sessions
        if (session == NULL){
            return;
        }

        u8_t msg[256];

        u16_t len = snprintf((char*)msg, sizeof(msg), AES67_SAPD_MSGU_RAV_DEL_FMT "\n", session->name);

        write_toall_except(msg, len, NULL);

        rav_session_delete(session);

        syslog(LOG_INFO, "RAV session terminated: %s@%s:%hu", name, hosttarget, port);
    }
}
#endif //AES67_SAPD_WITH_RAV == 1

static struct connection_st * connection_new(int sockfd, struct sockaddr_un * addr, socklen_t socklen)
{
    assert(sockfd > 0);
    assert(addr != NULL);
    assert(socklen > 0);
    assert(local.nconnections < AES67_SAPD_LOCAL_MAX_CONNECTIONS);

    struct connection_st * con = calloc(1, sizeof(struct connection_st));

    if (con == NULL){
        fprintf(stderr, "local calloc fail\n");
        return NULL;
    }

    local.nconnections++;

    con->sockfd = sockfd;

    con->euid = 0;
    con->egid = 0;

    getpeereid(sockfd, &con->euid, &con->egid);

    con->next = local.first_connection;

    local.first_connection = con;

    return con;
}

//static struct connection_st * connection_by_fd(int sockfd)
//{
//    struct connection_st * current = local.first_connection;
//    for(; current != NULL; current = current->next){
//        if (current->sockfd == sockfd){
//            return current;
//        }
//    }
//    return NULL;
//}

static void connection_close(struct connection_st * con)
{
    assert(con != NULL);
    assert(local.nconnections > 0);

    if (local.first_connection == con){
        local.first_connection = con->next;
    } else {
        struct connection_st * current = local.first_connection;
        for(; current != NULL; current = current->next ){
            if (current->next == con){
                current->next = con->next;
                break;
            }
        }
    }

    if (con->sockfd != -1){
        close(con->sockfd);
        con->sockfd = -1;
    }

    free(con);

    if (local.nconnections > 0){
        local.nconnections--;
    }
}

static int local_setup(const char * fname)
{
    if( access( AES67_SAPD_LOCAL_SOCK, F_OK ) == 0 ){
        syslog(LOG_ERR, "AF_LOCAL already exists: " AES67_SAPD_LOCAL_SOCK );
        return EXIT_FAILURE;
    }

    local.sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (local.sockfd < 0){
        perror ("socket(AF_LOCAL).failed");
        return EXIT_FAILURE;
    }

    local.addr.sun_family = AF_LOCAL;
    strncpy (local.addr.sun_path, AES67_SAPD_LOCAL_SOCK, sizeof (local.addr.sun_path));
    local.addr.sun_path[sizeof (local.addr.sun_path) - 1] = '\0';

    local.addr.sun_len = (offsetof (struct sockaddr_un, sun_path)
                          + strlen (local.addr.sun_path));

    if (bind (local.sockfd, (struct sockaddr *) &local.addr, local.addr.sun_len) < 0){
        close(local.sockfd);
        local.sockfd = -1;
        perror ("bind(AF_LOCAL)");
        return EXIT_FAILURE;
    }

    if (listen(local.sockfd, AES67_SAPD_LOCAL_LISTEN_BACKLOG) == -1){
        close(local.sockfd);
        local.sockfd = -1;
        remove(AES67_SAPD_LOCAL_SOCK);
        perror ("listen(AF_LOCAL)");
        return EXIT_FAILURE;
    }

    if (sock_nonblock(local.sockfd)){
        close(local.sockfd);
        local.sockfd = -1;
        remove(AES67_SAPD_LOCAL_SOCK);
        perror ("setsockopt(AF_LOCAL, nonblocking)");
        return EXIT_FAILURE;
    }

    local.nconnections = 0;
    local.first_connection = NULL;

    // change sock access rights to allow for non-sudoer access (r/w by all)
    if (chmod(AES67_SAPD_LOCAL_SOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)){
        close(local.sockfd);
        local.sockfd = -1;
        remove(AES67_SAPD_LOCAL_SOCK);
        perror ("fchmod(AF_LOCAL)");
        return EXIT_FAILURE;
    }

    syslog(LOG_NOTICE, "listen(AF_LOCAL): %s", AES67_SAPD_LOCAL_SOCK);

    return EXIT_SUCCESS;
}

static void local_teardown()
{
    if (local.sockfd != -1){
        close(local.sockfd);
        local.sockfd = -1;
    }

    if( access(AES67_SAPD_LOCAL_SOCK, F_OK ) == 0 ){
        //TODO is this generally safe??
        remove(AES67_SAPD_LOCAL_SOCK);
    }
}

static void local_accept()
{
    int sockfd;
    struct sockaddr_un addr;
    socklen_t socklen;

    if ((sockfd = accept(local.sockfd, (struct sockaddr *)&addr, &socklen)) != -1) {

        if (local.nconnections >= AES67_SAPD_LOCAL_MAX_CONNECTIONS){

            syslog(LOG_NOTICE, "Too many clients");

//            write(sockfd, ERROR_TOO_MANY_CLIENTS NL, sizeof(ERROR_TOO_MANY_CLIENTS));

            close(sockfd);
        } else {


            sock_nonblock(sockfd);

            struct connection_st * con = connection_new(sockfd, &addr, socklen);

            write(sockfd, MSG_VERSIONWELCOME "\n", sizeof(MSG_VERSIONWELCOME));

            syslog(LOG_INFO, "client connected: uid %d gid %d (count = %d)", con->euid, con->egid, local.nconnections);

            // well, shouldn't happen......
            assert(con != NULL);
        }
    }
}

static void local_process()
{
    local_accept();


    u8_t cmdline[MAX_CMDLINE];

    // check all connections if commands have been issued
    struct connection_st * con = local.first_connection;
    while(con != NULL){

        bool close_con = false;
        size_t len = 0;
        ssize_t cmdlen = -1;

        ssize_t retval;

        // attempt to read single commandline in one go
        do {
            retval = read(con->sockfd, &cmdline[len], 1);

            if (retval == 0){
                close_con = true;

//            syslog(LOG_INFO, "client discconnected:  (count = %d)", local.nconnections);
            }
            else if (retval == 1){
                // NL terminates command-line
                if (cmdline[len] == '\n'){

                    // make things simpler for parser
                    cmdline[len] = '\0';

                    if (cmdlen == -1){
                        cmdlen = len;
                    }

                    // try to match command
                    const struct cmd_st * cmd = NULL;
                    for(int i = 0; i < COMMAND_COUNT; i++){
                        if (cmdlen == commands[i].cmdlen && memcmp(cmdline, commands[i].cmd, cmdlen) == 0){
                            cmd = &commands[i];
                            break;
                        }
                    }

                    // if command (not) found
                    if (cmd == NULL){
                        write_error(con, AES67_SAPD_ERR_UNRECOGNIZED, NULL);
                    } else {
                        cmdline[len] = '\0';
                        syslog(LOG_DEBUG, "command: %s", cmdline);

                        cmd->handler(con, cmdline, len);
                    }

                    // don't break, there might be another command coming
                    // although, a very active client could thus deny service to other clients

                    // reset lengths;
                    len = 0;
                    cmdlen = -1;

                } else {
                    if (cmdline[len] == ' ' && cmdlen == -1){
                        cmdlen = len;
                    }
                    len++;
                }
            }
            else {
                // timeout, any passed data will be discarded
            }

        } while(retval > 0 && len < MAX_CMDLINE);

        if (len >= MAX_CMDLINE){
            syslog(LOG_NOTICE, "Rejecting unfriendly client");

            close_con = true;
        }

        // if closing a connection, make sure to set next before freeing memory
        if (close_con){
            struct connection_st * prev = con;
            con = con->next;

//            uid_t euid = con->euid;
//            gid_t egid = con->egid;

            connection_close(prev);

            // why does this segfault??
//            printf("client disconnected: uid %d gid %d (count = %d)\n", egid, 0, local.nconnections);
            syslog(LOG_INFO, "client disconnected: (count = %d)", local.nconnections);
        } else {
            con = con->next;
        }
    }
}

static void write_error(struct connection_st * con, const u32_t code, const char * str)
{
    char buf[256];

    const char * msg = "";
    if (str != NULL){
        msg = str;
    } else if (code < ERROR_COUNT) {
        msg = error_msg[code];
    }

    ssize_t len = snprintf(buf, sizeof(buf), AES67_SAPD_MSG_ERR_FMT "\n", code, msg);

    if (len <= 0){
        // hmmm
        return;
    }

    write(con->sockfd, buf, len);
}

static void write_ok(struct connection_st * con)
{
    write(con->sockfd, AES67_SAPD_MSG_OK "\n", sizeof(AES67_SAPD_MSG_OK));
}

static void write_toall_except(u8_t * msg, u16_t len, struct connection_st * except)
{
    struct connection_st * current = local.first_connection;

    while(current != NULL){

        if (current != except){
            write(current->sockfd, msg, len);
        }

        current = current->next;
    }
}

//static void cmd_help(struct connection_st * con, u8_t * cmdline, size_t len)
//{
//    write(con->sockfd, "+MSG help\n", sizeof("+MSG help"));
//
//    write_ok(con);
//}

static void write_list_entry(struct connection_st * con, aes67_sapsrv_session_t session, bool return_payload)
{
    u8_t buf[256 + AES67_SAPSRV_SDP_MAXLEN];
    size_t blen = 0;

    // assuming 256 is enough for first line...

    memcpy(buf, AES67_SAPD_RESULT_LIST, sizeof(AES67_SAPD_RESULT_LIST)-1);
    blen = sizeof(AES67_SAPD_RESULT_LIST)-1;

    buf[blen++] = ' ';

    u8_t managed_by = aes67_sapsrv_session_get_managedby(session);
    blen += aes67_itoa(managed_by, &buf[blen], 10);
    buf[blen++] = ' ';

    u32_t last_activity = aes67_sapsrv_session_get_lastactivity(session);
    blen += aes67_itoa(last_activity, &buf[blen], 10);
    buf[blen++] = ' ';


    u8_t *payload = NULL;
    u16_t payloadlen = 0;

    if (return_payload){
        aes67_sapsrv_session_get_payload(session, &payload, &payloadlen);
    }

    blen += aes67_itoa(payloadlen, &buf[blen], 10);
    buf[blen++] = ' ';


    struct aes67_sdp_originator * origin = aes67_sapsrv_session_get_origin(session);

    assert(origin != NULL);

    s32_t olen = aes67_sdp_origin_tostr(&buf[blen], sizeof(buf) - blen, origin);
    if (olen <= 0){
        write_error(con, AES67_SAPD_ERR, "unexpected origin tostr err");
        return;
    }
    olen -= 2; // remove CRNL
    blen += olen;

    buf[blen++] = '\n';

    if (payloadlen > 0){
        assert(payload != NULL);

        memcpy(&buf[blen], payload, payloadlen);
        blen += payloadlen;
    }

    write(con->sockfd, buf, blen);
}

static void cmd_list(struct connection_st * con, u8_t * cmdline, size_t len)
{
    bool return_payload = false;

    // check wether payload should be returned
    if (len >= sizeof(AES67_SAPD_CMD_LIST " 0")-1){
        if (cmdline[sizeof(AES67_SAPD_CMD_LIST)] == '1'){
            return_payload = true;
        } else if (cmdline[sizeof(AES67_SAPD_CMD_LIST)] == '0'){
            return_payload = false;
        } else {
            write_error(con, AES67_SAPD_ERR_SYNTAX, NULL);
            return;
        }
    }

    // if a session was specified, just return this one
    if (len >= sizeof(AES67_SAPD_CMD_LIST " 0 o")-1){
        u8_t * o = &cmdline[sizeof(AES67_SAPD_CMD_LIST " 0 o")-2];
        struct aes67_sdp_originator origin;
        if (aes67_sdp_origin_fromstr(&origin, o, len - (o - cmdline)) == AES67_SDP_ERROR){
            write_error(con, AES67_SAPD_ERR_INVALID, NULL);
            return;
        }
        aes67_sapsrv_session_t session = aes67_sapsrv_session_by_origin(sapsrv, &origin);
        if (session == NULL){
            write_error(con, AES67_SAPD_ERR_UNKNOWN, NULL);
            return;
        }

        write_list_entry(con, session, return_payload);
        write_ok(con);
        return;
    }

    aes67_sapsrv_session_t session = aes67_sapsrv_session_first(sapsrv);

    while(session != NULL){

        write_list_entry(con, session, return_payload);

        session = aes67_sapsrv_session_next(session);
    }

    write_ok(con);
}

static void cmd_set(struct connection_st * con, u8_t * cmdline, size_t len)
{
    if (len < sizeof(AES67_SAPD_CMD_SET " 1")){
        return write_error(con, AES67_SAPD_ERR_MISSING, NULL);
    }

    // prepare to read data
    u16_t sdplen_slen;
    ssize_t sdplen = aes67_atoi(&cmdline[sizeof(AES67_SAPD_CMD_SET)], len - sizeof(AES67_SAPD_CMD_SET), 10, &sdplen_slen);

    // sanity check
    if (sdplen < sizeof("v=0\no=- 1 1 IN IP4 1.1.1.1") || sdplen > AES67_SAPSRV_SDP_MAXLEN){
        if (sdplen > AES67_SAPSRV_SDP_MAXLEN) {
            write_error(con, AES67_SAPD_ERR_TOOBIG, NULL);
        } else {
            write_error(con, AES67_SAPD_ERR_INVALID, NULL);
        }

        // consume sdp data
        u8_t t;
        while(len--){
            read(con->sockfd, &t, 1);
        }

        return;
    }

    // read payload data in one go
    u8_t sdp[AES67_SAPSRV_SDP_MAXLEN];
    ssize_t rlen = read(con->sockfd, sdp, sizeof(sdp));

    if (rlen != sdplen){
        write_error(con, AES67_SAPD_ERR, "Not enough data");
        return;
    }

    // figure out origin offset ( w/ or w/o CR?
    u8_t * o = sdp[sizeof("v=0\n")] == 'o' ? &sdp[sizeof("v=0\n")] : &sdp[sizeof("v=0\r\n")];

    // parse originator
    struct aes67_sdp_originator origin;
    if (aes67_sdp_origin_fromstr(&origin, o, sdplen - (o - sdp)) == AES67_SDP_ERROR){
        write_error(con, AES67_SAPD_ERR_INVALID, "invalid originator");
        return;
    }

    // parse address (requires ip and NOT hostname)
    struct aes67_net_addr addr;
    if (aes67_net_str2addr(&addr, origin.address.data, origin.address.length) == false){
        write_error(con, AES67_SAPD_ERR, "origin must be denoted with IPv4/6");
        return;
    }

    aes67_sapsrv_session_t session = aes67_sapsrv_session_by_origin(sapsrv, &origin);

    if (session == NULL){
        // new SDP
        u16_t hash = atoi((char*)origin.session_id.data);
        session = aes67_sapsrv_session_add(sapsrv, hash, addr.ipver, addr.addr, sdp, sdplen);
    } else {
        // make sure it is a newer version.
        struct aes67_sdp_originator * sorigin = aes67_sapsrv_session_get_origin(session);
        if (aes67_sdp_origin_cmpversion(sorigin, &origin) == -1){
            aes67_sapsrv_session_update(sapsrv, session, sdp, sdplen);
        } else {
            write_error(con, AES67_SAPD_ERR, "session version is not newer");
            return;
        }
    }

    if (session == NULL){
        write_error(con, AES67_SAPD_ERR, "internal");
        return;
    }

//    o[aes67_sdp_origin_size(&origin)-2] = '\0';
//    syslog(LOG_INFO, "set %s", o);

    write_ok(con);


    // now inform all other clients that session was deleted
    u8_t buf[256];

    u16_t olen = aes67_sdp_origin_size(&origin)-2; // ignore CRNL

    // "+NEW <size> o=....\n"
    //
//    size_t blen = (sizeof(AES67_SAPD_MSGU_NEW) + 2) + sdplen_slen + (aes67_sdp_origin_size(&origin) - 2);
    size_t blen = sizeof(AES67_SAPD_MSGU_NEW)+2 + sdplen_slen + olen;


    if (blen > sizeof(buf)){
        syslog(LOG_ERR, "buf too small for " AES67_SAPD_MSGU_NEW " msg, %zu required", blen);
        return;
    }

    memcpy(buf, AES67_SAPD_MSGU_NEW, sizeof(AES67_SAPD_MSGU_NEW)-1);
    blen = sizeof(AES67_SAPD_MSGU_NEW)-1;

    buf[blen++] = ' ';

    // copy sdplen
    memcpy(&buf[blen], &cmdline[sizeof(AES67_SAPD_CMD_SET)], sdplen_slen);
    blen += sdplen_slen;

    buf[blen++] = ' ';

    memcpy(&buf[blen], o, olen);
    blen += olen;

    buf[blen++] = '\n';

    // also add sdp payload
//    memcpy(&buf[blen], sdp, sdplen);
//    blen += sdplen;

    write_toall_except(buf, blen, con);

    write_toall_except(sdp, sdplen, con);
}

static void cmd_unset(struct connection_st * con, u8_t * cmdline, size_t len)
{
    if (len < sizeof(AES67_SAPD_CMD_UNSET " o=- 1 1 IN IP4 1.2.3.4")){
        write_error(con, AES67_SAPD_ERR_SYNTAX, NULL);
        return;
    }

    // try to parse given originator
    struct aes67_sdp_originator origin;
    // note sizeof(..) gives length of string + 1 (terminating null)
    if (aes67_sdp_origin_fromstr(&origin, &cmdline[sizeof(AES67_SAPD_CMD_UNSET)], len - sizeof(AES67_SAPD_CMD_UNSET)) == AES67_SDP_ERROR){
        write_error(con, AES67_SAPD_ERR_SYNTAX, "Invalid origin");
        return;
    }

    // lookup session
    aes67_sapsrv_session_t session = aes67_sapsrv_session_by_origin(sapsrv, &origin);
    if (session == NULL){
        write_error(con, AES67_SAPD_ERR_UNKNOWN, NULL);
        return;
    }

    if (aes67_sapsrv_session_get_managedby(session) != AES67_SAPSRV_MANAGEDBY_LOCAL){
        write_error(con, AES67_SAPD_ERR, "Not a locally managed service");
        return;
    }

    // delete session
    aes67_sapsrv_session_delete(sapsrv, session);

    write_ok(con);

    // now inform all other clients that session was deleted
    u8_t buf[256];

    // "+DEL o=....\n"
    size_t blen = (sizeof(AES67_SAPD_MSGU_DELETED) + 1) + (len - sizeof(AES67_SAPD_CMD_UNSET));

    if (blen > sizeof(buf)){
        syslog(LOG_ERR, "buf too small for " AES67_SAPD_MSGU_DELETED " msg, %zu required", blen);
        return;
    }

    memcpy(buf, AES67_SAPD_MSGU_DELETED, sizeof(AES67_SAPD_MSGU_DELETED)-1);
    buf[sizeof(AES67_SAPD_MSGU_DELETED)-1] = ' ';
    memcpy(&buf[sizeof(AES67_SAPD_MSGU_DELETED)], &cmdline[sizeof(AES67_SAPD_CMD_UNSET)], len - sizeof(AES67_SAPD_CMD_UNSET));
    buf[blen-1] = '\n';

    write_toall_except(buf, blen, con);
}



int main(int argc, char * argv[]){

    argv0 = argv[0];

    // parse options
    while (1) {
        int c;

        int option_index = 0;
        static struct option long_options[] = {
                {"daemonize",  no_argument,       0,  'd' },
                {"l4g", no_argument, 0, 1},
                {"l4a", no_argument, 0, 2},
                {"l6ll", no_argument, 0, 3},
                {"l6al", no_argument, 0, 4},
                {"l6ip4", no_argument, 0, 5},
                {"l6sl", no_argument, 0, 6},
                {"s4g", no_argument, 0, 7},
                {"s4a", no_argument, 0, 8},
                {"s6ll", no_argument, 0, 9},
                {"s6ip4", no_argument, 0, 10},
                {"s6al", no_argument, 0, 11},
                {"s6sl", no_argument, 0, 12},
                {"port", required_argument, 0, 'p'},
                {"ipv6-if", required_argument, 0, 13},
#if AES67_SAPD_WITH_RAV == 1
                {"rav", no_argument, 0, 14},
                {"rav-pub-delay", required_argument, 0, 15},
                {"rav-upd-interval", required_argument, 0, 16},
#endif
                {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "?hvdp:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 1: // --l4gl
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv4_GLOBAL;
                break;

            case 2: // --l4al
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED;
                break;

            case 3: // --l6ll
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL;
                break;

            case 4: // --l6ip4
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv6_IPv4;
                break;

            case 5: // --l6al
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL;
                break;

            case 6: // --l6sl
                opts.listen_scopes |= AES67_SAPSRV_SCOPE_IPv6_SITELOCAL;
                break;

            case 7: // --l4gl
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv4_GLOBAL;
                break;

            case 8: // --l4al
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv4_ADMINISTERED;
                break;

            case 9: // --l6ll
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv6_LINKLOCAL;
                break;

            case 10: // --l6ip4
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv6_IPv4;
                break;

            case 11: // --l6al
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv6_ADMINLOCAL;
                break;

            case 12: // --l6sl
                opts.send_scopes |= AES67_SAPSRV_SCOPE_IPv6_SITELOCAL;
                break;

            case 13: // ipv6-if
                opts.ipv6_if = if_nametoindex(optarg);
                break;

#if AES67_SAPD_WITH_RAV == 1
            case 14: // --rav
                opts.rav_enabled = true;
                break;

            case 15: {// --rav-pub-delay
                int i = atoi(optarg);
                if (i < 0 || RAV_MAX_PUBLISH_DELAY < i) {
                    fprintf(stderr, "Invalid --rav-pub-delay must be in 0 .. %d", RAV_MAX_PUBLISH_DELAY);
                    return EXIT_FAILURE;
                }
                opts.rav_publish_delay = i;
                break;
            }

            case 16: {// --rav-upd-interval
                int i = atoi(optarg);
                if (i < 0 || RAV_MAX_UPDATE_INTERVAL < i){
                    fprintf(stderr, "Invalid --rav-upd-interval must be in 0 .. %d", RAV_MAX_UPDATE_INTERVAL);
                    return EXIT_FAILURE;
                }
                opts.rav_update_interval = i;
                break;
            }
#endif
            case 'd':
                opts.daemonize = true;
                break;

            case 'p': {
                int p = atoi(optarg);
                if (p <= 0 || (p & 0xffff) != p) {
                    fprintf(stderr, "Invalid port\n");
                    return EXIT_FAILURE;
                }
                opts.port = p;
                break;
            }

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

    // no additional arguments allowed
    if ( optind != argc ){
        fprintf(stderr, "Invalid arg count\n");
        return EXIT_FAILURE;
    }

    if ( opts.listen_scopes == 0){
        opts.listen_scopes = DEFAULT_LISTEN_SCOPES;
    }
    if ( opts.send_scopes == 0){
        opts.send_scopes = DEFAULT_SEND_SCOPES;
    }

    int syslog_option = AES67_SAPD_SYSLOG_OPTION | (opts.verbose ? LOG_PERROR : 0);
    openlog(AES67_SAPD_SYSLOG_IDENT,  syslog_option, AES67_SAPD_SYSLOG_FACILITY);

    if (opts.daemonize){
        aes67_daemonize();
    }

    syslog(LOG_INFO, "starting");

    if (local_setup(AES67_SAPD_LOCAL_SOCK)){
        syslog(LOG_ERR, "Failed to open AF_LOCAL sock: " AES67_SAPD_LOCAL_SOCK);
        return EXIT_FAILURE;
    }

    if (sapsrv_setup()){
        local_teardown();
        return EXIT_FAILURE;
    }

#if AES67_SAPD_WITH_RAV == 1
    if (opts.rav_enabled && rav_setup()){
        syslog(LOG_ERR, "Failed to start mdns resolver");
        sapsrv_teardown();
        local_teardown();
        return EXIT_FAILURE;
    }
#endif //AES67_SAPD_WITH_RAV == 1

    syslog(LOG_INFO, "started");

    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){
        block_until_event();

        local_process();
        aes67_sapsrv_process(sapsrv);

#if AES67_SAPD_WITH_RAV == 1
        if (opts.rav_enabled){
            rav_process();
        }
#endif
    }

    syslog(LOG_INFO, "stopping");

#if AES67_SAPD_WITH_RAV == 1
    if (opts.rav_enabled){
        rav_teardown();
    }
#endif

    sapsrv_teardown();

    local_teardown();

    syslog(LOG_INFO, "stopped");

    return EXIT_SUCCESS;
}