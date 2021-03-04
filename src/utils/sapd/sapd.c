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

#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

//#define BUFSIZE 1024
#define MAX_CMDLINE 256

#define MSG_VERSIONWELCOME         AES67_SAPD_MSGU " " AES67_SAPD_NAME_LONG


struct connection_st {
    int sockfd;
    struct sockaddr_un addr;
    socklen_t socklen;

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

static struct connection_st * connection_new(int sockfd, struct sockaddr_un * addr, socklen_t socklen);
static void connection_close(struct connection_st * con);

static int sock_nonblock(int sockfd);

static int local_setup(const char * fname);
static void local_teardown();
static void local_accept();
static void local_process();

static int sapsrv_setup();
static void sapsrv_teardown();
static void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sap_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data);

static void write_error(struct connection_st * con, const u32_t code, const char * str);
static void write_ok(struct connection_st * con);

static void cmd_help(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_list(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_add(struct connection_st * con, u8_t * cmdline, size_t len);
static void cmd_delete(struct connection_st * con, u8_t * cmdline, size_t len);

static const struct cmd_st commands[] = {
        CMD_INIT(AES67_SAPD_CMD_HELP, cmd_help),
        CMD_INIT(AES67_SAPD_CMD_LIST, cmd_list),
        CMD_INIT(AES67_SAPD_CMD_ADD, cmd_add),
        CMD_INIT(AES67_SAPD_CMD_DELETE, cmd_delete)
};

#define COMMAND_COUNT (sizeof(commands) / sizeof(struct cmd_st))

static const char * error_msg[] = {
  "Generic error",          // AES67_SAPD_ERROR
  "Unrecognized command",   // AES67_SAPD_ERR_UNRECOGNIZED
  "Missing args",           // AES67_SAPD_ERR_MISSING
  "Syntax error",           // AES67_SAPD_ERR_SYNTAX
};

#define ERROR_COUNT (sizeof(error_msg) / sizeof(char *))


static struct {
    bool daemonize;
    bool verbose;
    s32_t port;
    struct aes67_net_addr listen_addr;
    struct aes67_net_addr iface_addr;
} opts = {
    .daemonize = false,
    .verbose = false,
    .port = -1,
    .listen_addr = {
            .ipver = aes67_net_ipver_4,
            .addr = AES67_SAP_IPv4,
            .port = AES67_SAP_PORT
    },
    .iface_addr = {
        .ipver = aes67_net_ipver_undefined
    }
};

static char * argv0;

static volatile bool keep_running;

static struct {
    int sockfd;
    struct sockaddr_un addr;

    int nconnections;
    struct connection_st * first_connection;
} local;

aes67_sapsrv_t * sapsrv = NULL;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s [-h|-?] | [-d] [-l<listen-ip>[:<port>]] [-p<port>] [--if<iface-ip>]\n"
             "Starts an (SDP-only) SAP server that maintains incoming SDPs, informs about updates and takes care publishing"
             "specified SDPs.\n"
             "Communicates through local port (AF_LOCAL)\n"
             "Note: this is not a hardened server.\n"
             "Options:\n"
             "\t -h,-?\t\t Prints this info.\n"
             "\t -d\t\t Daemonize bwahahaha (and print to syslog if -v)\n"
             "\t -l <listen-ip>[:<port>]\n"
             "\t\t\t\t\t IPv4/6 and optional port of particular ip/port to listen to. (default 224.2.127.254:9875)\n"
             "\t\t\t\t\t If not given"
             "\t -p <port>\t Force this hash id (if not given tries to extract from SDP file, session id)\n"
             "\t --if<iface-ip>\t IP of interface to use (default -> \"default interface\")\n"
             "\t -v\t\t Print some basic info to STDERR\n"
             "Examples:\n"
            , argv0);
}

static void sig_int(int sig)
{
    keep_running = false;
}

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

static int sock_nonblock(int sockfd){
    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1){
        fprintf(stderr, "local. Couldn't change non-/blocking\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int local_setup(const char * fname)
{
    if( access( fname, F_OK ) == 0 ){
        fprintf(stderr, "local file exists, another server running?\n");
        return EXIT_FAILURE;
    }

    local.sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (local.sockfd < 0){
        perror ("local.socket().failed");
        return EXIT_FAILURE;
    }

    local.addr.sun_family = AF_LOCAL;
    strncpy (local.addr.sun_path, fname, sizeof (local.addr.sun_path));
    local.addr.sun_path[sizeof (local.addr.sun_path) - 1] = '\0';

    local.addr.sun_len = (offsetof (struct sockaddr_un, sun_path)
                                 + strlen (local.addr.sun_path));

    if (bind (local.sockfd, (struct sockaddr *) &local.addr, local.addr.sun_len) < 0){
        close(local.sockfd);
        local.sockfd = -1;
        perror ("local.bind()");
        return EXIT_FAILURE;
    }

    if (listen(local.sockfd, AES67_SAPD_LOCAL_LISTEN_BACKLOG) == -1){
        close(local.sockfd);
        local.sockfd = -1;
        return EXIT_FAILURE;
    }

    if (sock_nonblock(local.sockfd)){
        close(local.sockfd);
        local.sockfd = -1;
        return EXIT_FAILURE;
    }

    local.nconnections = 0;
    local.first_connection = NULL;

    return EXIT_SUCCESS;
}

static void local_teardown()
{
    if (local.sockfd != -1){
        return;
    }

    close(local.sockfd);
    local.sockfd = -1;
}

static void local_accept()
{
    int sockfd;
    struct sockaddr_un addr;
    socklen_t socklen;

    if ((sockfd = accept(local.sockfd, (struct sockaddr *)&addr, &socklen)) != -1) {

        if (local.nconnections >= AES67_SAPD_LOCAL_MAX_CONNECTIONS){

            //TODO log

//            write(sockfd, ERROR_TOO_MANY_CLIENTS NL, sizeof(ERROR_TOO_MANY_CLIENTS));

            close(sockfd);
        } else {

            sock_nonblock(sockfd);

            struct connection_st * con = connection_new(sockfd, &addr, socklen);

            write(sockfd, MSG_VERSIONWELCOME "\n", sizeof(MSG_VERSIONWELCOME));

            printf("accepted! now %d\n", local.nconnections);

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
                printf("closed!\n");
                close_con = true;
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
            printf("unfriendly client, closing!\n");
            close_con = true;
        }

        // if closing a connection, make sure to set next before freeing memory
        if (close_con){
            struct connection_st * prev = con;
            con = con->next;
            connection_close(prev);
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

static void cmd_help(struct connection_st * con, u8_t * cmdline, size_t len)
{
    write(con->sockfd, "+MSG help\n", sizeof("+MSG help"));

    write_ok(con);
}

static void cmd_list(struct connection_st * con, u8_t * cmdline, size_t len)
{
    //TODO for each (SDP) session print data

    write_ok(con);
}

static void cmd_add(struct connection_st * con, u8_t * cmdline, size_t len)
{
    if (len < sizeof(AES67_SAPD_CMD_ADD " 1")){
        return write_error(con, AES67_SAPD_ERR_MISSING, NULL);
    }

    write_ok(con);
}

static void cmd_delete(struct connection_st * con, u8_t * cmdline, size_t len)
{
    write_ok(con);
}

static int sapsrv_setup()
{
    aes67_time_init_system();
    aes67_timer_init_system();

    //TODO iface_addr
    sapsrv = aes67_sapsrv_start(&opts.listen_addr, NULL, sapsrv_callback, NULL);

    if (sapsrv == NULL){
        fprintf(stderr, "Failed to start sapsrv\n");

        aes67_timer_deinit_system();
        aes67_time_deinit_system();

        return EXIT_FAILURE;
    }

    aes67_sapsrv_setblocking(sapsrv, false);

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

static void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sap_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data)
{
    printf("sapsrv callback: %d\n", event);


    //TODO inform all clients
}

int main(int argc, char * argv[]){

    argv0 = argv[0];

    //TODO getopt


    if (opts.daemonize){
        if (aes67_daemonize()){
            fprintf(stderr, "Failed to daemonize.");
            return EXIT_FAILURE;
        }
    }

    if (local_setup(AES67_SAPD_LOCAL_SOCK)){
        return EXIT_FAILURE;
    }

    if (sapsrv_setup()){
        local_teardown();
        return EXIT_FAILURE;
    }

    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){
        local_process();
        aes67_sapsrv_process(sapsrv);
    }

    sapsrv_teardown();

    local_teardown();

    return EXIT_SUCCESS;
}