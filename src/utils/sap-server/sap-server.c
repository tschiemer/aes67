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

#include "aes67/utils/sapsrv.h"

#include "aes67/sap.h"

#include <stdlib.h>
#include <signal.h>
//#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#define SYSLOG_KEY      "sap-server"
#define SYSLOG_FACILITY 0

//#define LOCAL_DEFAULT_FNAME     "/var/run/sap-server"
#define LOCAL_DEFAULT_FNAME     "sap-server.sock"
#define LOCAL_LISTEN_BACKLOG    10
#define LOCAL_MAX_CONNECTIONS   10

#define BUFSIZE 1024

#define CMD_HELP    "help"
#define CMD_LIST    "ls"
#define CMD_GET     "get"
#define CMD_ADD     "add"
#define CMD_DELETE  "delete"

#define OK                  "OK"
#define ERROR_GENERAL       "ERROR 0 General"
#define ERROR_UNKNOWN_CMD   "ERROR 0 Unknown command"
//#define ERROR_
#define NL                  "\n"


struct connection_st {
    int sockfd;
    struct sockaddr_un addr;
    socklen_t socklen;

    struct connection_st * next;
};

static volatile bool keep_running;

static struct {
    char * local_fname;
    bool verbose;
} opts;

const static char default_fname[] = LOCAL_DEFAULT_FNAME;

static char * argv0;

static struct {
    int sockfd;
    struct sockaddr_un addr;

    int nconnections;
    struct connection_st * first_connection;
} local;

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

void local_help(int sockfd){
    write(sockfd,
            "HELP \n", sizeof("HELP ")

            );
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
    assert(local.nconnections < LOCAL_MAX_CONNECTIONS);

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

static int local_setup(char * fname)
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

    if (listen(local.sockfd, LOCAL_LISTEN_BACKLOG) == -1){
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

        if (local.nconnections >= LOCAL_MAX_CONNECTIONS){
            printf("too many connections! rejecting\n");
            close(sockfd);
        } else {

            sock_nonblock(sockfd);

            struct connection_st * con = connection_new(sockfd, &addr, socklen);

            printf("accepted! now %d\n", local.nconnections);

            // well, shouldn't happen......
            assert(con != NULL);
        }
    }
}

static void local_process_rx(struct connection_st * con, u8_t * buf, size_t len)
{
    assert(con != NULL);
    assert(buf != NULL);
    assert(len > 0);

    // use local buffer ???

//    printf("rx %zu ", len);
//
//    for(int i = 0; i < len; i++){
//        printf("%02x", buf[i]);
//    }
//
//    printf("\n");

    // discard meaningsless...
    if (len < 2){
        return;
    }

    u8_t * eol = memchr(buf+1, '\n', len-1);
    if (eol == NULL){
        return;
    }
    size_t linelen = eol - buf;

//    printf("linelen = %d %d\n", linelen, sizeof(CMD_LIST)-1);

    size_t contentlen = 0;
    if (linelen >= sizeof(CMD_HELP)-1 && memcmp(CMD_HELP, buf, sizeof(CMD_HELP)-1) == 0) {
        local_help(con->sockfd);
    }
    else if (linelen >= sizeof(CMD_LIST)-1 && memcmp(CMD_LIST, buf, sizeof(CMD_LIST)-1) == 0) {
        // TODO list all SDPs by origin only (?)
    }
    else if (linelen >= sizeof(CMD_GET " o=- 1 1 IN IP4 1.2.3.4") && memcmp(CMD_GET " o=", buf, sizeof(CMD_LIST" o=")-1) == 0) {
        // TODO list all SDPs
    }
    else if (linelen >= sizeof(CMD_ADD " ") && sscanf((char*)buf, CMD_ADD " %zu", &contentlen) == 1){
        // TODO Register new SDP
    }
    else if (linelen >= sizeof(CMD_DELETE " o=- 1 1 IN IP4 1.2.3.4")+1 && memcmp(buf, CMD_DELETE " o=", sizeof(CMD_DELETE " o=")-1) == 0){
        // TODO list all SDPs
    }
    else {
        write(con->sockfd, ERROR_UNKNOWN_CMD "\n", sizeof(ERROR_UNKNOWN_CMD));
        return;
    }


    write(con->sockfd, OK "\n", sizeof(OK));
    // echo back
}

static void local_process()
{
    local_accept();


    u8_t buf[BUFSIZE];

    struct connection_st * con = local.first_connection;

    for(;con != NULL; con = con->next){

        // set to nonbblock in local_accept()
        ssize_t retval = read(con->sockfd, buf, sizeof(buf));

        if (retval == 0){
            printf("closed!\n");
            connection_close(con);
        } else if (retval > 0){
            local_process_rx(con, buf, retval);
        }
    }
}

static void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sap_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data)
{
    printf("sapsrv callback: %d\n", event);
}

int main(int argc, char * argv[]){

    argv0 = argv[0];

    opts.local_fname = (char*)default_fname;
    opts.verbose = false;

    if (local_setup(opts.local_fname)){
        return EXIT_FAILURE;
    }


    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){
        local_process();
    }

    local_teardown();

    return EXIT_SUCCESS;

    aes67_time_init_system();
    aes67_timer_init_system();

    struct aes67_net_addr listen_addr = {
         .ipver = aes67_net_ipver_4,
         .addr = AES67_SAP_IPv4,
         .port = AES67_SAP_PORT
    };
    struct aes67_net_addr iface_addr = {
         .ipver = aes67_net_ipver_4,
         .addr = {192,168,2,138},
         .port = 0
    };
    aes67_sapsrv_t * sapsrv = aes67_sapsrv_start(&listen_addr, NULL, sapsrv_callback, NULL);

    if (sapsrv == NULL){
     printf("err\n");
     return EXIT_FAILURE;
    }

    aes67_sapsrv_setblocking(sapsrv, false);

    signal(SIGINT, sig_int);
    keep_running = true;
    while(keep_running){

     aes67_sapsrv_process(sapsrv);
    }

    aes67_sapsrv_stop(sapsrv);

    aes67_timer_deinit_system();
    aes67_time_deinit_system();

    return EXIT_SUCCESS;
}