/**
 * @file sapd.h
 * SAP daemon defines, in particular as used for/by local clients.
 */

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

#ifndef AES67_UTILS_SAPD_H
#define AES67_UTILS_SAPD_H

#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef AES67_SAPD_WITH_RAV
#define AES67_SAPD_WITH_RAV  1
#endif


#define AES67_SAPD_NAME        "sapd"
#define AES67_SAPD_VERSION     "0.1.0"

#define AES67_SAPD_NAME_LONG   AES67_SAPD_NAME "-" AES67_SAPD_VERSION

#define AES67_SAPD_SYSLOG_IDENT     AES67_SAPD_NAME
#define AES67_SAPD_SYSLOG_OPTION    0
#define AES67_SAPD_SYSLOG_FACILITY  LOG_DAEMON

//#define AES67_SAPD_LOCAL_SOCK     "/var/run/sapd.sock"
#define AES67_SAPD_LOCAL_SOCK      "sapd.sock"
#define AES67_SAPD_LOCAL_LISTEN_BACKLOG    3
#define AES67_SAPD_LOCAL_MAX_CONNECTIONS   10

#define AES67_SAPD_ERR              0
#define AES67_SAPD_ERR_UNRECOGNIZED 1
#define AES67_SAPD_ERR_MISSING      2
#define AES67_SAPD_ERR_SYNTAX       3
#define AES67_SAPD_ERR_UNKNOWN      4
#define AES67_SAPD_ERR_TOOBIG       5
#define AES67_SAPD_ERR_INVALID      6
#define AES67_SAPD_ERR_NOTENABLED   7

#define AES67_SAPD_MSG_OK           "OK"

#define AES67_SAPD_MSG_ERR          "ERR"
#define AES67_SAPD_MSG_ERR_FMT      "ERR %d %s"

/**
 * Unsolicited messages (informing about updates)
 *
 * INFO     general info that can be taken note of (or not)
 * NEW      there is a new session (either added by another client or discovered)
 * UPD      there is an updated SDP for a session
 * DEL      a session was explicitly deleted
 * TMT      a timeout for a session occurred, treat like deleted
 */
#define AES67_SAPD_MSGU_INFO        "+INFO"
#define AES67_SAPD_MSGU_NEW         "+NEW"
#define AES67_SAPD_MSGU_NEW_FMT     "+NEW %d o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_UPDATED     "+UPD"
#define AES67_SAPD_MSGU_UPDATED_FMT "+UPD %d o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_DELETED     "+DEL"
#define AES67_SAPD_MSGU_DELETED_FMT "+DEL o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_TIMEOUT     "+TMT"
#define AES67_SAPD_MSGU_TIMEOUT_FMT "+TMT o=%s %s %s IN IP%d %s"

#define AES67_SAPD_MSGU_DUPLICATE   "+DUP"
#define AES67_SAPD_MSGU_DUPLICATE_FMT "+DUP o=%s %s %s IN IP%d %s"

#define AES67_SAPD_MSGU_RAV_NEW     "+RAVNEW"
#define AES67_SAPD_MSGU_RAV_NEW_FMT "+RAVNEW %s %s %d %s"
#define AES67_SAPD_MSGU_RAV_DEL     "+RAVDEL"
#define AES67_SAPD_MSGU_RAV_DEL_FMT "+RAVDEL %s"


/**
 * LIST known SDPs
 *
 * Command: ls [SPACE <return-sdp> [SPACE <origin>]] NL
 *  <return-sdp>    0 (default) do not return, 1 do return -> if 0 implies returned <sdp-len> = 0
 *  <origin>        If given will only return matching session
 *
 * On success returns a series of LS items (see below) terminated by an OK (NL)
 *
 * LS <managed-by> <last-activity> <sdp-len> <origin> NL [<sdp>]
 *  <managed-by>    AES67_SAPSRV_MANAGEDBY_LOCAL | AES67_SAPSRV_MANAGEDBY_REMOTE
 *  <last-activity> timestamp
 *  <sdp-len>       length of sdp payload which follows terminating NL
 *  <origin>        SDP conform originator-line (without CRNL)
 *  <sdp>           SDP payload (only given if <sdp-len> is greater than 0), with exact length of <sdp-len> bytes
 */
#define AES67_SAPD_CMD_LIST         "ls"
#define AES67_SAPD_CMD_LIST_V_FMT   "ls %d"
//#define AES67_SAPD_CMD_LIST_VM_FMT  "ls %d %d"
#define AES67_SAPD_RESULT_LIST      "LS"
#define AES67_SAPD_RESULT_LIST_FMT  "LS %d %d %d o=%s %s %s IN IP%d %s"

/**
 * Add or update a locally administered SDP
 *
 * Command: set <sdp-len> NL <sdp>
 *
 * On success returns OK (NL)
 */
#define AES67_SAPD_CMD_SET          "set"
#define AES67_SAPD_CMD_SET_FMT      "set %d"


/**
 * Delete a locally administered SDP
 *
 * Command: unset <origin>
 *
 * On success returns OK (NL)
 * Informs any other connected clients through an unsolicited DELETED message
 */
#define AES67_SAPD_CMD_UNSET        "unset"
#define AES67_SAPD_CMD_UNSET_FMT    "unset o=%s %s %s IN IP%d %s"


/**
 * Handover authority of a locally managed session to remote devices
 * Implies unpublishing of rav session
 *
 * Command: handover <origin>
 *
 * On success returns OK (NL)
 * Informas any other connections clients through an unsolicited INFO message
 */
#define AES67_SAPD_CMD_HANDOVER     "handover"
#define AES67_SAPD_CMD_HANDOVER_FMT "handover o=%s %s %s IN IP%d %s"

/**
 * Takeover authority of a session announced by a remote device
 *
 * Command: handover <origin>
 *
 * On success returns OK (NL)
 * Informas any other connections clients through an unsolicited INFO message
 */
#define AES67_SAPD_CMD_TAKEOVER     "takeover"
#define AES67_SAPD_CMD_TAKEOVER_FMT "takeover o=%s %s %s IN IP%d %s"

/**
 * RAVLIST known ravenna sessions
 *
 * Command: ravls [SPACE <return-sdp> [SPACE <session-name>]] NL
 *  <return-sdp>    0 (default) do not return, 1 do return -> if 0 implies returned <sdp-len> = 0
 *  <origin>        If given will only return matching session
 *
 * On success returns a series of RAVLS items (see below) terminated by an OK (NL)
 *
 * RAVLS SPACE <state> SPACE <last-activity> SPACE <sdp-len> SPACE <hosttarget> SPACE <port> SPACE <ipv4> SPACE <session-name> NL [<sdp>]
 *
 *  <state>             (also see enum rav_state in sapd.c)
 *                          0   error (inactive)
 *                          1   discovered but no sdp yet
 *                          2   discovered and available sdp but not yet published through SAP
 *                          3   published through SAP
 *                          (4  published + updated (note, this is an transitory state and should be treated like 3)
 *                          5   not published (ie inactive), most likely because was announced through SAP by another host
 *  <last-activity>     typical timestamp in sec from last update
 *  <sdp-len>           length of sdp payload which follows terminating NL
 *  <hosttarget>        hostname as discovered through mdns
 *  <port>              port of rtsp service
 *  <ipv4-str>          parsable IPv4 string
 *  <session-name>      (unique) ravenna session name (can contain spaces)
 *  <sdp>               SDP payload (only given if <sdp-len> is greater than 0), with exact length of <sdp-len> bytes
 */
#define AES67_SAPD_CMD_RAV_LIST         "ravls"
//#define AES67_SAPD_CMD_RAV_LIST_FMT     "ravls %d %s"
#define AES67_SAPD_RESULT_RAV_LIST      "RAVLS"
#define AES67_SAPD_RESULT_RAV_LIST_FMT  "RAVLS %d %d %s %s"


#define AES67_SAPD_CMD_RAV_PUBLISH      "ravpub"
#define AES67_SAPD_CMD_RAV_PUBLISH_FMT  "ravpub %s"
#define AES67_SAPD_CMD_RAV_UNPUBLISH    "ravunpub"
#define AES67_SAPD_CMD_RAV_UNPUBLISH_FMT "ravunpub %s"
#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_SAPD_H
