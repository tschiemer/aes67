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

#define AES67_SAPD_ERROR            0
#define AES67_SAPD_ERR_UNRECOGNIZED 1
#define AES67_SAPD_ERR_MISSING      2
#define AES67_SAPD_ERR_SYNTAX       3

#define AES67_SAPD_MSG_OK           "OK"
#define AES67_SAPD_MSG_ERR          "ERR"
#define AES67_SAPD_MSG_ERR_FMT      "ERR %d %s"

#define AES67_SAPD_MSGU             "+MSG"
#define AES67_SAPD_MSGU_DISCVRD     "+NEW"
#define AES67_SAPD_MSGU_DISCVRD_FMT "+NEW %d o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_UPDATED     "+UPD"
#define AES67_SAPD_MSGU_UPDATED_FMT "+UPD %d o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_DELETED     "+DEL"
#define AES67_SAPD_MSGU_DELETED_FMT "+DEL o=%s %s %s IN IP%d %s"
#define AES67_SAPD_MSGU_TIMEOUT     "+TMT"
#define AES67_SAPD_MSGU_TIMEOUT_FMT "+TMT o=%s %s %s IN IP%d %s"

#define AES67_SAPD_CMD_HELP         "help"
#define AES67_SAPD_CMD_LIST         "ls"
#define AES67_SAPD_CMD_LIST_FMT     "ls %d %d"
#define AES67_SAPD_CMD_SET          "set"
#define AES67_SAPD_CMD_SET_FMT      "set %d"
#define AES67_SAPD_CMD_UNSET        "unset"
#define AES67_SAPD_CMD_UNSET_FMT    "unset o=%s %s %s IN IP%d %s"

#define AES67_SAPD_RESULT_LIST      "LS"
#define AES67_SAPD_RESULT_LIST_FMT  "LS o=%s %s %s IN IP%d %s"


#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_SAPD_H
