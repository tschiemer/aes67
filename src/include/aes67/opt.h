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


#ifndef AES67_OPT_H
#define AES67_OPT_H

#define AES67_MEMORY_POOL       1
#define AES67_MEMORY_DYNAMIC    2

/*
 * Include user defined options first. Anything not defined in these files
 * will be set to standard values. Override anything you don't like!
 */
#include "aes67opts.h"

/****** Core - Host *******/

#ifndef AES67_TIMESTAMP_TYPE
#define AES67_TIMESTAMP_TYPE uint32_t
#endif


/****** Core - Net *******/

#ifndef AES67_USE_IPv6
#define AES67_USE_IPv6 1
#endif

/****** Session Announcement Protocol (SAP) *******/

#ifndef AES67_SAP_MEMORY
#define AES67_SAP_MEMORY    AES67_MEMORY_POOL
#endif

#ifndef AES67_SAP_MEMORY_MAX_SESSIONS
#define AES67_SAP_MEMORY_MAX_SESSIONS 32
#endif

#ifndef AES67_SAP_AUTH_ENABLED
#define AES67_SAP_AUTH_ENABLED 0
#endif

#ifndef AES67_SAP_AUTH_SELF
#define AES67_SAP_AUTH_SELF 0
#endif

#ifndef AES67_SAP_DECOMPRESS_AVAILABLE
#define AES67_SAP_DECOMPRESS_AVAILABLE 0
#endif

#ifndef AES67_SAP_COMPRESS_ENABLED
#define AES67_SAP_COMPRESS_ENABLED 0
#endif


/******* Session Description Protocol (SDP) ********/

#ifndef AES67_SDP_MAXUSERNAME
#define AES67_SDP_MAXUSERNAME 32
#endif

// MAX_UINT64 (ntpv3) has a digit-count of 20 (ie. 18,446,744,073,709,551,615)
// MAX_UINT128 (ntpv4) has a digit-count of 39 (ie. 340,282,366,920,938,463,463,374,607,431,768,211,455)
#ifndef AES67_SDP_MAXSESSIONID
#define AES67_SDP_MAXSESSIONID 40
#endif

#ifndef AES67_SDP_MAXSESSIONVERSION
#define AES67_SDP_MAXSESSIONVERSION 40
#endif

#ifndef AES67_SDP_MAXADDRESS
#define AES67_SDP_MAXADDRESS 64
#endif

#ifndef AES67_SDP_MAXSESSIONNAME
#define AES67_SDP_MAXSESSIONNAME 32
#endif

#ifndef AES67_SDP_MAXSESSIONINFO
#define AES67_SDP_MAXSESSIONINFO 64
#endif

#ifndef AES67_SDP_MAXSTREAMINFO
#define AES67_SDP_MAXSTREAMINFO AES67_SDP_MAXSESSIONINFO
#endif

#ifndef AES67_SDP_MAXCONNECTIONS
#define AES67_SDP_MAXCONNECTIONS 5
#endif

#ifndef AES67_SDP_MAXPTPS
#define AES67_SDP_MAXPTPS 5
#endif

#ifndef AES67_SDP_MAXSTREAMS
#define AES67_SDP_MAXSTREAMS 5
#endif

#ifndef AES67_SDP_MAXENCODINGS
#define AES67_SDP_MAXENCODINGS 5
#endif

#ifndef AES67_SDP_MAXPTIMECAPS
#define AES67_SDP_MAXPTIMECAPS 4
#endif

#ifndef AES67_SDP_TOOL_ENABLED
#define AES67_SDP_TOOL_ENABLED 1
#endif

#ifndef AES67_SDP_TOOL
#define AES67_SDP_TOOL "caes67"
#endif

/****** Session Announcement Protocol (SAP) *******/

#ifndef AES67_RTP_MAXCHANNELS
#define AES67_RTP_MAXCHANNELS 8
#endif

#endif //AES67_OPT_H
