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


/*
 * Include user defined options first. Anything not defined in these files
 * will be set to standard values. Override anything you don't like!
 */
#include "aes67opts.h"

#ifndef AES67_USE_IPv6
#define AES67_USE_IPv6 1
#endif

#ifndef AES67_SDP_MAXUSERNAME
#define AES67_SDP_MAXUSERNAME 32
#endif

#ifndef AES67_SDP_MAXSESSIONID
#define AES67_SDP_MAXSESSIONID 20
#endif

#ifndef AES67_SDP_MAXSESSIONVERSION
#define AES67_SDP_MAXSESSIONVERSION 20
#endif

#ifndef AES67_SDP_MAXSESSIONNAME
#define AES67_SDP_MAXSESSIONNAME 32
#endif

#ifndef AES67_SDP_MASSESSIONINFO
#define AES67_SDP_MASSESSIONINFO 64
#endif

#ifndef AES67_SDP_MAXCONNECTIONDATA
#define AES67_SDP_MAXCONNECTIONDATA 1
#endif


#endif //AES67_OPT_H
