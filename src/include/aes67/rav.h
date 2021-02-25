/**
 * @file rav.h
 * Utilities/defines for interaction with RAVENNA systems
 *
 * References:
 * RAVENNA Operating Principles (Draft 1.0 2011-06-01, final), ALC NetworX GmbH
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

/**
 * mDNS Services + URLs
 * Receiving devices typically use a http service.
 * Sending devices typically use an rtsp service.
 *
 * mDNS registration is then twofold:
 * 1. for the basic service, ex "_rtsp._tcp"
 * 2. and to mark it additionally and specifically for ravenna it uses a subservice, ex "_ravenna._sub._rtsp._tcp"
 *
 * where a service named <vendor-node-id> should be registered and optionally a service named <user-defined-node-name>.
 * The ravenna subservice should use the <vendor-node-id> name.
 *
 * There is an additional subservice for named sessions, ex. "_ravenna_session._sub._rtsp._tcp"
 *
 *
 * There exist particular addressing schemes for generic and named sessions:
 * - "rtsp://<host-port>/by-id/<id>
 * - "rtsp://<host-port>/by-name/<session-name>
 * - "ravenna:<vendor-node-id>:/by-id/<id>
 * - "ravenna:<vendor-node-id>:/by-name/<session-name>
 * - "ravenna_session:<session-name>
 */

#ifndef AES67_RAV_H
#define AES67_RAV_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RAV_URI_PROTO_GENERIC         "ravenna"
#define AES67_RAV_URI_PROTO_NAMEDSESSION    "ravenna_session"

#define AES67_RAV_MDNS_SUBSRV_GENERIC       "_" AES67_RAV_URI_PROTO "._sub."
#define AES67_RAV_MDNS_SUBSRV_NAMEDSESSION  "_" AES67_RAV_URI_PROTO_NAMEDSESSION "._sub."

//#define AES67_RAV_MDNS_RTSP "_ravenna._sub._rtsp._tcp"
//#define AES67_RAV_MDNS_HTTP "_ravenna._sub._http._tcp"


#ifdef __cplusplus
}
#endif

#endif //AES67_RAV_H
