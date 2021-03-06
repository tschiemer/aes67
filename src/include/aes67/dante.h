/**
 * @file dante.h
 * Generic Dante defines
 *
 * References:
 * https://www.audinate.com/learning/faqs/which-network-ports-does-dante-use
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

#ifndef AES67_DANTE_H
#define AES67_DANTE_H

#define AES67_DANTE_MDNS_TYPE_ARC       "_netaudio-arc._udp"
#define AES67_DANTE_MDNS_TYPE_CHAN      "_netaudio-chan._udp"
#define AES67_DANTE_MDNS_TYPE_CMC       "_netaudio-cmc._udp"
#define AES67_DANTE_MDNS_TYPE_DBC       "_netaudio-dbc._udp"

// 239.69.0.0/16
#define AES67_DANTE_RTP_IPv4_MIN        {239.69.0.0}
#define AES67_DANTE_RTP_IPv4_MAX        {239.69.255.255}

#endif //AES67_DANTE_H
