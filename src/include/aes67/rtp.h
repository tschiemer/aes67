/**
 * @file rtp.h
 * Real-time Procotol
 *
 * References:
 * RTP: A Transport Protocol for Real-Time Applications https://tools.ietf.org/html/rfc3550
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc3551
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

#ifndef AES67_RTP_H
#define AES67_RTP_H

#include "aes67/arch.h"
#include "aes67/def.h"
#include "aes67/audio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RTP_HEADER1       0
#define AES67_RTP_HEADER2       1
#define AES67_RTP_SEQNO         2
#define AES67_RTP_TIMESTAMP     4
#define AES67_RTP_SSRC          8
#define AES67_RTP_CSRC          12

#define AES67_RTP_HEADER1_VERSION       0b11000000
#define AES67_RTP_HEADER1_PADDING       0b00100000
#define AES67_RTP_HEADER1_EXTENSION     0b00010000
#define AES67_RTP_HEADER1_CSRC_COUNT    0b00001111
#define AES67_RTP_HEADER2_MARKER        0b10000000
#define AES67_RTP_HEADER2_PAYLOADTYPE   0b01111111

#define AES67_RTP_PAYLOAD(csrc_count) (AES67_RTP_CSRC + 4*((u16_t)(csrc_count)))

typedef u16_t ptime_t;

struct aes67_rtp_packet {
    u8_t header1;
    u8_t header2;
    u16_t seqno;
    u32_t timestamp;
    u32_t ssrc;
    u8_t data[];
} PACK_STRUCT;

//inline u32_t aes67_rtp_computer_nsamples(u8_t * packet, u16_t len, )
//{
//    u16_t dlen = len - AES67_RTP_PAYLOAD(packet[AES67_RTP_HEADER1] & AES67_RTP_HEADER1_CSRC_COUNT);
//}

inline void aes67_rtp_header_ntoh(struct aes67_rtp_packet *packet)
{
    packet->seqno = aes67_ntohs(packet->seqno);
    packet->timestamp = aes67_ntohl(packet->timestamp);
    packet->ssrc = aes67_ntohl(packet->ssrc);
    // ignore csrc
}
inline void aes67_rtp_header_hton(struct aes67_rtp_packet *packet)
{
    aes67_rtp_header_ntoh(packet);
}

ptime_t aes67_rtp_compute_ptime(struct aes67_rtp_packet *before, struct aes67_rtp_packet * after, u32_t samplerate);

#ifdef __cplusplus
}
#endif

#endif //AES67_RTP_H
