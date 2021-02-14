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

#define AES67_RTP_STATUS1       0
#define AES67_RTP_STATUS2       1
#define AES67_RTP_SEQNO         2
#define AES67_RTP_TIMESTAMP     4
#define AES67_RTP_SSRC          8
#define AES67_RTP_CSRC          12

#define AES67_RTP_STATUS1_VERSION       0b11000000
#define AES67_RTP_STATUS1_PADDING       0b00100000
#define AES67_RTP_STATUS1_EXTENSION     0b00010000
#define AES67_RTP_STATUS1_CSRC_COUNT    0b00001111
#define AES67_RTP_STATUS2_MARKER        0b10000000
#define AES67_RTP_STATUS2_PAYLOADTYPE   0b01111111

#define AES67_RTP_STATUS1_VERSION_2     0b10000000

#define AES67_RTP_PAYLOAD(csrc_count) (AES67_RTP_CSRC + 4*((u16_t)(csrc_count)))

/** p(acket)time (realtime duration of packet samples when played back) in usec
 * u16_t should be fine, quite unlikely to have a ptime of more than 65ms ..
 */
typedef u16_t ptime_t;

#define AES67_RTP_PTIME(ms, us) (1000*ms + us)

#define AES67_RTP_PTIME_0_125ms_44_1k   130
#define AES67_RTP_PTIME_0_125ms_48k     120
#define AES67_RTP_PTIME_0_125ms_96k     120
#define AES67_RTP_PTIME_0_25ms_44_1k    270
#define AES67_RTP_PTIME_0_25ms_48k      250
#define AES67_RTP_PTIME_0_25ms_96k      250
#define AES67_RTP_PTIME_0_33ms_44_1k    360
#define AES67_RTP_PTIME_0_33ms_48k      330
#define AES67_RTP_PTIME_0_33ms_96k      330
#define AES67_RTP_PTIME_1ms_44_1k       1090
#define AES67_RTP_PTIME_1ms_48k         1000
#define AES67_RTP_PTIME_1ms_96k         1000
#define AES67_RTP_PTIME_4ms_44_1k       4350
#define AES67_RTP_PTIME_4ms_48k         4000
#define AES67_RTP_PTIME_4ms_96k         4000

#define AES67_RTP_NSAMPLES_0_125ms_44_1k    6
#define AES67_RTP_NSAMPLES_0_125ms_48k      6
#define AES67_RTP_NSAMPLES_0_125ms_96k      12
#define AES67_RTP_NSAMPLES_0_25ms_44_1k     12
#define AES67_RTP_NSAMPLES_0_25ms_48k       12
#define AES67_RTP_NSAMPLES_0_25ms_96k       24
#define AES67_RTP_NSAMPLES_0_33ms_44_1k     16
#define AES67_RTP_NSAMPLES_0_33ms_48k       16
#define AES67_RTP_NSAMPLES_0_33ms_96k       32
#define AES67_RTP_NSAMPLES_1ms_44_1k        48
#define AES67_RTP_NSAMPLES_1ms_48k          48
#define AES67_RTP_NSAMPLES_1ms_96k          96
#define AES67_RTP_NSAMPLES_4ms_44_1k        192
#define AES67_RTP_NSAMPLES_4ms_48k          192
#define AES67_RTP_NSAMPLES_4ms_96k          384

struct aes67_rtp_header {
    u8_t status1;
    u8_t status2;
    u16_t seqno;
    u32_t timestamp;
    u32_t ssrc;
} PACK_STRUCT;

struct aes67_rtp_packet {
    struct aes67_rtp_header header;
    u8_t data[];
} PACK_STRUCT;

//#define AES67_RTP_TXFIFO(NCHANNELS, SAMPLESIZE, NSAMPLES) \
//struct aes67_rtp_txfifo_ ## NCHANNELS ## _ ## SAMPLESIZE ## _ ## NSAMPLES { \
//    u8_t nchannels; \
//    u8_t samplesize; \
//    u16_t nsamples;  \
//    u8_t * start; \
//    u8_t * end; \
//    u8_t data[NCHANNELS * SAMPLESIZE * NSAMPLES]; \
//}

struct aes67_rtp_buffer {
    size_t nchannels;
    size_t samplesize;
    size_t nsamples;
    struct {
        u32_t min;
        u32_t max;
        u32_t ch[AES67_RTP_MAXCHANNELS];
    } in;
    struct {
        u32_t min;
        u32_t max;
        u32_t ch[AES67_RTP_MAXCHANNELS];
    } out;
    u8_t data[];
};

#define AES67_RTP_RAWBUFFER_SIZE(nchannels, samplesize, nsamples)    ((nchannels)*(samplesize)*(nsamples))
#define AES67_RTP_BUFFER_SIZE(nchannels, samplesize, nsamples)      (sizeof(struct aes67_rtp_buffer) + AES67_RTP_RAWBUFFER_SIZE(nchannels, samplesize, nsamples))
//#define AES67_RTP_BUFFER_SIZE_NPTIME(nchannels, samplesize, n, ptime_ms, samplerate)  AES67_RTP_BUFFER_SIZE(nchannels, samplesize, ((ptime_ms) * (samplerate)))

struct aes67_rtp_tx {
    u8_t payloadtype;
    u16_t seqno;
    u32_t timestamp;
    u32_t ssrc;
    struct aes67_rtp_buffer * buf;
};

inline u32_t aes67_rtp_ptime2nsamples(ptime_t ptime, u32_t samplerate)
{
    u32_t t = (u32_t)ptime * samplerate;
    u32_t round = (t % 1000000) >= 500000 ? 1 : 0;
    return (t / 1000000) + round;
}

inline u32_t aes67_rtp_nsamples2ptime(u32_t nsamples, u32_t samplerate)
{
    return (1000000*nsamples) / samplerate;
}

inline ptime_t aes67_rtp_packet2nsamples(void * packet, u16_t len, u32_t nchannels, u32_t samplesize)
{
    u32_t payloadlen = len - AES67_RTP_PAYLOAD(((u8_t*)packet)[AES67_RTP_STATUS1] & AES67_RTP_STATUS1_CSRC_COUNT );
    return payloadlen / samplesize / nchannels;
}


void aes67_rtp_buffer_insert_all(struct aes67_rtp_buffer * buf, void * data, size_t samples);
//void aes67_rtp_buffer_insert_nch(struct aes67_rtp_buffer * buf, void * data, size_t channel, size_t nch, size_t samples);
void aes67_rtp_buffer_insert_1ch(struct aes67_rtp_buffer * buf, void * data, size_t channel, size_t samples);

//inline u32_t aes67_rtp_computer_nsamples(u8_t * packet, u16_t len, )
//{
//    u16_t dlen = len - AES67_RTP_PAYLOAD(packet[AES67_RTP_STATUS1] & AES67_RTP_STATUS1_CSRC_COUNT);
//}

inline void aes67_rtp_header_ntoh(struct aes67_rtp_packet *packet)
{
    packet->header.seqno = aes67_ntohs(packet->header.seqno);
    packet->header.timestamp = aes67_ntohl(packet->header.timestamp);
    packet->header.ssrc = aes67_ntohl(packet->header.ssrc);
    // ignore csrc
}

inline void aes67_rtp_header_hton(struct aes67_rtp_packet * packet)
{
    aes67_rtp_header_ntoh(packet);
}

//ptime_t aes67_rtp_ptime_from_packdiff(struct aes67_rtp_packet *before, struct aes67_rtp_packet * after, u32_t samplerate);


u16_t aes67_rtp_pack(u8_t * packet, u8_t payloadtype, u16_t seqno, u32_t timestamp, u32_t ssrc, void * samples, u16_t ssize);

//void aes67_rtp_tx()

//inline u16_t aes67_rtp_pack_rtp(struct aes67_rtp_packet * packet, struct aes67_rtp_out * rtp, void * samples, u16_t ssize)
//{
//    return aes67_rtp_pack(packet, rtp->payloadtype, rtp->seqno, rtp->timestamp, rtp->timestamp, rtp->ssrc, samples, ssize);
//}

#ifdef __cplusplus
}
#endif

#endif //AES67_RTP_H
