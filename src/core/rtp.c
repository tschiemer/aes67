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

#include "aes67/rtp.h"

#include "aes67/debug.h"

static inline void rtp_memcpy(u8_t * dst, u8_t * src, size_t size){
    while(size--){
        *dst++ = *src++;
    }
}

//inline void rtp_txfifo_update(struct aes67_rtp_txfifo * fifo)
//{
//    size_t min = fifo->in.min;
//    size_t max = fifo->in.max;
//
//
//}

void aes67_rtp_buffer_insert_all(struct aes67_rtp_buffer * buf, void * data, size_t samples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("data != NULL", data != NULL);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[ss*(nch * buf->in.ch[0])];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->in.ch[0] + samples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = samples - last;

        rtp_memcpy(dst, data, nch*ss*c);
        data += nch*ss*c;

        c = last;
        dst = &buf->data[0];

    } else {
        c = samples;
    }

    rtp_memcpy(dst, data, nch*ss*c);

    buf->in.ch[0] = last;
}

void aes67_rtp_buffer_insert_1ch(struct aes67_rtp_buffer * buf, void * data, size_t channel, size_t samples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("data != NULL", data != NULL);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;
    size_t inc = ss * nch;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[ss*(nch * buf->in.ch[channel] + channel)];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->in.ch[channel] + samples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = samples - last;

        while(c--){
            rtp_memcpy(dst, data, ss);
            dst += inc;
            data += ss;
        }

        c = last;
        dst = &buf->data[ss*channel];

    } else {
        c = samples;
    }

    // if was necessary to wrap around circular buffer copy remaining data

    while(c--){
        rtp_memcpy(dst, data, ss);
        dst += inc;
        data += ss;
    }

    buf->in.ch[channel] = last;
}

//ptime_t aes67_rtp_ptime_from_packdiff(struct aes67_rtp_packet *before, struct aes67_rtp_packet * after, u32_t samplerate)
//{
//    // require strictly increasing sequence number to safely establish a packet was really before
//    // will wrap around every ~60 sec with a ptime of 250ms
//    // note: computing this makes only sense, when the ptime is not yet known
//    if (before->header.seqno >= after->header.seqno){
//        return 0;
//    }
//
//    u32_t seqdiff = after->header.seqno - before->header.seqno;
//
//    u32_t tdiff;
//
//    // get timestamp/clock difference
//    if (before->header.timestamp < after->header.timestamp){
//        tdiff = after->header.timestamp - before->header.timestamp;
//    } else {
//        tdiff = (UINT32_MAX - before->header.timestamp) + after->header.timestamp + 1;
//    }
//
//    // the number of samples per packet is fixed and has a fixed relationship to the media clock
//    // ie each sample is exactly one clock increment
//    return (1000000*tdiff) / seqdiff / samplerate;
//}

u16_t aes67_rtp_pack(u8_t * packet, u8_t payloadtype, u16_t seqno, u32_t timestamp, u32_t ssrc, void * samples, u16_t ssize)
{
    AES67_ASSERT("packet != NULL", packet != NULL);
    AES67_ASSERT("samples != NULL", samples != NULL);
    AES67_ASSERT("ssize > 0" , ssize > 0);

    ((struct aes67_rtp_packet *)packet)->header.status1 = AES67_RTP_STATUS1_VERSION_2;
    ((struct aes67_rtp_packet *)packet)->header.status2 = AES67_RTP_STATUS2_PAYLOADTYPE & payloadtype;
    ((struct aes67_rtp_packet *)packet)->header.seqno = aes67_htons(seqno);
    ((struct aes67_rtp_packet *)packet)->header.timestamp = aes67_htonl(timestamp);
    ((struct aes67_rtp_packet *)packet)->header.ssrc = aes67_htonl(ssrc);

    aes67_memcpy(((struct aes67_rtp_packet *)packet)->data, samples, ssize);

    return AES67_RTP_CSRC + ssize;
}