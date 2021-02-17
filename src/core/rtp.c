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

inline void rtp_memcpy(u8_t * dst, u8_t * src, size_t count)
{
    while(count--){
        *dst++ = *src++;
    }
}

inline void rtp_memset(u8_t * dst, u8_t val, size_t count)
{
    while(count--){
        *dst++ = val;
    }
}

inline void rtp_zerofill(u8_t * dst, size_t count)
{
    while(count--){
        *dst++ = 0;
    }
}
void aes67_rtp_init(struct aes67_rtp * rtp)
{
    // see RFC 3550  Section 5
    rtp->seqno = AES67_RAND();
    rtp->timestamp = AES67_RAND();
    rtp->ssrc = AES67_RAND();
}

u32_t aes67_rtp_pack_raw(u8_t * packet, u8_t payloadtype, u16_t seqno, u32_t timestamp, u32_t ssrc, void * samples, u16_t ssize)
{
    AES67_ASSERT("packet != NULL", packet != NULL);
    AES67_ASSERT("samples != NULL", samples != NULL);
    AES67_ASSERT("ssize > 0" , ssize > 0);

    packet[AES67_RTP_STATUS1] = AES67_RTP_STATUS1_VERSION_2;
    packet[AES67_RTP_STATUS2] = AES67_RTP_STATUS2_PAYLOADTYPE & payloadtype;
    *(u16_t*)(&packet[AES67_RTP_SEQNO]) = aes67_htons(seqno);
    *(u32_t*)(&packet[AES67_RTP_TIMESTAMP]) = aes67_htonl(timestamp);
    *(u32_t*)(&packet[AES67_RTP_SSRC]) = aes67_htonl(ssrc);

    aes67_memmove(&packet[AES67_RTP_CSRC], samples, ssize);

    //TODO padding??

    return AES67_RTP_CSRC + ssize;
}

u32_t aes67_rtp_pack(struct aes67_rtp *rtp, u8_t * packet)
{
    AES67_ASSERT("rtp != NULL", rtp != NULL);
    AES67_ASSERT("rtp->nsamples > 0", rtp->nsamples > 0);
    AES67_ASSERT("packet != NULL", packet != NULL);

    packet[AES67_RTP_STATUS1] = AES67_RTP_STATUS1_VERSION_2;
    packet[AES67_RTP_STATUS2] = AES67_RTP_STATUS2_PAYLOADTYPE & rtp->payloadtype;
    *(u16_t*)(&packet[AES67_RTP_SEQNO]) = aes67_htons(rtp->seqno);
    *(u32_t*)(&packet[AES67_RTP_TIMESTAMP]) = aes67_htonl(rtp->timestamp);
    *(u32_t*)(&packet[AES67_RTP_SSRC]) = aes67_htonl(rtp->ssrc);

    aes67_rtp_buffer_read_allch(&rtp->buf, &packet[AES67_RTP_CSRC], rtp->nsamples );

    //TODO padding??

    rtp->seqno++;
    rtp->timestamp += rtp->nsamples;

    return AES67_RTP_CSRC + (rtp->nsamples * rtp->buf.samplesize * rtp->buf.nchannels);
}

void aes67_rtp_buffer_insert_allch(struct aes67_rtp_buffer *buf, void *src, size_t nsamples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("data != NULL", src != NULL);

    size_t nch_ss = buf->nchannels * buf->samplesize;
//    size_t ss = ;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[nch_ss * buf->in.ch[0]];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->in.ch[0] + nsamples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = nsamples - last;

        rtp_memcpy(dst, src, nch_ss * c);
        src += nch_ss * c;

        c = last;
        dst = &buf->data[0];

    } else {
        c = nsamples;
    }

    rtp_memcpy(dst, src, nch_ss * c);

    buf->in.ch[0] = last;
}

void aes67_rtp_buffer_read_allch(struct aes67_rtp_buffer *buf, void *dst, size_t nsamples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("dst != NULL", dst != NULL);

    size_t nch_ss = buf->nchannels * buf->samplesize;

    // compute offset of where to insert first sample
    u8_t * src = &buf->data[nch_ss * buf->out.ch[0]];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->out.ch[0] + nsamples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = nsamples - last;

        rtp_memcpy(dst, src, nch_ss * c);

#if AES67_RTP_BUFREAD_ZEROFILL == 1
        rtp_zerofill(src, nch_ss*c);
#endif

        dst += nch_ss * c;

        c = last;
        src = &buf->data[0];

    } else {
        c = nsamples;
    }

    rtp_memcpy(dst, src, nch_ss * c);

#if AES67_RTP_BUFREAD_ZEROFILL == 1
    rtp_zerofill(src, nch_ss*c);
#endif

    buf->out.ch[0] = last;
}


void aes67_rtp_buffer_insert_allch_1smpl(struct aes67_rtp_buffer *buf, void *src)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("src != NULL", src != NULL);

    size_t nch_ss = buf->nchannels * buf->samplesize;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[nch_ss * buf->in.ch[0]];

    rtp_memcpy(dst, src, nch_ss);

    // shift in-pointer
    buf->in.ch[0] = (buf->in.ch[0] + 1) % buf->nsamples;
}

void aes67_rtp_buffer_read_allch_1smpl(struct aes67_rtp_buffer *buf, void *dst)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("dst != NULL", dst != NULL);

    size_t nch_ss = buf->nchannels * buf->samplesize;

    // compute offset of where to insert first sample
    u8_t * src = &buf->data[nch_ss * buf->out.ch[0]];

    rtp_memcpy(dst, src, nch_ss);

#if AES67_RTP_BUFREAD_ZEROFILL == 1
    rtp_zerofill(src, nch_ss);
#endif

    // shift in-pointer
    buf->out.ch[0] = (buf->out.ch[0] + 1) % buf->nsamples;
}

void aes67_rtp_buffer_insert_1ch(struct aes67_rtp_buffer *buf, void *src, size_t srcinc, size_t channel, size_t nsamples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("data != NULL", src != NULL);
    AES67_ASSERT("channel < buf->nchannels", channel < buf->nchannels);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;
    size_t inc = ss * nch;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[ss*(nch * buf->in.ch[channel] + channel)];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->in.ch[channel] + nsamples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = nsamples - last;

        while(c--){
            rtp_memcpy(dst, src, ss);
            dst += inc;
            src += srcinc;
        }

        c = last;
        dst = &buf->data[ss*channel];

    } else {
        c = nsamples;
    }

    // if was necessary to wrap around circular buffer copy remaining data

    while(c--){
        rtp_memcpy(dst, src, ss);
        dst += inc;
        src += srcinc;
    }

    buf->in.ch[channel] = last;
}


void aes67_rtp_buffer_read_1ch(struct aes67_rtp_buffer *buf, void *dst, size_t srcinc, size_t channel, size_t nsamples)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("dst != NULL", dst != NULL);
    AES67_ASSERT("channel < buf->nchannels", channel < buf->nchannels);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;
    size_t inc = ss * nch;

    // compute offset of where to insert first sample
    u8_t * src = &buf->data[ss*(nch * buf->out.ch[channel] + channel)];

    // remember how many samples could be inserted until end of (circular) buffer
    size_t last = (buf->in.ch[channel] + nsamples);
    size_t c;

    if (last >= buf->nsamples){

        last -= buf->nsamples;

        c = nsamples - last;

        while(c--){
            rtp_memcpy(dst, src, ss);
            dst += inc;
            src += srcinc;
        }

        c = last;
        dst = &buf->data[ss*channel];

    } else {
        c = nsamples;
    }

    // if was necessary to wrap around circular buffer copy remaining data

    while(c--){
        rtp_memcpy(dst, src, ss);
        dst += inc;
        src += srcinc;
    }

    buf->in.ch[channel] = last;
}



void aes67_rtp_buffer_insert_1ch_1smpl(struct aes67_rtp_buffer *buf, void *src, size_t channel)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("src != NULL", src != NULL);
    AES67_ASSERT("channel < buf->nchannels", channel < buf->nchannels);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;

    // compute offset of where to insert first sample
    u8_t * dst = &buf->data[ss*(nch * buf->in.ch[channel] + channel)];

    rtp_memcpy(dst, src, ss);

    // shift in-pointer
    buf->in.ch[channel] = (buf->in.ch[channel] + 1) % buf->nsamples;
}

void aes67_rtp_buffer_read_1ch_1smpl(struct aes67_rtp_buffer *buf, void *dst, size_t channel)
{
    AES67_ASSERT("buf != NULL", buf != NULL);
    AES67_ASSERT("dst != NULL", dst != NULL);
    AES67_ASSERT("channel < buf->nchannels", channel < buf->nchannels);

    size_t nch = buf->nchannels;
    size_t ss = buf->samplesize;

    // compute offset of where sample is
    u8_t * src = &buf->data[ss*(nch * buf->out.ch[channel] + channel)];

    rtp_memcpy(dst, src, ss);

#if AES67_RTP_BUFREAD_ZEROFILL == 1
    rtp_zerofill(src, ss);
#endif

    // shift in-pointer
    buf->out.ch[channel] = (buf->out.ch[channel] + 1) % buf->nsamples;
}
