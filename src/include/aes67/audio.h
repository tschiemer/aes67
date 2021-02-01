/**
 * @file audio.h
 * Common audio defines and functionality.
 *
 * References:
 * AES67-2018 https://www.aes.org/publications/standards/search.cfm?docID=96
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc3551
 * RTP Payload Format for 12-bit DAT Audio and 20- and 24-bit Linear Sampled Audio https://tools.ietf.org/html/rfc3190
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

#ifndef AES67_AUDIO_H
#define AES67_AUDIO_H

enum aes67_audio_encoding {
    aes67_audio_encoding_undef  = 0,
    aes67_audio_encoding_L8     = 1,
    aes67_audio_encoding_L16    = 2,
    aes67_audio_encoding_L24    = 3,
    aes67_audio_encoding_L32    = 4,
} PACK_STRUCT;

#define AES67_AUDIO_ENCODING_ISVALID(x) ( \
    (x) == aes67_audio_encoding_L8 || \
    (x) == aes67_audio_encoding_L16 || \
    (x) == aes67_audio_encoding_L24 || \
    (x) == aes67_audio_encoding_L32 \
)

#define AES67_AUDIO_LX_SAMPLE(data, nchannels, samplesize, channel, sample)     ((void*)&((u8_t*)data)[sample*samplesize*nchannels + channel])

#define AES67_AUDIO_L8_SAMPLE(data, nchannels, channel, sample)                 ((s8_t*)AES67_AUDIO_LX_SAMPLE(data, nchannels, 1, channel, sample))
#define AES67_AUDIO_L16_SAMPLE(data, nchannels, channel, sample)                ((s16_t*)AES67_AUDIO_LX_SAMPLE(data, nchannels, 2, channel, sample))
#define AES67_AUDIO_L24_SAMPLE(data, nchannels, channel, sample)                AES67_AUDIO_LX_SAMPLE(data, nchannels, 3, channel, sample)
#define AES67_AUDIO_L32_SAMPLE(data, nchannels, channel, sample)                (s32_t*)AES67_AUDIO_LX_SAMPLE(data, nchannels, 3, channel, sample)

#endif //AES67_AUDIO_H
