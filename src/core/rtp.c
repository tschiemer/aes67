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

ptime_t aes67_rtp_compute_ptime(struct aes67_rtp_packet *before, struct aes67_rtp_packet * after, u32_t samplerate)
{
    // require strictly increasing sequence number to safely establish a packet was really before
    // will wrap around every ~60 sec with a ptime of 250ms
    // note: computing this makes only sense, when the ptime is not yet known
    if (before->seqno >= after->seqno){
        return 0;
    }

    u32_t seqdiff = after->seqno - before->seqno;

    u32_t tdiff;

    // get timestamp/clock difference
    if (before->timestamp < after->timestamp){
        tdiff = after->timestamp - before->timestamp;
    } else {
        tdiff = (UINT32_MAX - before->timestamp) + after->timestamp + 1;
    }

    // the number of samples per packet is fixed and has a fixed relationship to the media clock
    // ie each sample is exactly one clock increment
    return (1000000*tdiff) / seqdiff / samplerate;
}