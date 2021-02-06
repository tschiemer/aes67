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


#include "CppUTest/TestHarness.h"

#include "aes67/rtp.h"


TEST_GROUP(RTP_TestGroup)
        {
        };

TEST(RTP_TestGroup, rtp_compute_ptime)
{
    struct aes67_rtp_packet before = {
            .seqno = 0,
            .timestamp = 0
    };
    struct aes67_rtp_packet after = {
            .seqno = 1,
            .timestamp = 48 //
    };

    // requires increasing seqno
    CHECK_EQUAL(0, aes67_rtp_compute_ptime(&after, &before, 48000));
    CHECK_EQUAL(0, aes67_rtp_compute_ptime(&after, &before, 96000));
    CHECK_EQUAL(0, aes67_rtp_compute_ptime(&after, &before, 192000));


    CHECK_EQUAL(1000, aes67_rtp_compute_ptime(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_compute_ptime(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_compute_ptime(&before, &after, 192000));

    after.seqno *= 2;
    after.timestamp *= 2;

    CHECK_EQUAL(1000, aes67_rtp_compute_ptime(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_compute_ptime(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_compute_ptime(&before, &after, 192000));

    // timestamp overflow

    before.timestamp += (UINT32_MAX - 4);
    after.timestamp += (UINT32_MAX - 4); // will overflow

    CHECK_EQUAL(1000, aes67_rtp_compute_ptime(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_compute_ptime(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_compute_ptime(&before, &after, 192000));

    // TODO 441000 Hz (44.1khz is somewhat a special case as in it should also be packed in 48 sample packets)
    // this messes up the otherwise straightforward computation

}