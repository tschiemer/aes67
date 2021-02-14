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

//TEST(RTP_TestGroup, rtp_macros)
//{
//
//}

TEST(RTP_TestGroup, rtp_buffer_insert_all)
{struct aes67_rtp_buffer * b1 = (struct aes67_rtp_buffer *)std::calloc(1, AES67_RTP_BUFFER_SIZE(4, 3, 10));

    b1->nsamples = 10;
    b1->nchannels = 4;
    b1->samplesize = 3;

    u8_t d1[] = {
            0,0,1, 0,0,2, 0,0,3, 0,0,4,
            0,0,2, 0,0,3, 0,0,4, 0,0,5,
            0,0,3, 0,0,4, 0,0,5, 0,0,6,
            0,0,4, 0,0,5, 0,0,6, 0,0,7,
            0,0,5, 0,0,6, 0,0,7, 0,0,8,
            0,0,6, 0,0,7, 0,0,8, 0,0,9,
            0,0,7, 0,0,8, 0,0,9, 0,0,10,
            0,0,8, 0,0,9, 0,0,10, 0,0,11,
            0,0,9, 0,0,10, 0,0,11, 0,0,12,
            0,0,10, 0,0,11, 0,0,12, 0,0,13,
    };

    CHECK_EQUAL(0, b1->in.ch[0]);

    aes67_rtp_buffer_insert_all(b1, d1, 3);
    CHECK_EQUAL(3, b1->in.ch[0]);

    u8_t c1[] = {
            0,0,1, 0,0,2, 0,0,3, 0,0,4,
            0,0,2, 0,0,3, 0,0,4, 0,0,5,
            0,0,3, 0,0,4, 0,0,5, 0,0,6,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
    };
    MEMCMP_EQUAL(c1, b1->data, sizeof(c1));

    aes67_rtp_buffer_insert_all(b1, d1, 3);
    CHECK_EQUAL(6, b1->in.ch[0]);

    u8_t c2[] = {
            0,0,1, 0,0,2, 0,0,3, 0,0,4,
            0,0,2, 0,0,3, 0,0,4, 0,0,5,
            0,0,3, 0,0,4, 0,0,5, 0,0,6,
            0,0,1, 0,0,2, 0,0,3, 0,0,4,
            0,0,2, 0,0,3, 0,0,4, 0,0,5,
            0,0,3, 0,0,4, 0,0,5, 0,0,6,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
            0,0,0, 0,0,0, 0,0,0, 0,0,0,
    };
    MEMCMP_EQUAL(c2, b1->data, sizeof(c2));


    // now insert whole buffer d1
    // because it was non-empty we'll end up with a rotated buffer
    aes67_rtp_buffer_insert_all(b1, d1, 10);
    CHECK_EQUAL(6, b1->in.ch[0]);

    u8_t c3[] = {
            0,0,5, 0,0,6, 0,0,7, 0,0,8,
            0,0,6, 0,0,7, 0,0,8, 0,0,9,
            0,0,7, 0,0,8, 0,0,9, 0,0,10,
            0,0,8, 0,0,9, 0,0,10, 0,0,11,
            0,0,9, 0,0,10, 0,0,11, 0,0,12,
            0,0,10, 0,0,11, 0,0,12, 0,0,13,
            0,0,1, 0,0,2, 0,0,3, 0,0,4,
            0,0,2, 0,0,3, 0,0,4, 0,0,5,
            0,0,3, 0,0,4, 0,0,5, 0,0,6,
            0,0,4, 0,0,5, 0,0,6, 0,0,7,
    };
    MEMCMP_EQUAL(c3, b1->data, sizeof(c3));

    free(b1);
}

TEST(RTP_TestGroup, rtp_buffer_insert_1ch)
{

    struct aes67_rtp_buffer * b1 = (struct aes67_rtp_buffer *)std::calloc(1, AES67_RTP_BUFFER_SIZE(4, 3, 10));

    b1->nsamples = 10;
    b1->nchannels = 4;
    b1->samplesize = 3;

    u8_t d1[] = {0,0,1, 0,0,2, 0,0,3 };
    u8_t d2[] = {0,0,4, 0,0,5, 0,0,6 };
    u8_t d3[] = {0,0,7, 0,0,8, 0,0,9, 0,0,10};

    u8_t c1[] = {
            0,0,0, 0,0,1, 0,0,0, 0,0,0,
            0,0,0, 0,0,2, 0,0,0, 0,0,0,
            0,0,0, 0,0,3, 0,0,0, 0,0,0,
            0,0,0, 0,0,4, 0,0,0, 0,0,0,
            0,0,0, 0,0,5, 0,0,0, 0,0,0,
            0,0,0, 0,0,6, 0,0,0, 0,0,0,
            0,0,0, 0,0,7, 0,0,0, 0,0,0,
            0,0,0, 0,0,8, 0,0,0, 0,0,0,
            0,0,0, 0,0,9, 0,0,0, 0,0,0,
            0,0,0, 0,0,10, 0,0,0, 0,0,0,
    };

    CHECK_EQUAL(0, b1->in.ch[1]);

    aes67_rtp_buffer_insert_1ch(b1, d1, 1, 3);
    CHECK_EQUAL(3, b1->in.ch[1]);

    aes67_rtp_buffer_insert_1ch(b1, d2, 1, 3);
    CHECK_EQUAL(6, b1->in.ch[1]);

    aes67_rtp_buffer_insert_1ch(b1, d3, 1, 4);
    CHECK_EQUAL(0, b1->in.ch[1]);

    MEMCMP_EQUAL(c1, b1->data, sizeof(c1));


    aes67_rtp_buffer_insert_1ch(b1, d3, 1, 4);
    CHECK_EQUAL(4, b1->in.ch[1]);


    u8_t c2[] = {
            0,0,0, 0,0,7, 0,0,0, 0,0,0,
            0,0,0, 0,0,8, 0,0,0, 0,0,0,
            0,0,0, 0,0,9, 0,0,0, 0,0,0,
            0,0,0, 0,0,10, 0,0,0, 0,0,0,
            0,0,0, 0,0,5, 0,0,0, 0,0,0,
            0,0,0, 0,0,6, 0,0,0, 0,0,0,
            0,0,0, 0,0,7, 0,0,0, 0,0,0,
            0,0,0, 0,0,8, 0,0,0, 0,0,0,
            0,0,0, 0,0,9, 0,0,0, 0,0,0,
            0,0,0, 0,0,10, 0,0,0, 0,0,0,
    };

    MEMCMP_EQUAL(c2, b1->data, sizeof(c2));

    CHECK_EQUAL(0, b1->in.ch[0]);
    CHECK_EQUAL(0, b1->in.ch[2]);
    CHECK_EQUAL(0, b1->in.ch[3]);

    aes67_rtp_buffer_insert_1ch(b1, d1, 0, 3);
    CHECK_EQUAL(3, b1->in.ch[0]);

    aes67_rtp_buffer_insert_1ch(b1, d2, 2, 3);
    CHECK_EQUAL(3, b1->in.ch[2]);

    aes67_rtp_buffer_insert_1ch(b1, d3, 3, 4);
    CHECK_EQUAL(4, b1->in.ch[3]);

    uint8_t c3[] = {
            0,0,1, 0,0,7, 0,0,4, 0,0,7,
            0,0,2, 0,0,8, 0,0,5, 0,0,8,
            0,0,3, 0,0,9, 0,0,6, 0,0,9,
            0,0,0, 0,0,10, 0,0,0, 0,0,10,
            0,0,0, 0,0,5, 0,0,0, 0,0,0,
            0,0,0, 0,0,6, 0,0,0, 0,0,0,
            0,0,0, 0,0,7, 0,0,0, 0,0,0,
            0,0,0, 0,0,8, 0,0,0, 0,0,0,
            0,0,0, 0,0,9, 0,0,0, 0,0,0,
            0,0,0, 0,0,10, 0,0,0, 0,0,0,
    };
    MEMCMP_EQUAL(c3, b1->data, sizeof(c3));

    std::free(b1);
}

TEST(RTP_TestGroup, rtp_compute_ptime)
{
    struct aes67_rtp_packet before = {
            .header.seqno = 0,
            .header.timestamp = 0
    };
    struct aes67_rtp_packet after = {
            .header.seqno = 1,
            .header.timestamp = 48 //
    };

    // requires increasing seqno
    CHECK_EQUAL(0, aes67_rtp_ptime_from_packdiff(&after, &before, 48000));
    CHECK_EQUAL(0, aes67_rtp_ptime_from_packdiff(&after, &before, 96000));
    CHECK_EQUAL(0, aes67_rtp_ptime_from_packdiff(&after, &before, 192000));


    CHECK_EQUAL(1000, aes67_rtp_ptime_from_packdiff(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_ptime_from_packdiff(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_ptime_from_packdiff(&before, &after, 192000));

    after.header.seqno *= 2;
    after.header.timestamp *= 2;

    CHECK_EQUAL(1000, aes67_rtp_ptime_from_packdiff(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_ptime_from_packdiff(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_ptime_from_packdiff(&before, &after, 192000));

    // timestamp overflow

    before.header.timestamp += (UINT32_MAX - 4);
    after.header.timestamp += (UINT32_MAX - 4); // will overflow

    CHECK_EQUAL(1000, aes67_rtp_ptime_from_packdiff(&before, &after, 48000));
    CHECK_EQUAL(500, aes67_rtp_ptime_from_packdiff(&before, &after, 96000));
    CHECK_EQUAL(250, aes67_rtp_ptime_from_packdiff(&before, &after, 192000));

    // TODO 441000 Hz (44.1khz is somewhat a special case as in it should also be packed in 48 sample packets)
    // this messes up the otherwise straightforward computation

}