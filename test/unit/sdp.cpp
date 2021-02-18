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

#include "aes67/sdp.h"

typedef struct {
    aes67_sdp_flags context;
    char str[64];
} unhandled_t;

static struct {
    int seen;
    int expected;
    unhandled_t * lines;
} unhandled;

static void set_unhandled_expectations(int expected, unhandled_t * lines){
    assert( expected || lines != NULL );

    unhandled.seen = 0;
    unhandled.expected = expected;
    unhandled.lines = lines;
}

void aes67_sdp_fromstr_unhandled(struct aes67_sdp *sdp, aes67_sdp_flags context, u8_t *line, u32_t len, void *user_data)
{
    CHECK_COMPARE(NULL, !=,  unhandled.lines);
    CHECK_COMPARE(unhandled.seen, <, unhandled.expected);

    assert(line != NULL);
    assert(len > 0);

    char str[256];

    assert(len < sizeof(str)-1);

    std::memcpy(str, line, len);
    str[len] = '\0';

    STRCMP_EQUAL(unhandled.lines[unhandled.seen++].str, str);
}

TEST_GROUP(SDP_TestGroup)
{
};


TEST(SDP_TestGroup, sdp_get_connections)
{
    struct aes67_sdp s1 = {
            .connections = {
                    .count = 0
            }
    };

    CHECK_EQUAL(0, aes67_sdp_get_connection_count(&s1));

    struct aes67_sdp s2 = {
            .connections = {
                    .count = 1,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            }
                    }
            },
            .streams = {
                    .count = 1
            }
    };

    CHECK_EQUAL(1, aes67_sdp_get_connection_count(&s2));
    CHECK_EQUAL(&s2.connections.data[0], aes67_sdp_get_connection(&s2, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s2, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(&s2.connections.data[0], aes67_sdp_get_connection(&s2, 0));


    struct aes67_sdp s3 = {
            .connections = {
                    .count = 1,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            },
            .streams = {
                    .count = 1
            }
    };

    CHECK_EQUAL(1, aes67_sdp_get_connection_count(&s3));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s3, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(&s3.connections.data[0], aes67_sdp_get_connection(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(&s3.connections.data[0], aes67_sdp_get_connection(&s3, 0));

    s3.connections.data[0].flags |= 1; // set other (actually invalid) stream index

    CHECK_EQUAL(1, aes67_sdp_get_connection_count(&s3));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s3, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s3, 0));


    struct aes67_sdp s4 = {
            .connections = {
                    .count = 2,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            },
            .streams = {
                    .count = 1
            }
    };

    CHECK_EQUAL(2, aes67_sdp_get_connection_count(&s4));
    CHECK_EQUAL(&s4.connections.data[0], aes67_sdp_get_connection(&s4, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(&s4.connections.data[1], aes67_sdp_get_connection(&s4, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(&s4.connections.data[1], aes67_sdp_get_connection(&s4, 0));


    struct aes67_sdp s5 = {
            .connections = {
                    .count = 2,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            },
            .streams = {
                    .count = 2
            }
    };

    CHECK_EQUAL(2, aes67_sdp_get_connection_count(&s5));
    CHECK_EQUAL(&s5.connections.data[0], aes67_sdp_get_connection(&s5, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(&s5.connections.data[1], aes67_sdp_get_connection(&s5, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(&s5.connections.data[1], aes67_sdp_get_connection(&s5, 0));
    CHECK_EQUAL(NULL, aes67_sdp_get_connection(&s5, AES67_SDP_FLAG_DEFLVL_STREAM | 1));
    CHECK_EQUAL(&s5.connections.data[0], aes67_sdp_get_connection(&s5, 1));


    struct aes67_sdp s6 = {
            .connections = {
                    .count = 3,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1
                            }
                    }
            },
            .streams = {
                    .count = 2
            }
    };

    CHECK_EQUAL(3, aes67_sdp_get_connection_count(&s6));
    CHECK_EQUAL(&s6.connections.data[0], aes67_sdp_get_connection(&s6, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(&s6.connections.data[1], aes67_sdp_get_connection(&s6, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(&s6.connections.data[1], aes67_sdp_get_connection(&s6, 0));
    CHECK_EQUAL(&s6.connections.data[2], aes67_sdp_get_connection(&s6, AES67_SDP_FLAG_DEFLVL_STREAM | 1));
    CHECK_EQUAL(&s6.connections.data[2], aes67_sdp_get_connection(&s6, 1));

}



TEST(SDP_TestGroup, sdp_get_streams)
{
    struct aes67_sdp s1 = {
            .streams = {
                    .count = 0
            }
    };

    CHECK_EQUAL(0, aes67_sdp_get_stream_count(&s1));

    struct aes67_sdp s2 = {
            .streams = {
                    .count = 2
            }
    };


    CHECK_EQUAL(2, aes67_sdp_get_stream_count(&s2));
    CHECK_EQUAL(&s2.streams.data[0], aes67_sdp_get_stream(&s2, 0));
    CHECK_EQUAL(&s2.streams.data[1], aes67_sdp_get_stream(&s2, 1));
}


TEST(SDP_TestGroup, sdp_get_stream_encodings)
{
    struct aes67_sdp s1 = {
            .streams = {
                    .count = 1,
                    .data = {
                            {
                                    .nencodings = 0
                            }
                    }
            },
            .encodings = {
                    .count = 0
            }
    };

    CHECK_EQUAL(0, aes67_sdp_get_stream_encoding_count(&s1, 0));


    struct aes67_sdp s2 = {
            .streams = {
                    .count = 1,
                    .data = {
                            {
                                .nencodings = 2
                            }
                    }
            },
            .encodings = {
                    .count = 2,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            }
    };

    CHECK_EQUAL(2, aes67_sdp_get_stream_encoding_count(&s2, 0));
    CHECK_EQUAL(&s2.encodings.data[0], aes67_sdp_get_stream_encoding(&s2, 0, 0));
    CHECK_EQUAL(&s2.encodings.data[1], aes67_sdp_get_stream_encoding(&s2, 0, 1));


    struct aes67_sdp s3 = {
            .streams = {
                    .count = 2,
                    .data = {
                            {
                                    .nencodings = 1
                            },
                            {
                                    .nencodings = 1
                            },
                    }
            },
            .encodings = {
                    .count = 2,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            }
    };

    CHECK_EQUAL(1, aes67_sdp_get_stream_encoding_count(&s3, 0));
    CHECK_EQUAL(&s3.encodings.data[1], aes67_sdp_get_stream_encoding(&s3, 0, 0));
    CHECK_EQUAL(1, aes67_sdp_get_stream_encoding_count(&s3, 1));
    CHECK_EQUAL(&s3.encodings.data[0], aes67_sdp_get_stream_encoding(&s3, 1, 0));


    struct aes67_sdp s4 = {
            .streams = {
                    .count = 3,
                    .data = {
                            {
                                    .nencodings = 2
                            },
                            {
                                    .nencodings = 1
                            },
                            {
                                    .nencodings = 2
                            },
                    }
            },
            .encodings = {
                    .count = 5,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 2
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 2
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            }
                    }
            }
    };

    CHECK_EQUAL(2, aes67_sdp_get_stream_encoding_count(&s4, 0));
    CHECK_EQUAL(&s4.encodings.data[2], aes67_sdp_get_stream_encoding(&s4, 0, 0));
    CHECK_EQUAL(&s4.encodings.data[4], aes67_sdp_get_stream_encoding(&s4, 0, 1));
    CHECK_EQUAL(1, aes67_sdp_get_stream_encoding_count(&s4, 1));
    CHECK_EQUAL(&s4.encodings.data[3], aes67_sdp_get_stream_encoding(&s4, 1, 0));
    CHECK_EQUAL(2, aes67_sdp_get_stream_encoding_count(&s4, 2));
    CHECK_EQUAL(&s4.encodings.data[0], aes67_sdp_get_stream_encoding(&s4, 2, 0));
    CHECK_EQUAL(&s4.encodings.data[1], aes67_sdp_get_stream_encoding(&s4, 2, 1));
}


TEST(SDP_TestGroup, sdp_get_ptps)
{
    aes67_sdp s1 = {
            .nptp = 0
    };

    CHECK_EQUAL(0, aes67_sdp_get_ptp_count(&s1, AES67_SDP_FLAG_DEFLVL_SESSION));


    aes67_sdp s2 = {
            .nptp = 0,
            .streams = {
                    .count = 1,
                    .data = {
                            {
                                    .nptp = 1 // well, the ptp itself is not set yet..
                            }
                    }
            }
    };

    CHECK_EQUAL(0, aes67_sdp_get_ptp_count(&s2, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(1, aes67_sdp_get_ptp_count(&s2, 0));


    aes67_sdp s3 = {
            .nptp = 2,
            .ptps = {
                    .count = 5,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1
                            }
                    }
            },
            .streams = {
                    .count = 2,
                    .data = {
                            {
                                    .nptp = 1
                            },
                            {
                                    .nptp = 2
                            }
                    }
            }
    };

    CHECK_EQUAL(2, aes67_sdp_get_ptp_count(&s3, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(1, aes67_sdp_get_ptp_count(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 0));
    CHECK_EQUAL(3, aes67_sdp_get_ptp_count(&s3, 0));
    CHECK_EQUAL(2, aes67_sdp_get_ptp_count(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 1));
    CHECK_EQUAL(4, aes67_sdp_get_ptp_count(&s3, 1));
    CHECK_EQUAL(&s3.ptps.data[0], aes67_sdp_get_ptp(&s3, AES67_SDP_FLAG_DEFLVL_SESSION, 0));
    CHECK_EQUAL(&s3.ptps.data[3], aes67_sdp_get_ptp(&s3, AES67_SDP_FLAG_DEFLVL_SESSION, 1));
    CHECK_EQUAL(&s3.ptps.data[1], aes67_sdp_get_ptp(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 0, 0));
    CHECK_EQUAL(&s3.ptps.data[0], aes67_sdp_get_ptp(&s3, 0, 0));
    CHECK_EQUAL(&s3.ptps.data[1], aes67_sdp_get_ptp(&s3, 0, 1));
    CHECK_EQUAL(&s3.ptps.data[3], aes67_sdp_get_ptp(&s3, 0, 2));
    CHECK_EQUAL(&s3.ptps.data[2], aes67_sdp_get_ptp(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 1, 0));
    CHECK_EQUAL(&s3.ptps.data[4], aes67_sdp_get_ptp(&s3, AES67_SDP_FLAG_DEFLVL_STREAM | 1, 1));
    CHECK_EQUAL(&s3.ptps.data[0], aes67_sdp_get_ptp(&s3, 1, 0));
    CHECK_EQUAL(&s3.ptps.data[2], aes67_sdp_get_ptp(&s3, 1, 1));
    CHECK_EQUAL(&s3.ptps.data[3], aes67_sdp_get_ptp(&s3, 1, 2));
    CHECK_EQUAL(&s3.ptps.data[4], aes67_sdp_get_ptp(&s3, 1, 3));
}


TEST(SDP_TestGroup, sdp_origin_compare)
{
    struct aes67_sdp_originator o1 = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(1, aes67_sdp_origin_eq(&o1, &o1));
    CHECK_EQUAL(0, aes67_sdp_origin_cmpversion(&o1, &o1));

    struct aes67_sdp_originator o1_later = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543211"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(1, aes67_sdp_origin_eq(&o1, &o1_later));
    CHECK_EQUAL(-1, aes67_sdp_origin_cmpversion(&o1, &o1_later));
    CHECK_EQUAL(1, aes67_sdp_origin_cmpversion(&o1_later, &o1));


    struct aes67_sdp_originator o2 = {
            .username = AES67_STRING_INIT_BYTES(""),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(0, aes67_sdp_origin_eq(&o1, &o2));

    struct aes67_sdp_originator o3 = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("1234567890as"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(0, aes67_sdp_origin_eq(&o1, &o3));


    struct aes67_sdp_originator o4 = {
            .username = AES67_STRING_INIT_BYTES(""),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name2")
    };

    CHECK_EQUAL(0, aes67_sdp_origin_eq(&o1, &o4));
}


TEST(SDP_TestGroup, sdp_origin_tostr)
{
    uint8_t str[512];
    uint32_t len;

    struct aes67_sdp_originator o1 = {
            .username = AES67_STRING_INIT_BYTES(""),
            .session_id = AES67_STRING_INIT_BYTES(""),
            .session_version = AES67_STRING_INIT_BYTES(""),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("")
    };

    len = aes67_sdp_origin_tostr(str, sizeof(str), &o1);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL("o=-   IN IP4 \r\n", (const char *)str);


    struct aes67_sdp_originator o2 = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("123456789012345678901234567890123456789"),
            .session_version = AES67_STRING_INIT_BYTES("098765432109876543210987654321098765432"),
            .ipver = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    len = aes67_sdp_origin_tostr(str, sizeof(str), &o2);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL("o=joe 123456789012345678901234567890123456789 098765432109876543210987654321098765432 IN IP4 random.host.name\r\n", (const char *)str);


    o2.ipver = aes67_net_ipver_6;

    len = aes67_sdp_origin_tostr(str, sizeof(str), &o2);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL("o=joe 123456789012345678901234567890123456789 098765432109876543210987654321098765432 IN IP6 random.host.name\r\n", (const char *)str);

}


TEST(SDP_TestGroup, aes67_sdp_connections_tostr)
{
    uint8_t str[512];
    uint32_t len;

    struct aes67_sdp_connection_list c1 = {
            .count = 0
    };

    len = aes67_sdp_connections_tostr(str, sizeof(str), &c1, AES67_SDP_FLAG_DEFLVL_SESSION);

    CHECK_COMPARE(0, ==, len);

    len = aes67_sdp_connections_tostr(str, sizeof(str), &c1, AES67_SDP_FLAG_DEFLVL_STREAM | 0);

    CHECK_COMPARE(0, ==, len);


    struct aes67_sdp_connection_list c2 = {
            .count = 5,
            .data = {
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                            .ipver = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.1",
                                    .length = sizeof("10.0.0.1")-1
                            },
                            .ttl = 0,
                            .naddr = 1
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .ipver = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.2",
                                    .length = sizeof("10.0.0.2")-1
                            },
                            .ttl = 33,
                            .naddr = 1
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .ipver = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.3",
                                    .length = sizeof("10.0.0.3")-1
                            },
                            .ttl = 44,
                            .naddr = 2
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                            .ipver = aes67_net_ipver_6,
                            .address = {
                                    .data = "host1",
                                    .length = sizeof("host1")-1
                            },
                            .ttl = 0,
                            .naddr = 0
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                            .ipver = aes67_net_ipver_6,
                            .address = {
                                    .data = "host2",
                                    .length = sizeof("host2")-1
                            },
                            .ttl = 0,
                            .naddr = 32
                    }
            }
    };


    len = aes67_sdp_connections_tostr(str, sizeof(str), &c2, AES67_SDP_FLAG_DEFLVL_SESSION);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "c=IN IP4 10.0.0.1\r\n"
            "c=IN IP6 host2/32\r\n",
            (const char*)str
    );


    len = aes67_sdp_connections_tostr(str, sizeof(str), &c2, AES67_SDP_FLAG_DEFLVL_STREAM | 0);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "c=IN IP6 host1\r\n",
            (const char*)str
    );


    len = aes67_sdp_connections_tostr(str, sizeof(str), &c2, AES67_SDP_FLAG_DEFLVL_STREAM | 1);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "c=IN IP4 10.0.0.2/33\r\n"
            "c=IN IP4 10.0.0.3/44/2\r\n",
            (const char*)str
    );
}

TEST(SDP_TestGroup, aes67_sdp_ptp_tostr)
{
    uint8_t str[512];
    uint32_t len;

    struct aes67_sdp_ptp_list p1 = {
            .count = 0
    };

    len = aes67_sdp_ptp_tostr(str, sizeof(str), &p1, AES67_SDP_FLAG_DEFLVL_SESSION);

    CHECK_COMPARE(0, ==, len);

    len = aes67_sdp_ptp_tostr(str, sizeof(str), &p1, AES67_SDP_FLAG_DEFLVL_STREAM | 0);

    CHECK_COMPARE(0, ==, len);


    struct aes67_sdp_ptp_list p2 = {
            .count = 5,
            .data = {
                    { // a=ts-refclk:ptp=IEEE1588-2002:01-02-03-04-05-06-07-08
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                            .ptp = {
                                    .type = aes67_ptp_type_IEEE1588_2002,
                                    .gmid.u8 = {1,2,3,4,5,6,7,8}
                            }
                    },
                    { // a=ts-refclk:ptp=IEEE1588-2008:02-03-04-05-06-07-08-09:10
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .ptp = {
                                    .type = aes67_ptp_type_IEEE1588_2008,
                                    .gmid.u8 = {2,3,4,5,6,7,8,9},
                                    .domain = 10
                            }
                    },
                    { // a=ts-refclk:ptp=IEEE1588-2019:03-04-05-06-07-08-09-0A:11
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                            .ptp = {
                                    .type = aes67_ptp_type_IEEE1588_2019,
                                    .gmid.u8 = {3,4,5,6,7,8,9,10},
                                    .domain = 11
                            }
                    },
                    { // a=ts-refclk:ptp=IEEE802.1AS-2011:04-05-06-07-08-09-0A-0B
                        .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                        .ptp = {
                                .type = aes67_ptp_type_IEEE802AS_2011,
                                .gmid.u8 = {4,5,6,7,8,9,10,11}
                        }
                    },
                    { // a=ts-refclk:ptp=IEEE1588-2019:05-06-07-08-09-0A-0B-0C:12
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .ptp = {
                                    .type = aes67_ptp_type_IEEE1588_2019,
                                    .gmid.u8 = {5,6,7,8,9,10,11,12},
                                    .domain = 12
                            }
                    }
            }
    };

    std::memset(str, 0, sizeof(str));

    len = aes67_sdp_ptp_tostr(str, sizeof(str), &p2, AES67_SDP_FLAG_DEFLVL_SESSION);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "a=ts-refclk:ptp=IEEE1588-2002:01-02-03-04-05-06-07-08\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:04-05-06-07-08-09-0A-0B\r\n"
            ,
            (const char*)str
            );


    std::memset(str, 0, sizeof(str));

    len = aes67_sdp_ptp_tostr(str, sizeof(str), &p2, AES67_SDP_FLAG_DEFLVL_STREAM | 0);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "a=ts-refclk:ptp=IEEE1588-2019:03-04-05-06-07-08-09-0A:11\r\n"
    ,
            (const char*)str
    );


    std::memset(str, 0, sizeof(str));

    len = aes67_sdp_ptp_tostr(str, sizeof(str), &p2, AES67_SDP_FLAG_DEFLVL_STREAM | 1);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "a=ts-refclk:ptp=IEEE1588-2008:02-03-04-05-06-07-08-09:10\r\n"
            "a=ts-refclk:ptp=IEEE1588-2019:05-06-07-08-09-0A-0B-0C:12\r\n"
    ,
            (const char*)str
    );
}

TEST(SDP_TestGroup, sdp_tostr)
{
    uint8_t str[1500];
    uint32_t len;

    struct aes67_sdp s1 = {
            .originator = {
                .username = AES67_STRING_INIT_BYTES("joe"),
                .session_id = AES67_STRING_INIT_BYTES("1234567890"),
                .session_version = AES67_STRING_INIT_BYTES("9876543210"),
                .ipver = aes67_net_ipver_4,
                .address = AES67_STRING_INIT_BYTES("random.host.name")
            },
            .name = AES67_STRING_INIT_BYTES("")
    };

    len = aes67_sdp_tostr(str, sizeof(str), &s1);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s= \r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            , (const char *)str);


    std::memcpy(s1.name.data, "1337 $3$$i0n", sizeof("1337 $3$$i0n") - 1);
    s1.name.length = sizeof("1337 $3$$i0n") - 1;

#if 0 < AES67_SDP_MAXSESSIONINFO
    std::memcpy(s1.info.data, "more info", sizeof("more info") - 1);
    s1.info.length = sizeof("more info") - 1;
#endif

    std::memset(str, 0, sizeof(str));
    len = aes67_sdp_tostr(str, sizeof(str), &s1);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$i0n\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=more info\r\n"
#endif
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
    , (const char *)str);


    struct aes67_sdp s2 = {
            .originator = {
                    .username = AES67_STRING_INIT_BYTES("joe"),
                    .session_id = AES67_STRING_INIT_BYTES("1234567890"),
                    .session_version = AES67_STRING_INIT_BYTES("9876543210"),
                    .ipver = aes67_net_ipver_4,
                    .address = AES67_STRING_INIT_BYTES("random.host.name")
            },
            .name = AES67_STRING_INIT_BYTES("1337 $3$$10N"),
#if 0 < AES67_SDP_MAXSESSIONINFO
            .info = AES67_STRING_INIT_BYTES("my session info"),
#endif
            .connections = {
                    .count = 2,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                                    .ipver = aes67_net_ipver_4,
                                    .address = AES67_STRING_INIT_BYTES("224.0.0.1"),
                                    .ttl = 33,
                                    .naddr = 1
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                                    .ipver = aes67_net_ipver_6,
                                    .address = AES67_STRING_INIT_BYTES("some.host.name"),
                                    .naddr = 1
                            }
                    }
            },
            .ptp_domain = AES67_SDP_PTPDOMAIN_SET | 2,
            .nptp = 1,
            .ptps = {
                    .count = 2,
                    .data = {
                            {
                                .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                                .ptp = {
                                        .type = aes67_ptp_type_IEEE802AS_2011,
                                        .gmid.u8 = {8,7,6,5,4,3,2,1}
                                }
                            },
                            {
                                .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                                .ptp = {
                                        .type = aes67_ptp_type_IEEE1588_2008,
                                        .gmid.u8 = {1,2,3,4,5,6,7,8},
                                        .domain = 1,
                                }
                            }
                    }
            },
            .streams = {
                    .count = 2,
                    .data = {
                            {
                                    .info = AES67_STRING_INIT_BYTES("stream level info"),
                                    .port = 5000,
                                    .nports = 2,
                                    .mode = aes67_sdp_attr_mode_inactive,
                                    .nptp = 1,
                                    .mediaclock = {
                                            .set = 1,
                                            .offset = 12345,
                                    },
                                    .synctime = {
                                            .set = 1,
                                            .value = 7890
                                    },
                                    .nencodings = 3,
                                    .ptime = AES67_SDP_PTIME_SET | 1000,
                                    .ptime_cap = {
                                            .count = 2,
                                            .cfg = AES67_SDP_CAP_PROPOSED | 1,
                                            .cfg_a = 1,
                                            .data = {
                                                    {
                                                            .cap = 1,
                                                            .ptime = 330
                                                    },
                                                    {
                                                            .cap = 2,
                                                            .ptime = 1000
                                                    }
                                            }
                                    },
                                    .maxptime = AES67_SDP_PTIME_SET | 1000
                            },
                            {
                                    .info = AES67_STRING_INIT_BYTES(""),
                                    .port = 5002,
                                    .nports = 0,
                                    .mode = aes67_sdp_attr_mode_recvonly,
                                    .nptp = 0,
                                    .mediaclock = {
                                            .set = 1,
                                            .offset = 98765,
                                    },
                                    .nencodings = 1,
                                    .ptime = AES67_SDP_PTIME_SET | 4000,
                                    .ptime_cap = {
                                            .cfg = AES67_SDP_CAP_ACTIVE | 3,
                                            .cfg_a = 12,
                                    },
                            },
                    }
            },
            .encodings = {
                    .count = 4,
                    .data = {
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                                    .payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START,
                                    .encoding = aes67_audio_encoding_L16,
                                    .samplerate = 48000,
                                    .nchannels = 2
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                                    .payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START + 1,
                                    .encoding = aes67_audio_encoding_L24,
                                    .samplerate = 48000,
                                    .nchannels = 2
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                                    .payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START + 2,
                                    .encoding = aes67_audio_encoding_L24,
                                    .samplerate = 96000,
                                    .nchannels = 2
                            },
                            {
                                    .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                                    .payloadtype = AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START,
                                    .encoding = aes67_audio_encoding_L24,
                                    .samplerate = 192000,
                                    .nchannels = 1
                            }
                    }
            }
    };

    std::memset(str, 0, sizeof(str));
    len = aes67_sdp_tostr(str, sizeof(str), &s2);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 ptime:1\r\n"
            "a=maxptime:1\r\n"
            "a=pcfg:1 a=1\r\n"
            "a=ts-refclk:ptp=IEEE1588-2008:01-02-03-04-05-06-07-08:1\r\n"
            "a=mediaclk:direct=12345\r\n"
            "a=sync-time:7890\r\n"
            "m=audio 5002 RTP/AVP 96\r\n"
            "c=IN IP6 some.host.name\r\n"
            "a=recvonly\r\n"
            "a=rtpmap:96 L24/192000\r\n"
            "a=ptime:4\r\n"
            "a=acfg:3 a=12\r\n"
            "a=mediaclk:direct=98765\r\n"
    , (const char *)str);

#ifdef RELEASE
    len = aes67_sdp_tostr(str, 4, &s2);
    CHECK_EQUAL(0, len);
#endif

    // maxlen checks
    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o= asdfasdf"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$1"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my sessio"
#endif
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 "
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL
#endif
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 "
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-"
    ), &s2));


    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inac"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/480"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 pt"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 ptime:1\r\n"
            "a=maxpti"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 ptime:1\r\n"
            "a=maxptime:1\r\n"
            "a=pcfg:1 a="
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 ptime:1\r\n"
            "a=maxptime:1\r\n"
            "a=pcfg:1 a=1\r\n"
            "a=ts-refclk:ptp=IEEE158"
    ), &s2));

    CHECK_EQUAL(0,aes67_sdp_tostr(str, sizeof(
            "v=0\r\n"
            "o=joe 1234567890 9876543210 IN IP4 random.host.name\r\n"
            "s=1337 $3$$10N\r\n"
#if 0 < AES67_SDP_MAXSESSIONINFO
            "i=my session info\r\n"
#endif
            "c=IN IP4 224.0.0.1/33\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
            "a=clock-domain:PTPv2 2\r\n"
            "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\r\n"
            "m=audio 5000/2 RTP/AVP 96 97 98\r\n"
            "i=stream level info\r\n"
            "a=inactive\r\n"
            "a=rtpmap:96 L16/48000/2\r\n"
            "a=rtpmap:97 L24/48000/2\r\n"
            "a=rtpmap:98 L24/96000/2\r\n"
            "a=ptime:1\r\n"
            "a=pcap:1 ptime:0.33\r\n"
            "a=pcap:2 ptime:1\r\n"
            "a=maxptime:1\r\n"
            "a=pcfg:1 a=1\r\n"
            "a=ts-refclk:ptp=IEEE1588-2008:01-02-03-04-05-06-07-08:1\r\n"
            "a=mediaclk:direct=1"
    ), &s2));
}


TEST(SDP_TestGroup, sdp_fromstr)
{
    struct aes67_sdp sdp;


    uint8_t s1[] = "random";

    std::memset(&sdp, 0, sizeof(struct aes67_sdp));
    CHECK_EQUAL(AES67_SDP_ERROR, aes67_sdp_fromstr(&sdp, s1, sizeof(s1) - 1, NULL));


    uint8_t s2[] = "v=0\r\n"
                   "o=- 123 45678 IN IP4 ipaddr1\r\n"
                   "s= \r\n"
                   "c=IN IP4 ipaddr2/44/36\r\n"
                   "t=0 0\r\n"
                   "a=ptp-domain:PTPv2 13\r\n"
                   "a=inactive\r\n"
                   "m=audio 5000 RTP/AVP 96 97\r\n"
                   "a=recvonly\r\n"
                   "a=rtpmap:96 L16/48000/2\r\n"
                   "a=rtpmap:97 L32/96000\r\n"
                   "a=ptime:1.33\r\n"
                   "a=pcap:2 ptime:1.33\r\n"
                   "a=pcap:3 ptime:4\r\n"
                   "a=pcfg:5 a=2\r\n"
                   "a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:2\r\n"
                   "a=mediaclk:direct=963214424\r\n"
                   "a=sync-time:46482394\r\n"
                   ;


    std::memset(&sdp, 0, sizeof(struct aes67_sdp));
    CHECK_EQUAL(AES67_SDP_OK, aes67_sdp_fromstr(&sdp, s2, sizeof(s2) - 1, NULL));

    // originator
    CHECK_EQUAL(0, sdp.originator.username.length);
//    MEMCMP_EQUAL("", sdp.originator.username.data, 0);
    CHECK_EQUAL(sizeof("123")-1, sdp.originator.session_id.length);
    MEMCMP_EQUAL("123", sdp.originator.session_id.data, sizeof("123")-1);
    CHECK_EQUAL(sizeof("45678")-1, sdp.originator.session_version.length);
    MEMCMP_EQUAL("45678", sdp.originator.session_version.data, sizeof("123")-1);
    CHECK_EQUAL(aes67_net_ipver_4, sdp.originator.ipver);
    CHECK_EQUAL(sizeof("ipaddr1")-1, sdp.originator.address.length);
    MEMCMP_EQUAL("ipaddr1", sdp.originator.address.data, sizeof("ipaddr1")-1);

    //session name
    CHECK_EQUAL(0, sdp.name.length);

    //connection
    CHECK_EQUAL(1, sdp.connections.count);
    CHECK_EQUAL(aes67_net_ipver_4, sdp.connections.data[0].ipver);
    CHECK_EQUAL(sizeof("ipaddr2")-1, sdp.connections.data[0].address.length);
    MEMCMP_EQUAL("ipaddr2", sdp.connections.data[0].address.data, sizeof("ipaddr2")-1);
    CHECK_EQUAL(36, sdp.connections.data[0].naddr);
    CHECK_EQUAL(44, sdp.connections.data[0].ttl);

    CHECK_EQUAL(aes67_sdp_attr_mode_inactive, aes67_sdp_get_mode(&sdp, AES67_SDP_FLAG_DEFLVL_SESSION));
    CHECK_EQUAL(aes67_sdp_attr_mode_recvonly, aes67_sdp_get_mode(&sdp, AES67_SDP_FLAG_DEFLVL_STREAM | 0));

    //media/stream
    CHECK_EQUAL(1, sdp.streams.count);
    struct aes67_sdp_stream * stream = aes67_sdp_get_stream(&sdp, 0);
    CHECK_EQUAL(&sdp.streams.data[0], stream);
    CHECK_EQUAL(5000, stream->port);
    CHECK_EQUAL(2, stream->nports);

    CHECK_EQUAL(2, aes67_sdp_get_stream_encoding_count(&sdp, 0));
    struct aes67_sdp_attr_encoding * enc = aes67_sdp_get_stream_encoding(&sdp, 0, 0);
    CHECK_EQUAL(&sdp.encodings.data[0], enc);
    CHECK_EQUAL(AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0, enc->flags);
    CHECK_EQUAL(96, enc->payloadtype);
    CHECK_EQUAL(aes67_audio_encoding_L16, enc->encoding);
    CHECK_EQUAL(48000, enc->samplerate);
    CHECK_EQUAL(2, enc->nchannels);
    enc = aes67_sdp_get_stream_encoding(&sdp, 0, 1);
    CHECK_EQUAL(&sdp.encodings.data[1], enc);
    CHECK_EQUAL(AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0, enc->flags);
    CHECK_EQUAL(97, enc->payloadtype);
    CHECK_EQUAL(aes67_audio_encoding_L32, enc->encoding);
    CHECK_EQUAL(96000, enc->samplerate);
    CHECK_EQUAL(1, enc->nchannels);

    CHECK_EQUAL(aes67_sdp_attr_mode_recvonly, stream->mode);

    CHECK_EQUAL(1, stream->mediaclock.set);
    CHECK_EQUAL(963214424, stream->mediaclock.offset);

    CHECK_EQUAL(1, stream->synctime.set);
    CHECK_EQUAL(46482394, stream->synctime.value);

    CHECK_EQUAL(AES67_SDP_PTIME_SET, (stream->ptime & AES67_SDP_PTIME_SET));
    CHECK_EQUAL(1330, stream->ptime & AES67_SDP_PTIME_VALUE);

#if 0 < AES67_SDP_MAXPTIMECAPS
    CHECK_EQUAL(2, stream->ptime_cap.count);
    CHECK_EQUAL(2, stream->ptime_cap.data[0].cap);
    CHECK_EQUAL(1330, stream->ptime_cap.data[0].ptime);
    CHECK_EQUAL(3, stream->ptime_cap.data[1].cap);
    CHECK_EQUAL(4000, stream->ptime_cap.data[1].ptime);

    CHECK_EQUAL(AES67_SDP_CAP_PROPOSED | 5,  stream->ptime_cap.cfg);
    CHECK_EQUAL(2,  stream->ptime_cap.cfg_a);
#endif //0 < AES67_SDP_MAXPTIMECAPS

    CHECK_EQUAL(AES67_SDP_PTPDOMAIN_SET | 13, sdp.ptp_domain);
    CHECK_EQUAL(0, sdp.nptp);
    CHECK_EQUAL(1, aes67_sdp_get_ptp_count(&sdp, 0));
    struct aes67_sdp_ptp * ptp = aes67_sdp_get_ptp(&sdp, 0, 0);
    CHECK_EQUAL(&sdp.ptps.data[0], ptp);
    CHECK_EQUAL(aes67_ptp_type_IEEE1588_2008, ptp->ptp.type);
    MEMCMP_EQUAL("\x39\xA7\x94\xFF\xFE\x07\xCB\xD0", ptp->ptp.gmid.u8, 8);
    CHECK_EQUAL(2, ptp->ptp.domain);

    uint8_t s3[] = "v=0\n"
                   "o=audio 1311738121 1311738121 IN IP4 192.168.1.1\n"
                   "s=Stage left I/O\n"
                   "c=IN IP4 192.168.1.1\n"
                   "u=https://jdoe.wrong/fancy-pants\n"
                   "e=foobert@jdoe.wrong\n"
                   "p=+666 1234567890\n"
                   "t=0 0\n"
                   "a=tool:gst\n"
                   "a=charset:ISO-8859-1\n"
                   "a=mediaclk:direct=446172\n"
                   "m=audio 5004 RTP/AVP 96\n"
                   "i=Channels 1-8\n"
                   "a=rtpmap:96 L24/48000/8\n"
                   "a=sendonly\n"
                   "a=ptime:0.250\n"
                   "a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:0\n"
                   "a=ts-refclk:ptp=IEEE802.1AS-2011:08-07-06-05-04-03-02-01\n"
                   "a=mediaclk:direct=2216659908";


    std::memset(&sdp, 0, sizeof(struct aes67_sdp));
    CHECK_EQUAL(AES67_SDP_OK, aes67_sdp_fromstr(&sdp, s3, sizeof(s3) - 1, NULL));

    CHECK_EQUAL(1, sdp.mediaclock.set);
    CHECK_EQUAL(446172, sdp.mediaclock.offset);

#if 0 < AES67_SDP_MAXURI
    CHECK_EQUAL(sizeof("https://jdoe.wrong/fancy-pants")-1, sdp.uri.length);
    MEMCMP_EQUAL("https://jdoe.wrong/fancy-pants", sdp.uri.data, sizeof("https://jdoe.wrong/fancy-pants")-1);
#endif

#if 0 < AES67_SDP_MAXEMAIL
    CHECK_EQUAL(sizeof("foobert@jdoe.wrong")-1, sdp.email.length);
    MEMCMP_EQUAL("foobert@jdoe.wrong", sdp.email.data, sizeof("foobert@jdoe.wrong")-1);
#endif

#if 0 < AES67_SDP_MAXPHONE
    CHECK_EQUAL(sizeof("+666 1234567890")-1, sdp.phone.length);
    MEMCMP_EQUAL("+666 1234567890", sdp.phone.data, sizeof("+666 1234567890")-1);
#endif

#if 0 < AES67_SDP_MAXTOOL
    CHECK_EQUAL(sizeof("gst")-1, sdp.tool.length);
    MEMCMP_EQUAL("gst", sdp.tool.data, sizeof("gst")-1);
#endif

#if 0 < AES67_SDP_MAXCHARSET
    CHECK_EQUAL(sizeof("ISO-8859-1")-1, sdp.charset.length);
    MEMCMP_EQUAL("ISO-8859-1", sdp.charset.data, sizeof("ISO-8859-1")-1);
#endif


    uint8_t s4[] = "v=0\n"
                   "o=audio 1311738121 1311738121 IN IP4 192.168.1.1\n"
                   "s=Stage left I/O\n"
                   "c=IN IP4 192.168.1.1\n"
                   "t=2873397496 2873404696\n"
                   "r=604800 3600 0 90000\n"
                   "m=audio 5004 RTP/AVP 96 2\n"
                   "i=Channels 1-8\n"
                   "a=rtpmap:96 L24/48000/8\n"
                   "a=sendonly\n"
                   "a=ptime:0.250\n"
                   "a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:0\n"
                   "a=mediaclk:direct=2216659908\n"
                   "a=sync-time:12332\n" // optional RAVENNA attr
                   "a=clock-deviation:1001/1000\n" // optional RAVENNA attr
                   "m=video 51372 RTP/AVP 99\n"
                   "a=rtpmap:99 h263-1998/90000\n"
                   "m=audio 5004 RTP/AVP 96\n"
                   "a=rtpmap:96 PCMU/8000/1\n"
                   "a=fmtp:18 annexb=yes\n"
                   "m=audio 5004 SRTP/AVP 96\n"
                   "a=rtpmap:96 L16/48000/8\n"
                   "a=ts-refclk:ptp=IEEE1588-2008:01-02-03-04-05-06-07-08:0\n"
                   "a=mediaclk:direct=1234\n";

    unhandled_t u1[] = {
            {
                    .context = AES67_SDP_FLAG_DEFLVL_SESSION,
                    .str = "t=2873397496 2873404696"
            },
            {
                    .context = AES67_SDP_FLAG_DEFLVL_SESSION,
                    .str = "r=604800 3600 0 90000"
            },
            {
                    .context = AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                    .str = "m=audio 5004 RTP/AVP 96 2" // reported because unknown payload type
            },
            {
                    .context = AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                    .str = "a=clock-deviation:1001/1000" // unknown RAVENNA attr
            },
            {
                    .context = 0,
                    .str = "m=video 51372 RTP/AVP 99" // unkonwn media type
            },
            {
                    .context = 0,
                    .str = "a=rtpmap:99 h263-1998/90000" // part of unknown media
            },
            {
                    .context = AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                    .str = "a=rtpmap:96 PCMU/8000/1" // unknown encoding
            },
            {
                    .context = AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                    .str = "a=fmtp:18 annexb=yes" // unknown attr
            },
            {
                    .context = 0,
                    .str = "m=audio 5004 SRTP/AVP 96" // unknown media profile
            },
            {
                    .context = 0,
                    .str = "a=rtpmap:96 L16/48000/8" // part of unknown media
            },
            {
                    .context = 0,
                    .str = "a=ts-refclk:ptp=IEEE1588-2008:01-02-03-04-05-06-07-08:0" // part of unknown media
            },
            {
                    .context = 0,
                    .str = "a=mediaclk:direct=1234" // part of unknown media
            }
    };

    set_unhandled_expectations(12, u1);

    std::memset(&sdp, 0, sizeof(struct aes67_sdp));
    CHECK_EQUAL(AES67_SDP_OK, aes67_sdp_fromstr(&sdp, s4, sizeof(s4) - 1, NULL));

    CHECK_EQUAL(2, sdp.streams.count);

    CHECK_EQUAL(unhandled.expected, unhandled.seen);
}

