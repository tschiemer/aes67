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
            .address_type = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(1, aes67_sdp_origin_eq(&o1, &o1));
    CHECK_EQUAL(0, aes67_sdp_origin_cmpversion(&o1, &o1));

    struct aes67_sdp_originator o1_later = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543211"),
            .address_type = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(1, aes67_sdp_origin_eq(&o1, &o1_later));
    CHECK_EQUAL(-1, aes67_sdp_origin_cmpversion(&o1, &o1_later));
    CHECK_EQUAL(1, aes67_sdp_origin_cmpversion(&o1_later, &o1));


    struct aes67_sdp_originator o2 = {
            .username = AES67_STRING_INIT_BYTES(""),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .address_type = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(0, aes67_sdp_origin_eq(&o1, &o2));

    struct aes67_sdp_originator o3 = {
            .username = AES67_STRING_INIT_BYTES("joe"),
            .session_id = AES67_STRING_INIT_BYTES("1234567890as"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .address_type = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    CHECK_EQUAL(0, aes67_sdp_origin_eq(&o1, &o3));


    struct aes67_sdp_originator o4 = {
            .username = AES67_STRING_INIT_BYTES(""),
            .session_id = AES67_STRING_INIT_BYTES("1234567890"),
            .session_version = AES67_STRING_INIT_BYTES("9876543210"),
            .address_type = aes67_net_ipver_4,
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
            .address_type = aes67_net_ipver_4,
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
            .address_type = aes67_net_ipver_4,
            .address = AES67_STRING_INIT_BYTES("random.host.name")
    };

    len = aes67_sdp_origin_tostr(str, sizeof(str), &o2);

    CHECK_COMPARE(0, <, len);
    str[len] = '\0';
    STRCMP_EQUAL("o=joe 123456789012345678901234567890123456789 098765432109876543210987654321098765432 IN IP4 random.host.name\r\n", (const char *)str);


    o2.address_type = aes67_net_ipver_6;

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
                            .address_type = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.1",
                                    .length = sizeof("10.0.0.1")-1
                            },
                            .ttl = 0,
                            .naddr = 1
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .address_type = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.2",
                                    .length = sizeof("10.0.0.2")-1
                            },
                            .ttl = 33,
                            .naddr = 1
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 1,
                            .address_type = aes67_net_ipver_4,
                            .address = {
                                    .data = "10.0.0.3",
                                    .length = sizeof("10.0.0.3")-1
                            },
                            .ttl = 44,
                            .naddr = 2
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | 0,
                            .address_type = aes67_net_ipver_6,
                            .address = {
                                    .data = "host1",
                                    .length = sizeof("host1")-1
                            },
                            .ttl = 0,
                            .naddr = 0
                    },
                    {
                            .flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION,
                            .address_type = aes67_net_ipver_6,
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
    uint8_t str[1024];
    uint32_t len;

    struct aes67_sdp s1 = {
            .originator = {
                .username = AES67_STRING_INIT_BYTES("joe"),
                .session_id = AES67_STRING_INIT_BYTES("1234567890"),
                .session_version = AES67_STRING_INIT_BYTES("9876543210"),
                .address_type = aes67_net_ipver_4,
                .address = AES67_STRING_INIT_BYTES("random.host.name")
            },
            .session_name = AES67_STRING_INIT_BYTES("")
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


    std::memcpy(s1.session_name.data, "1337 $3$$i0n", sizeof("1337 $3$$i0n")-1);
    s1.session_name.length = sizeof("1337 $3$$i0n")-1;

#if 0 < AES67_SDP_MAXSESSIONINFO
    std::memcpy(s1.session_info.data, "more info", sizeof("more info")-1);
    s1.session_info.length = sizeof("more info")-1;
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

    s1.connections.count = 4;
    s1.connections.data[0].flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION;
    s1.connections.data[0].address_type = aes67_net_ipver_4;
    std::memcpy(s1.connections.data[0].address.data, "10.0.0.1", sizeof("10.0.0.1")-1);
    s1.connections.data[0].address.length = sizeof("10.0.0.1")-1;
    s1.connections.data[0].ttl = 33;
    s1.connections.data[0].naddr = 1;

    s1.connections.data[1].flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION;
    s1.connections.data[1].address_type = aes67_net_ipver_4;
    std::memcpy(s1.connections.data[1].address.data, "10.0.0.2", sizeof("10.0.0.2")-1);
    s1.connections.data[1].address.length = sizeof("10.0.0.2")-1;
    s1.connections.data[1].ttl = 44;
    s1.connections.data[1].naddr = 8;

    s1.connections.data[2].flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION;
    s1.connections.data[2].address_type = aes67_net_ipver_6;
    std::memcpy(s1.connections.data[2].address.data, "host1", sizeof("host1")-1);
    s1.connections.data[2].address.length = sizeof("host1")-1;
    s1.connections.data[2].ttl = 0;
    s1.connections.data[2].naddr = 1;

    s1.connections.data[3].flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_SESSION;
    s1.connections.data[3].address_type = aes67_net_ipver_6;
    std::memcpy(s1.connections.data[3].address.data, "host2", sizeof("host2")-1);
    s1.connections.data[3].address.length = sizeof("host2")-1;
    s1.connections.data[3].ttl = 0;
    s1.connections.data[3].naddr = 2;

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
            "c=IN IP4 10.0.0.1/33\r\n"
            "c=IN IP4 10.0.0.2/44/8\r\n"
            "c=IN IP6 host1\r\n"
            "c=IN IP6 host2/2\r\n"
            "t=0 0\r\n"
#if AES67_SDP_TOOL_ENABLED == 1
            "a=tool:" AES67_SDP_TOOL "\r\n"
#endif
    , (const char *)str);
}