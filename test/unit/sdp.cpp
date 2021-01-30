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

TEST(SDP_TestGroup, sdp_origin_tostr)
{
    uint8_t str[512];
    uint16_t len;

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