/**
 * @file sdp.h
 * Minimal (partial) Session Description Protocol (SDP) implementation as
 * required for AES67.
 *
 * Designed to support (limited) capability negotiation (encoding, ptime alternatives) and RAVENNA specific attributes.
 *
 * Also see avp.h
 *
 * References:
 * Session Description Protocol (SDP) https://tools.ietf.org/html/rfc4566
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc3551
 * RTP Clock Source Signalling https://tools.ietf.org/html/rfc7273
 * Session Description Protocol (SDP) Capability Negotiation https://tools.ietf.org/html/rfc5939
 * An Offer/Answer Model with the Session Description Protocol (SDP) https://tools.ietf.org/html/rfc3264
 * RAVENNA Operating Principles (Draft 1.0 2011-06-01, final), ALC NetworX GmbH
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

#ifndef AES67_SDP_H
#define AES67_SDP_H

#include "aes67/arch.h"
#include "aes67/debug.h"
#include "aes67/net.h"
#include "aes67/ptp.h"
#include "aes67/rtp.h"
#include "aes67/rtp-avp.h"
#include "aes67/audio.h"


#ifdef __cplusplus
extern "C" {
#endif

#define AES67_SDP_MIMETYPE "application/sdp"

#define AES67_SDP_FLAG_SET_MASK             0b1000000000000000
#define AES67_SDP_FLAG_DEFLVL_MASK          0b0110000000000000
#define AES67_SDP_FLAG_STREAM_INDEX_MASK    0b0000000011111111

// Internally used bit (is entry set?)
#define AES67_SDP_FLAG_SET_YES          0b1000000000000000
#define AES67_SDP_FLAG_SET_NO           0b0000000000000000

#define AES67_SDP_FLAG_DEFLVL_SESSION   0b0100000000000000
#define AES67_SDP_FLAG_DEFLVL_STREAM    0b0010000000000000

/**
 * Marker for storing identifying context of SDP option/attribute
 *
 * In particular also used to query for options (once parsed).
 */
typedef u16_t aes67_sdp_flags;

#define AES67_SDP_PTPDOMAIN_SET        0b10000000
#define AES67_SDP_PTPDOMAIN_VALUE      0b01111111

#define AES67_SDP_PTIME_SET             0b1000000000000000
#define AES67_SDP_PTIME_VALUE           0b0111111111111111

#define AES67_SDP_CAP_SET               0b11000000
#define AES67_SDP_CAP_PROPOSED          0b10000000
#define AES67_SDP_CAP_ACTIVE            0b01000000
#define AES67_SDP_CAP_VALUE             0b00111111

/**
 * Result code (for parser specifically)
 */
enum {
    AES67_SDP_OK            = 0,
    AES67_SDP_ERROR,                // generic error
    AES67_SDP_NOMEMORY,             // not enough memory / too small pool sizes
    AES67_SDP_INCOMPLETE,           // missing some required fields
    AES67_SDP_NOTSUPPORTED          // unsupported feature
};

/**
 * SDP Mode attribute
 */
enum aes67_sdp_attr_mode {
    aes67_sdp_attr_mode_undefined = 0,
    aes67_sdp_attr_mode_inactive = 1,
    aes67_sdp_attr_mode_recvonly = 2,
    aes67_sdp_attr_mode_sendonly = 3,
    aes67_sdp_attr_mode_sendrecv = 4
} PACK_STRUCT;

#define AES67_SDP_ATTR_MODE_ISVALID(x) ( \
    (x) == aes67_sdp_attr_mode_inactive || \
    (x) == aes67_sdp_attr_mode_recvonly || \
    (x) == aes67_sdp_attr_mode_sendonly || \
    (x) == aes67_sdp_attr_mode_sendrecv \
)

/**
 * Originator data
 */
struct aes67_sdp_originator {
#if 0 < AES67_SDP_MAXUSERNAME
    AES67_STRING(AES67_SDP_MAXUSERNAME) username;
#endif
    AES67_STRING(AES67_SDP_MAXSESSIONID) session_id;
    AES67_STRING(AES67_SDP_MAXSESSIONVERSION) session_version;
//    u8_t nettype; // only IN type used
    enum aes67_net_ipver ipver;
    AES67_STRING(AES67_SDP_MAXADDRESS) address;
};

/**
 * Data of connection options
 */
struct aes67_sdp_connection {
    aes67_sdp_flags flags;
    u8_t ttl;
    u8_t naddr;
    enum aes67_net_ipver ipver;
    AES67_STRING(AES67_SDP_MAXADDRESS) address;
};

/**
 * Internally used connection list
 */
struct aes67_sdp_connection_list {
    u8_t count;
    struct aes67_sdp_connection data[AES67_SDP_MAXCONNECTIONS];
};

struct aes67_sdp_ptp {
    aes67_sdp_flags flags;
    struct aes67_ptp ptp;
};

struct aes67_sdp_ptp_list {
    u8_t count;
    struct aes67_sdp_ptp data[AES67_SDP_MAXPTPS];
};


/**
 * ptime capability data
 */
struct aes67_sdp_attr_ptimecap {
    u32_t cap;
    ptime_t ptime;
} PACK_STRUCT;

/**
 * Data of dynamic media payload types
 */
struct aes67_sdp_attr_encoding {
    aes67_sdp_flags flags;
    u8_t payloadtype;
    enum aes67_audio_encoding encoding;
    u32_t samplerate;
    u8_t nchannels;
};

/**
 * Internally used encoding list.
 */
struct aes67_sdp_attr_encoding_list {
    u8_t count;
    struct aes67_sdp_attr_encoding data[AES67_SDP_MAXENCODINGS];
};

/**
 * Collections essential info about a stream.
 */
struct aes67_sdp_stream {
    u16_t port;
    u8_t nports;
    u8_t nencodings;                // count of alternative stream encodings (in separate list)
    enum aes67_sdp_attr_mode mode;
    u8_t nptp;                      // count of stream level ptps (in separate list)
    u32_t mediaclock_offset;        //
    ptime_t ptime;
#if 0 < AES67_SDP_MAXPTIMECAPS
    struct {
        u8_t count;
        u8_t cfg;                   // (AES67_SDP_CAP_PROPOSED | AES67_SDP_CAP_ACTIVE) | AES67_SDP_CAP_VALUE
        u8_t cfg_a;                 // propsed/active attribute index
        struct aes67_sdp_attr_ptimecap data[AES67_SDP_MAXPTIMECAPS];
    } ptime_cap;
    ptime_t maxptime;
#endif // 0 < AES67_SDP_MAXPTIMECAPS
#if 0 < AES67_SDP_MAXSTREAMINFO
    AES67_STRING(AES67_SDP_MAXSTREAMINFO) info;
#endif
};

/**
 * Internally used stream list
 */
struct aes67_sdp_stream_list {
    u8_t count;
    struct aes67_sdp_stream data[AES67_SDP_MAXSTREAMS];
};

/**
 * A session description struct.
 *
 * Serves as container for programmatic handling of SDP strings.
 */
struct aes67_sdp {

    struct aes67_sdp_originator originator;

#if 0 < AES67_SDP_MAXSESSIONNAME
    AES67_STRING(AES67_SDP_MAXSESSIONNAME) name;
#endif

#if 0 < AES67_SDP_MAXSESSIONINFO
    AES67_STRING(AES67_SDP_MAXSESSIONINFO) info;
#endif

#if 0 < AES67_SDP_MAXURI
    AES67_STRING(AES67_SDP_MAXURI) uri;
#endif

#if 0 < AES67_SDP_MAXEMAIL
    AES67_STRING(AES67_SDP_MAXEMAIL) email;
#endif

#if 0 < AES67_SDP_MAXPHONE
    AES67_STRING(AES67_SDP_MAXPHONE) phone;
#endif

#if 0 < AES67_SDP_MAXCATEGORY
    AES67_STRING(AES67_SDP_MAXCATEGORY) category;
#endif

#if 0 < AES67_SDP_MAXKEYWORDS
    AES67_STRING(AES67_SDP_MAXKEYWORDS) keywords;
#endif

#if 0 < AES67_SDP_MAXTOOL
    AES67_STRING(AES67_SDP_MAXTOOL) tool;
#endif

#if 0 < AES67_SDP_MAXCHARSET
    AES67_STRING(AES67_SDP_MAXCHARSET) charset;
#endif


    // for the moment being, just forget about bandwidth ("b=.."), timing ("t=", assume "t=0 0"),
    // repeat times ("r="), time zones ("z="), encryption keys ("k=")

    enum aes67_sdp_attr_mode mode;

    u8_t nptp; // count of session level ptps

    u8_t ptp_domain; // session level ptp domain attribute (RAVENNA)

    struct aes67_sdp_connection_list connections;

    struct aes67_sdp_stream_list streams;

    struct aes67_sdp_ptp_list ptps;

    struct aes67_sdp_attr_encoding_list encodings;
};

/**
 * Resets/inits origin struct
 *
 * @param origin
 */
void aes67_sdp_origin_init(struct aes67_sdp_originator * origin);

/**
 * Resets/inits sdp struct
 *
 * @param sdp
 */
void aes67_sdp_init(struct aes67_sdp * sdp);

/**
 * Comfort getter for (RAVENNA) ptpdomain  attribute
 *
 * @param sdp
 * @return
 */
inline u8_t aes67_sdp_get_ptpdomain(struct aes67_sdp * sdp)
{
    return AES67_SDP_PTPDOMAIN_VALUE & sdp->ptp_domain;
}

/**
 * Comfort setter for (RAVENNA) ptpdomain  attribute
 *
 * @param sdp
 * @param domain
 * @return
 */
inline u8_t aes67_sdp_set_ptpdomain(struct aes67_sdp * sdp, u8_t domain)
{
    return sdp->ptp_domain = AES67_SDP_PTPDOMAIN_SET | (AES67_SDP_PTPDOMAIN_VALUE & domain);
}

/**
 * Comfort unsetter for (RAVENNA) ptpdomain attribute
 *
 * @param sdp
 * @param domain
 * @return
 */
inline u8_t aes67_sdp_unset_ptpdomain(struct aes67_sdp * sdp)
{
    return sdp->ptp_domain = 0;
}



/**
 * Get total connection setting count.
 *
 * @param sdp
 * @return
 */
inline u8_t aes67_sdp_get_connection_count(struct aes67_sdp * sdp)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    return sdp->connections.count;
}

/**
 * Get connection for session and/or streams (preferred).
 *
 * Can be specified to return..
 *  - only session level connection (flags = AES67_SDP_FLAG_DEFLVL_SESSION)
 *  - only stream level connection (flags = AES67_SDP_FLAG_DEFLVL_STREAM | <streams-index> )
 *  - the final connection (flags = <streams-index>) ie session level connection or overriding stream level connection
 *
 * @param sdp
 * @param flags
 * @return
 */
struct aes67_sdp_connection * aes67_sdp_get_connection(struct aes67_sdp * sdp, aes67_sdp_flags flags);

/**
 * Adds session-/stream-level connection to struct returning pointer (comfort function)
 *
 * @param sdp
 * @param di
 * @return
 */
inline struct aes67_sdp_connection * aes67_sdp_add_connection(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("sdp->connections.count < AES67_SDP_MAXCONNECTIONS", sdp->connections.count < AES67_SDP_MAXCONNECTIONS);

    return &sdp->connections.data[sdp->connections.count++];
}



/**
 * Get total stream count.
 *
 * @param sdp
 * @return
 */
inline u8_t aes67_sdp_get_stream_count(struct aes67_sdp * sdp)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    return sdp->streams.count;
}

/**
 * Get ith stream.
 *
 * @param sdp
 * @param si    stream index
 * @return
 */
inline struct aes67_sdp_stream * aes67_sdp_get_stream(struct aes67_sdp * sdp, u8_t si)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("si < sdp->streams.count", si < sdp->streams.count);

    return &sdp->streams.data[si];
}

/**
 * Comfort function to add new stream.
 *
 * @param sdp
 * @param si        if not NULL, is set to stream index
 * @return
 */
inline struct aes67_sdp_stream * aes67_sdp_add_stream(struct aes67_sdp * sdp, u8_t * si)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("si < sdp->streams.count", sdp->streams.count < AES67_SDP_MAXSTREAMS);

    if (si != NULL){
        *si = sdp->streams.count;
    }

    return &sdp->streams.data[sdp->streams.count++];
}


/**
 * Get number of (alternative) encodings for specific stream
 *
 * @param sdp
 * @param si    stream index
 * @return
 */
inline u8_t aes67_sdp_get_stream_encoding_count(struct aes67_sdp * sdp, u8_t si)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("si < sdp->streams.count", si < sdp->streams.count);

    return sdp->streams.data[si].nencodings;
}

/**
 * Get ith encoding (alternative) for jth stream.
 *
 * @param sdp
 * @param si    stream index
 * @param ei    encoding index
 * @return
 */
struct aes67_sdp_attr_encoding * aes67_sdp_get_stream_encoding(struct aes67_sdp * sdp, u8_t si, u8_t ei);

/**
 * Comfort function to add a new stream encoding.
 *
 * @param sdp
 * @param si
 * @return
 */
inline struct aes67_sdp_attr_encoding * aes67_sdp_add_stream_encoding(struct aes67_sdp * sdp, u8_t si)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("si < sdp->streams.count", si < sdp->streams.count);
    AES67_ASSERT("sdp->encodings.count < AES67_SDP_MAXENCODINGS", sdp->encodings.count < AES67_SDP_MAXENCODINGS);

    struct aes67_sdp_attr_encoding * enc = &sdp->encodings.data[ sdp->encodings.count++ ];

    AES67_ASSERT("(enc->flags & AES67_SDP_FLAG_SET_MASK) == AES67_SDP_FLAG_SET_YES", (enc->flags & AES67_SDP_FLAG_SET_MASK) == AES67_SDP_FLAG_SET_YES);

    enc->flags = AES67_SDP_FLAG_SET_YES | AES67_SDP_FLAG_DEFLVL_STREAM | si;

    return enc;
}


inline u8_t aes67_sdp_get_ptp_count(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);

    AES67_ASSERT("non-session level -> valid stream index", (flags & AES67_SDP_FLAG_DEFLVL_MASK) == AES67_SDP_FLAG_DEFLVL_SESSION || (flags & AES67_SDP_FLAG_STREAM_INDEX_MASK) < sdp->streams.count);

    if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) == AES67_SDP_FLAG_DEFLVL_SESSION ){
        return sdp->nptp;
    }
    if ((flags & AES67_SDP_FLAG_DEFLVL_MASK) == AES67_SDP_FLAG_DEFLVL_STREAM){
        return sdp->streams.data[(flags & AES67_SDP_FLAG_STREAM_INDEX_MASK)].nptp;
    }

    return sdp->nptp + sdp->streams.data[(flags & AES67_SDP_FLAG_STREAM_INDEX_MASK)].nptp;
}

/**
 * Get ith PTP clock for given flags.
 *
 * Where either
 * - session level ptp declarations are considered only (flags = AES67_SDP_FLAG_DEFLVL_SESSION)
 * - stream level ptp declarations are considered only (flags = AES67_SDP_FLAG_DEFLVL_STREAM | <stream-index>)
 * - session and stream level ptp declarations are considered (flags = <stream-index>), ie all ptp declarations valid for a stream
 *
 * @param sdp
 * @param flags
 * @param pi
 * @return
 */
struct aes67_sdp_ptp * aes67_sdp_get_ptp(struct aes67_sdp * sdp, aes67_sdp_flags flags, u8_t pi);

/**
 * Comfort function to add new session- or media-level ptp refclock
 *
 * @param sdp
 * @param flags
 * @param pi
 * @return
 */
inline struct aes67_sdp_ptp * aes67_sdp_add_ptp(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    AES67_ASSERT("sdp != NULL", sdp != NULL);
    AES67_ASSERT("(flags & AES67_SDP_FLAG_DEFLVL_MASK) != 0", (flags & AES67_SDP_FLAG_DEFLVL_MASK) != 0);
    AES67_ASSERT("sdp->ptps.count < AES67_SDP_MAXPTPS", sdp->ptps.count < AES67_SDP_MAXPTPS);

    struct aes67_sdp_ptp * ptp = &sdp->ptps.data[ sdp->ptps.count++ ];

    AES67_ASSERT("(ptp->flags &AES67_SDP_FLAG_SET_MASK) == AES67_SDP_FLAG_SET_YES", (ptp->flags &AES67_SDP_FLAG_SET_MASK) == AES67_SDP_FLAG_SET_YES);

    ptp->flags = AES67_SDP_FLAG_SET_YES | flags;

    return ptp;
}

/**
 * Returns session or media level mode
 *
 * Primary use case is assumed to be getting a stream level mode (which may not be set and fallbacks to session-level)
 *
 * @param sdp
 * @param flags     either AES67_SDP_FLAG_DEFLVL_SESSION or AES67_SDP_FLAG_DEFLVL_STREAM | <stream-index>
 * @return
 */
inline enum aes67_sdp_attr_mode aes67_sdp_get_mode(struct aes67_sdp * sdp, aes67_sdp_flags flags)
{
    // if specifically requested session level mode return it
    if ((flags & AES67_SDP_FLAG_DEFLVL_SESSION) == AES67_SDP_FLAG_DEFLVL_SESSION){
        return sdp->mode;
    }
    // if media/stream level attribute is not set fallback to session level value
    if (sdp->streams.data[flags & AES67_SDP_FLAG_STREAM_INDEX_MASK].mode == aes67_sdp_attr_mode_undefined){
        return sdp->mode;
    }
    // otherwise just return the media level attribute
    return sdp->streams.data[flags & AES67_SDP_FLAG_STREAM_INDEX_MASK].mode;
}

/**
 * Compares two SDP structs w.r.t. originator NOT considering the (ever increasing) session version
 *
 * NOTE the unicast address is compared bytewise, ie if one is given as IP and the other as hostname it will
 * not be considered equal even if it may indeed be the same device.
 *
 * Also see aes67_sdp_origin_cmpversion
 *
 * @param lhs
 * @param rhs
 * @return          1 (iff originator is equal), 0 otherwise
 */
u8_t aes67_sdp_origin_eq(struct aes67_sdp_originator *lhs, struct aes67_sdp_originator *rhs);

/**
 * Compares two SDP structs denoting the same originator w.r.t. the version.
 *
 * Note: only compares version. Requires prior originator match (see aes67_sdp_origin_eq)
 *
 * @param lhs
 * @param rhs
 * @return          -1 (iff lhs version is earlier), 0 (iff version is equal), 1 (iff lhs version is later)
 */
s32_t aes67_sdp_origin_cmpversion(struct aes67_sdp_originator *lhs, struct aes67_sdp_originator *rhs);


/**
 * Writes originator line to given memory.
 *
 * @param str
 * @param maxlen    max length of target buffer <str>
 * @param origin
 * @return          length of string, 0 if maxlen too short
 */
u32_t aes67_sdp_origin_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_originator * origin);

/**
 * Write SDP conform connection ("c=..") option of first connection in list <cons> matching criteria in <flags>
 *
 * Note: there SHOULD only be one such match at most.
 *
 * @param str
 * @param maxlen    max length of target buffer <str>
 * @param cons
 * @param flags     either AES67_SDP_FLAG_DEFLVL_SESSION or AES67_SDP_FLAG_DEFLVL_STREAM | <stream-index>
 * @return          length of string, -1 if maxlen too short
 */
u32_t aes67_sdp_connections_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_connection_list * cons, aes67_sdp_flags flags);


/**
 * Writes SDP conform ts-refclk attributes of all clocks in list <ptps> matching <flags>
 *
 * @param str
 * @param maxlen    max length of target buffer <str>
 * @param ptps
 * @param flags     either AES67_SDP_FLAG_DEFLVL_SESSION or AES67_SDP_FLAG_DEFLVL_STREAM | <stream-index>
 * @return          length of string, -1 if maxlen too short
 */
u32_t aes67_sdp_ptp_tostr(u8_t * str, u32_t maxlen, struct aes67_sdp_ptp_list * ptps, aes67_sdp_flags flags);

/**
 * Write SDP conform mode (a=sendonly|recvonly|inactive|sendrecv)
 *
 * @param str
 * @param maxlen
 * @param mode
 * @return          length of string, -1 if maxlen too short
 */
u32_t aes67_sdp_attrmode_tostr( u8_t * str, u32_t maxlen, enum aes67_sdp_attr_mode mode);

/**
 * Generate SDP string from struct.
 *
 * @param str
 * @param maxlen    max length of target buffer <str>
 * @param sdp
 * @return          length of string, 0 if maxlen too short
 */
u32_t aes67_sdp_tostr(u8_t *str, u32_t maxlen, struct aes67_sdp *sdp);


/**
 * Attempts to parse given originator string(line)
 *
 * @param origin
 * @param str
 * @param len       length of string
 * @return          AES67_SDP_ERROR | AES67_SDP_OK
 */
u32_t aes67_sdp_origin_fromstr(struct aes67_sdp_originator * origin, u8_t * str, u32_t len);

/**
 * Attempts to parse given SDP string
 *
 * @param sdp
 * @param str
 * @param len       length of string
 * @return          AES67_SDP_OK | AES67_SDP_ERROR | AES67_SDP_NOMEMORY | AES67_SDP_INCOMPLETE | AES67_SDP_NOTSUPPORTED
 */
u32_t aes67_sdp_fromstr(struct aes67_sdp *sdp, u8_t *str, u32_t len, void * user_data);

/**
 * Callback for unhandled settings and attributes on session- and media-level.
 *
 * To be implemented by user.
 *
 * @param sdp
 * @param context       0 (iff skipped media), AES67_SDP_FLAG_DEFLEVEL_SESSION or AES67_SDP_FLAG_DEFLEVEL_STREAM | <stream-index> otherwise
 * @param line          non-null-terminated string
 * @param len           length of line without line delimiter
 * @param user_data     as passed to aes67_sdp_fromstr()
 */
void aes67_sdp_fromstr_unhandled(struct aes67_sdp *sdp, aes67_sdp_flags context, u8_t *line, u32_t len, void *user_data);


#ifdef __cplusplus
}
#endif


#endif //AES67_SDP_H
