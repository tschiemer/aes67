/**
 * @file avp.h
 * Defines for RTP Audio and Video Profile
 *
 * References:
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc3551
 * RTP Payload Format for 12-bit DAT Audio and 20- and 24-bit Linear Sampled Audiohttps://tools.ietf.org/html/rfc3190
 * MIME Type Registration of RTP Payload Formats https://tools.ietf.org/html/rfc3555
 * Media Type Registration of RTP Payload Formats https://tools.ietf.org/html/rfc4855
 * RTP Profile for Audio and Video Conferences with Minimal Control https://tools.ietf.org/html/rfc1890
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

#ifndef AES67_RTP_AVP_H
#define AES67_RTP_AVP_H

#define AES67_RTP_AVP_PROFILE_STR   "RTP/AVP"

#define AES67_RTP_AVP_PAYLOADTYPE_A_PCMU_8k_1ch     0
#define AES67_RTP_AVP_PAYLOADTYPE_A_GSM_8k_1ch      3
#define AES67_RTP_AVP_PAYLOADTYPE_A_G723_8k_1ch     4
#define AES67_RTP_AVP_PAYLOADTYPE_A_DVI4_8k_1ch     5
#define AES67_RTP_AVP_PAYLOADTYPE_A_DVI4_16k_1ch    6
#define AES67_RTP_AVP_PAYLOADTYPE_A_LPC_8k_1ch      7
#define AES67_RTP_AVP_PAYLOADTYPE_A_PCMA_8k_1ch     8
#define AES67_RTP_AVP_PAYLOADTYPE_A_G722_8k_1ch     9
#define AES67_RTP_AVP_PAYLOADTYPE_A_L16_44100_2ch   10
#define AES67_RTP_AVP_PAYLOADTYPE_A_L16_44100_1ch   11
#define AES67_RTP_AVP_PAYLOADTYPE_A_QCELP_8k_1ch    12
#define AES67_RTP_AVP_PAYLOADTYPE_A_CN_8k_1ch       13
#define AES67_RTP_AVP_PAYLOADTYPE_A_MPA_90k         14
#define AES67_RTP_AVP_PAYLOADTYPE_A_G728_8k_1ch     15
#define AES67_RTP_AVP_PAYLOADTYPE_A_DVI4_11025_1ch  16
#define AES67_RTP_AVP_PAYLOADTYPE_A_DVI4_22050_1ch  17
#define AES67_RTP_AVP_PAYLOADTYPE_A_G729_8k_1ch     18
#define AES67_RTP_AVP_PAYLOADTYPE_V_CELB_90k        25
#define AES67_RTP_AVP_PAYLOADTYPE_V_JP_90k          26
#define AES67_RTP_AVP_PAYLOADTYPE_V_NV_90k          28
#define AES67_RTP_AVP_PAYLOADTYPE_V_H261_90k        31
#define AES67_RTP_AVP_PAYLOADTYPE_V_MPV_90k         32
#define AES67_RTP_AVP_PAYLOADTYPE_AV_MP2T_90k       33
#define AES67_RTP_AVP_PAYLOADTYPE_V_H263_90k        34

#define AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START     96
#define AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_END       127

#define AES67_RTP_AVP_PAYLOADTYPE_IS_DYNAMIC(x)     (AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_START <= (x) && (x) <= AES67_RTP_AVP_PAYLOADTYPE_DYNAMIC_END)

#define AES67_RTP_AVP_MIMETYPE_DVI4         "audio/DVI4"
#define AES67_RTP_AVP_MIMETYPE_G722         "audio/G722"
#define AES67_RTP_AVP_MIMETYPE_G723         "audio/G723"
#define AES67_RTP_AVP_MIMETYPE_G726_16      "audio/G726-16"
#define AES67_RTP_AVP_MIMETYPE_G726_24      "audio/G726-24"
#define AES67_RTP_AVP_MIMETYPE_G726_32      "audio/G726-32"
#define AES67_RTP_AVP_MIMETYPE_G726_40      "audio/G726-40"
#define AES67_RTP_AVP_MIMETYPE_G728         "audio/G278"
#define AES67_RTP_AVP_MIMETYPE_G729         "audio/G729"
#define AES67_RTP_AVP_MIMETYPE_G729D        "audio/G729D"
#define AES67_RTP_AVP_MIMETYPE_G729E        "audio/G729E"
#define AES67_RTP_AVP_MIMETYPE_GSM          "audio/GSM"
#define AES67_RTP_AVP_MIMETYPE_GSM_EFR      "audio/GSM-EFR"
#define AES67_RTP_AVP_MIMETYPE_L8           "audio/L8"
#define AES67_RTP_AVP_MIMETYPE_L16          "audio/L16"
#define AES67_RTP_AVP_MIMETYPE_L20          "audio/L20"
#define AES67_RTP_AVP_MIMETYPE_L24          "audio/L24"
#define AES67_RTP_AVP_MIMETYPE_DAT12        "audio/DAT12"
#define AES67_RTP_AVP_MIMETYPE_LPC          "audio/LPC"
#define AES67_RTP_AVP_MIMETYPE_MPA          "audio/MPA"
#define AES67_RTP_AVP_MIMETYPE_PCMA         "audio/PCMA"
#define AES67_RTP_AVP_MIMETYPE_PCMU         "audio/PCMU"
#define AES67_RTP_AVP_MIMETYPE_QCELP        "audio/QCELP"
#define AES67_RTP_AVP_MIMETYPE_RED          "audio/RED"
#define AES67_RTP_AVP_MIMETYPE_VDVI         "audio/VDVI"
#define AES67_RTP_AVP_MIMETYPE_BT656        "video/BT656"
#define AES67_RTP_AVP_MIMETYPE_CELB         "video/CelB"
#define AES67_RTP_AVP_MIMETYPE_JPEG         "video/JPEG"
#define AES67_RTP_AVP_MIMETYPE_H261         "video/H261"
#define AES67_RTP_AVP_MIMETYPE_H263         "video/H263"
#define AES67_RTP_AVP_MIMETYPE_H263_1998    "video/H263-1998"
#define AES67_RTP_AVP_MIMETYPE_H263_2000    "video/H263-2000"
#define AES67_RTP_AVP_MIMETYPE_MPV          "video/MPV"
#define AES67_RTP_AVP_MIMETYPE_MP2T         "video/MP2T"
#define AES67_RTP_AVP_MIMETYPE_MP1S         "video/MP1S"
#define AES67_RTP_AVP_MIMETYPE_MP2P         "video/MP2P"
#define AES67_RTP_AVP_MIMETYPE_BMPEG        "video/BMPEG"
#define AES67_RTP_AVP_MIMETYPE_NV           "video/nv"

//#define AES67_RTP_AVP_CHORDER_AIFFC
//#define AES67_RTP_AVP_CHORDER_DV

#define AES67_RTP_AVP_CHORDER_

#endif //AES67_RTP_AVP_H
