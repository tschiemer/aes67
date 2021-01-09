/**
 * @file
 * Debug messages infrastructure
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 * Adapted for AES67
 *
 */
#ifndef AES67_DEBUG_H
#define AES67_DEBUG_H

#include "aes67/arch.h"
#include "aes67/opt.h"

/**
 * @defgroup debugging_levels AES67_DBG_MIN_LEVEL and AES67_DBG_TYPES_ON values
 * @ingroup AES67_opts_debugmsg
 * @{
 */

/** @name Debug level (AES67_DBG_MIN_LEVEL)
 * @{
 */
/** Debug level: ALL messages*/
#define AES67_DBG_LEVEL_ALL     0x00
/** Debug level: Warnings. bad checksums, dropped packets, ... */
#define AES67_DBG_LEVEL_WARNING 0x01
/** Debug level: Serious. memory allocation failures, ... */
#define AES67_DBG_LEVEL_SERIOUS 0x02
/** Debug level: Severe */
#define AES67_DBG_LEVEL_SEVERE  0x03
/**
 * @}
 */

#define AES67_DBG_MASK_LEVEL    0x03
/* compatibility define only */
#define AES67_DBG_LEVEL_OFF     AES67_DBG_LEVEL_ALL

/** @name Enable/disable debug messages completely (AES67_DBG_TYPES_ON)
 * @{
 */
/** flag for AES67_DEBUGF to enable that debug message */
#define AES67_DBG_ON            0x80U
/** flag for AES67_DEBUGF to disable that debug message */
#define AES67_DBG_OFF           0x00U
/**
 * @}
 */

/** @name Debug message types (AES67_DBG_TYPES_ON)
 * @{
 */
/** flag for AES67_DEBUGF indicating a tracing message (to follow program flow) */
#define AES67_DBG_TRACE         0x40U
/** flag for AES67_DEBUGF indicating a state debug message (to follow module states) */
#define AES67_DBG_STATE         0x20U
/** flag for AES67_DEBUGF indicating newly added code, not thoroughly tested yet */
#define AES67_DBG_FRESH         0x10U
/** flag for AES67_DEBUGF to halt after printing this debug message */
#define AES67_DBG_HALT          0x08U
/**
 * @}
 */

/**
 * @}
 */

/**
 * @defgroup AES67_assertions Assertion handling
 * @ingroup AES67_opts_debug
 * @{
 */
/**
 * AES67_NOASSERT: Disable AES67_ASSERT checks:
 * To disable assertions define AES67_NOASSERT in arch/cc.h.
 */
#ifdef __DOXYGEN__
#define AES67_NOASSERT
#undef AES67_NOASSERT
#endif
/**
 * @}
 */

#ifndef AES67_NOASSERT
#define AES67_ASSERT(message, assertion) do { if (!(assertion)) { \
  AES67_PLATFORM_ASSERT(message); }} while(0)
#else  /* AES67_NOASSERT */
#define AES67_ASSERT(message, assertion)
#endif /* AES67_NOASSERT */

#ifndef AES67_ERROR
#ifdef AES67_DEBUG
#define AES67_PLATFORM_ERROR(message) AES67_PLATFORM_DIAG((message))
#else
#define AES67_PLATFORM_ERROR(message)
#endif

/* if "expression" isn't true, then print "message" and execute "handler" expression */
#define AES67_ERROR(message, expression, handler) do { if (!(expression)) { \
  AES67_PLATFORM_ERROR(message); handler;}} while(0)
#endif /* AES67_ERROR */

/** Enable debug message printing, but only if debug message type is enabled
 *  AND is of correct type AND is at least AES67_DBG_LEVEL.
 */
#ifdef __DOXYGEN__
#define AES67_DEBUG
#undef AES67_DEBUG
#endif

#ifdef AES67_DEBUG
#define AES67_DEBUG_ENABLED(debug) (((debug) & AES67_DBG_ON) && \
                                   ((debug) & AES67_DBG_TYPES_ON) && \
                                   ((s16_t)((debug) & AES67_DBG_MASK_LEVEL) >= AES67_DBG_MIN_LEVEL))

#define AES67_DEBUGF(debug, message) do { \
                               if (AES67_DEBUG_ENABLED(debug)) { \
                                 AES67_PLATFORM_DIAG(message); \
                                 if ((debug) & AES67_DBG_HALT) { \
                                   while(1); \
                                 } \
                               } \
                             } while(0)

#else  /* AES67_DEBUG */
#define AES67_DEBUG_ENABLED(debug) 0
#define AES67_DEBUGF(debug, message)
#endif /* AES67_DEBUG */


#endif //AES67_DEBUG_H
