/*
 *  Copyright (c) 2024, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file includes compile-time configurations for TREL.
 */

#ifndef CONFIG_TREL_H_
#define CONFIG_TREL_H_

/**
 * @addtogroup config-trel
 *
 * @brief
 *   This module includes configuration variables for TREL.
 *
 * @{
 */

/**
 * @def OPENTHREAD_CONFIG_TREL_MANAGE_DNSSD_ENABLE
 *
 * Define as 1 to have the OpenThread core TREL implementation directly manage mDNS (DNS-SD) service registration
 * and peer discovery (browse and service/address resolution of TREL service for TREL peer discovery).
 *
 * When this feature is disabled, the mDNS (DNS-SD) functions are delegated to the platform layer. More details are
 * provided in the `platform/trel.h` API documentation.
 */
#ifndef OPENTHREAD_CONFIG_TREL_MANAGE_DNSSD_ENABLE
#define OPENTHREAD_CONFIG_TREL_MANAGE_DNSSD_ENABLE 0
#endif

/**
 * @def OPENTHREAD_CONFIG_TREL_USE_HEAP_ENABLE
 *
 * Define as 1 to allow TREL modules to use heap allocated objects (e.g. for the TREL peer table).
 */
#ifndef OPENTHREAD_CONFIG_TREL_USE_HEAP_ENABLE
#define OPENTHREAD_CONFIG_TREL_USE_HEAP_ENABLE OPENTHREAD_CONFIG_TREL_MANAGE_DNSSD_ENABLE
#endif

/**
 * @def OPENTHREAD_CONFIG_TREL_PEER_TABLE_SIZE
 *
 * Specifies the capacity of TREL peer table. Only non-zero value will be directly used for setting the TREL peer table
 * capacity. Zero value lets the size to be determined by the OT stack itself which is derived based on other
 * configurations such as a child table size, neighbor table size, etc.
 *
 * Applicable when `OPENTHREAD_CONFIG_TREL_USE_HEAP_ENABLE` is not used.
 */
#ifndef OPENTHREAD_CONFIG_TREL_PEER_TABLE_SIZE
#define OPENTHREAD_CONFIG_TREL_PEER_TABLE_SIZE (0)
#endif

/**
 * @}
 */

#endif // CONFIG_TREL_H_
