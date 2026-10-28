/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_ub_sdk.h
 *        UB (unified bus) SDK: locally declared lock types plus the runtime
 *        loader for the shared memory library.
 *
 *        The UB SDK is NOT linked and its headers are NOT required at build
 *        time. The shared memory API (ubsmem_*) is resolved with dlopen()/
 *        dlsym() the first time UB support is initialized; the distributed
 *        read-write lock keeps the in-tree atomic implementation
 *        (ub_atomic_dist_lock.c), so no SDK symbol is needed for locking.
 *
 * IDENTIFICATION
 * pkg/src/common/cm_ub_sdk.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_UB_SDK_H
#define CM_UB_SDK_H

#include <stdint.h>
#include <sys/types.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Size reserved for one distributed read-write lock inside the UB shared memory region.
 * Every instance of this build lays locks out with the same stride, so the region is
 * self-consistent; the lock body itself is defined by ub_atomic_dist_lock.c. */
#define UB_RW_LOCK_SIZE 128

typedef enum en_ub_lock_result {
    UB_LOCK_SUCCESS = 0,
    UB_LOCK_ERROR = -1
} ub_lock_result_t;

typedef struct st_ub_location {
    int32 tid;
    uint8 node_id;
} ub_location_t;

typedef struct st_ub_lock_config {
    uint32 lease_time;
    uint32 heartbeat_timeout;
} ub_lock_config_t;

typedef struct st_ub_lock_policy ub_lock_policy_t;

typedef struct ub_rw_lock ub_rw_lock_t;

#define UB_SDK_LIB_DEFAULT "/usr/local/ubs_mem/lib/libubsm_sdk.so"
#define UB_SDK_LIB_ENV "OGRAC_UB_SDK_LIB"

// Resolves every ubsmem_* entry point; on failure UB support stays disabled.
status_t cm_ub_sdk_load(void);
void cm_ub_sdk_unload(void);
bool32 cm_ub_sdk_ready(void);

#ifdef __cplusplus
}
#endif

#endif  // CM_UB_SDK_H
