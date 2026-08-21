/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dtc_shmem_scn.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_SHMEM_SCN_H
#define DTC_SHMEM_SCN_H

#include "knl_session.h"
#include "dtc_remote_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_shmem_scn_slot {
    volatile uint64 value;
    volatile uint32 owner_node;
    uint8 pad[52];
} shmem_scn_slot_t;

typedef struct st_shmem_scn_mgr {
    shmem_scn_slot_t *global_scn_slot;  /* cached slot on reformer UB, set after mmap bind */
    uint32 owner_id;                    /* cached reformer node id */
} shmem_scn_mgr_t;

uint32 shmem_scn_get_owner_id(void);
bool32 shmem_scn_is_owner(void);
void shmem_scn_init(void);
void shmem_scn_bind(void);
void shmem_scn_invalidate_cache(void);
status_t shmem_scn_rebind_if_needed(void);
status_t shmem_scn_ensure_ub_mapped(uint32 owner_id);
status_t shmem_scn_sync_to_ub(void);
status_t shmem_scn_ensure_ready(void);
bool32 shmem_scn_ready(void);
bool32 shmem_scn_need_broadcast(void);
knl_scn_t shmem_scn_read_atomic(atomic_t *local_scn);
knl_scn_t shmem_scn_add_atomic(atomic_t *local_scn);
void shmem_scn_update_max_atomic(atomic_t *local_scn, knl_scn_t scn);

#ifdef __cplusplus
}
#endif
#endif
