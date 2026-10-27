/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd. All rights reserved.
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
 * SCN slot in global remote SGA (st_remote_sga). Each slot is 64-byte aligned.
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_SHMEM_SCN_H
#define DTC_SHMEM_SCN_H

#include "cm_defs.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SHMEM_SCN_SIZE
#define SHMEM_SCN_SIZE (64)
#endif

/* 64B slot: value + owner + pad, placed in remote SGA after node_flush_lsn. */
typedef struct st_shmem_scn_slot {
    volatile uint64 value;
    volatile uint32 owner_node;
    uint8 pad[52];
} shmem_scn_slot_t;

typedef struct st_shmem_scn_mgr {
    shmem_scn_slot_t *global_scn_slot; /* local node SCN slot; GET reads this only */
    uint32 owner_id;                   /* self node id after local bind */
    char *map_addr[OG_MAX_INSTANCES];  /* per-node SCN slot addrs (inside remote SGA) */
    bool32 map_success[OG_MAX_INSTANCES];
} shmem_scn_mgr_t;

uint32 shmem_scn_get_owner_id(void);
bool32 shmem_scn_is_owner(void);
status_t shmem_scn_init(void);
void shmem_scn_cleanup(void);
void shmem_scn_bind(void);
void shmem_scn_invalidate_cache(void);
status_t shmem_scn_rebind_if_needed(void);
status_t shmem_scn_ensure_ub_mapped(uint32 owner_id);
status_t shmem_scn_sync_to_ub(void);
status_t shmem_scn_ensure_ready(void);
bool32 shmem_scn_ready(void);
bool32 shmem_scn_need_broadcast(void);
void shmem_scn_fanout_raise(uint64 scn);
/* Raise the local SCN slot to the max of mapped peer slots. Does not fan back out. */
void shmem_scn_absorb_peers(void);
/* Read peer node's SCN slot from remote SGA (maps if needed). 0 if unavailable. */
knl_scn_t shmem_scn_read_node(uint32 node_id);
/*
 * Raise local SCN from peer's shared-memory slot; fallback_scn used if peer unread
 * or smaller (e.g. ack->scn). No peer fan-out.
 */
void shmem_scn_raise_local_from_node(knl_session_t *session, uint32 node_id, knl_scn_t fallback_scn);

#ifdef __cplusplus
}
#endif
#endif
