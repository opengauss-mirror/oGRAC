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
 * dtc_shmem_scn.c
 *
 * Multi-node SCN slots live in global remote SGA (st_remote_sga):
 *   data | dist_que | dist_lck | node_flush_lsn | shmem_scn(64B-aligned) | txn_hot...
 * GET reads the local slot. SET fan-out raises peers to the caller's value.
 * INC raises the local slot to the max peer slot, then adds 1 and fan-out.
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_drc.h"
#include "dtc_shmem_scn.h"
#include "dtc_remote_buffer.h"
#include "cm_utils.h"
#include "cm_memory.h"
#include "knl_context.h"
#include "srv_instance.h"

#ifndef WIN32
volatile uint64 *g_ub_global_scn = NULL;
#endif

CM_STATIC_ASSERT(sizeof(shmem_scn_slot_t) == SHMEM_SCN_SIZE);
CM_STATIC_ASSERT((SHMEM_SCN_SIZE % SHMEM_SCN_SLOT_ALIGN) == 0);
CM_STATIC_ASSERT(DRC_SHMEM_SCN_SIZE == SHMEM_SCN_SIZE);

static bool32 shmem_scn_enabled(void)
{
    return (g_instance != NULL && g_instance->kernel.attr.enable_ubsmem) ? OG_TRUE : OG_FALSE;
}

static inline shmem_scn_mgr_t *shmem_scn_mgr(void)
{
    return &DRC_RES_CTX->shmem_scn_mgr;
}

static inline remote_sga_t *shmem_scn_remote_sga(void)
{
    return &DRC_RES_CTX->remote_sga;
}

static uint32 shmem_scn_node_count(void)
{
    uint32 node_count;

    if (g_instance == NULL) {
        return 0;
    }

    node_count = g_instance->kernel.db.ctrl.core.node_count;
    if (node_count == 0 || node_count > OG_MAX_INSTANCES) {
        return 0;
    }
    return node_count;
}

static knl_scn_t shmem_scn_read_local(void)
{
    if (g_instance == NULL) {
        return KNL_INVALID_SCN;
    }

    return KNL_GET_SCN(&g_instance->kernel.scn);
}

static void shmem_scn_raise_local(knl_scn_t scn)
{
    knl_scn_t local_scn;

    if (g_instance == NULL) {
        return;
    }

    local_scn = KNL_GET_SCN(&g_instance->kernel.scn);
    if (scn > local_scn) {
        KNL_SET_SCN(&g_instance->kernel.scn, scn);
    }
}

uint32 shmem_scn_get_owner_id(void)
{
    if (g_instance == NULL) {
        return OG_INVALID_ID32;
    }
    return g_instance->kernel.id;
}

bool32 shmem_scn_is_owner(void)
{
    if (!shmem_scn_enabled() || g_instance == NULL) {
        return OG_FALSE;
    }
    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

static void shmem_scn_publish(shmem_scn_slot_t *slot, uint32 owner_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    mgr->global_scn_slot = slot;
    mgr->owner_id = owner_id;
#ifndef WIN32
    CM_MFENCE;
    g_ub_global_scn = &slot->value;
#endif
}

static void shmem_scn_unpublish(void)
{
#ifndef WIN32
    g_ub_global_scn = NULL;
    CM_MFENCE;
#endif
    shmem_scn_mgr()->global_scn_slot = NULL;
    shmem_scn_mgr()->owner_id = OG_INVALID_ID32;
}

void shmem_scn_invalidate_cache(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot = mgr->global_scn_slot;
    knl_scn_t ub_scn;

    if (slot != NULL) {
        ub_scn = (knl_scn_t)ub_atomic_read_u64(&slot->value);
        OG_LOG_RUN_INF("[SHMEM-SCN] invalidate local scn slot, self=%u, scn=%llu", mgr->owner_id, (uint64)ub_scn);
        shmem_scn_raise_local(ub_scn);
    }

    shmem_scn_unpublish();
}

#ifndef WIN32
static shmem_scn_slot_t *shmem_scn_slot_of(uint32 node_id)
{
    char *addr = drc_get_shmem_scn_addr(shmem_scn_remote_sga(), node_id);

    if (addr == NULL) {
        return NULL;
    }
    if (((uint64)addr % SHMEM_SCN_SLOT_ALIGN) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] slot addr %p on node %u is not %u-byte aligned", addr, node_id,
            (uint32)SHMEM_SCN_SLOT_ALIGN);
        return NULL;
    }
    return (shmem_scn_slot_t *)addr;
}

static status_t shmem_scn_map_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    remote_sga_t *rsga = shmem_scn_remote_sga();
    shmem_scn_slot_t *slot;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (mgr->map_success[node_id] == OG_TRUE && mgr->map_addr[node_id] != NULL) {
        return OG_SUCCESS;
    }

    if (rsga->map_success[node_id] != OG_TRUE || rsga->remote_buf_addr[node_id] == NULL) {
        if (dtc_mmap_remote_data_buf(rsga, node_id) != OG_SUCCESS) {
            if (g_instance != NULL && node_id == g_instance->kernel.id) {
                OG_LOG_RUN_ERR("[SHMEM-SCN] map local remote SGA for scn failed, node=%u", node_id);
            } else {
                OG_LOG_DEBUG_INF("[SHMEM-SCN] map peer remote SGA for scn not ready, node=%u", node_id);
            }
            return OG_ERROR;
        }
    }

    slot = shmem_scn_slot_of(node_id);
    if (slot == NULL) {
        return OG_ERROR;
    }

    mgr->map_addr[node_id] = (char *)slot;
    mgr->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[SHMEM-SCN] bound remote-sga scn slot node=%u, addr=%p, offset=%llu", node_id, slot,
        drc_get_shmem_scn_offset(rsga));
    return OG_SUCCESS;
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    if (node_id >= OG_MAX_INSTANCES) {
        return;
    }

    /* Slot memory belongs to remote SGA; only drop local references. */
    mgr->map_addr[node_id] = NULL;
    mgr->map_success[node_id] = OG_FALSE;
}

static status_t shmem_scn_create_local(void)
{
    uint32 self_id;
    remote_sga_t *rsga = shmem_scn_remote_sga();

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (rsga->remote_buf_addr[self_id] == NULL || rsga->shmem_scn == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] remote SGA scn slot not ready, self=%u, remote_buf=%p, shmem_scn=%p", self_id,
            rsga->remote_buf_addr[self_id], rsga->shmem_scn);
        return OG_ERROR;
    }

    if (((uint64)rsga->shmem_scn % SHMEM_SCN_SLOT_ALIGN) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] remote_sga.shmem_scn %p is not %u-byte aligned", rsga->shmem_scn,
            (uint32)SHMEM_SCN_SLOT_ALIGN);
        return OG_ERROR;
    }

    return shmem_scn_map_node(self_id);
}

status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    return shmem_scn_map_node(node_id);
}

static void shmem_scn_try_map_peers(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        if (mgr->map_success[i] == OG_TRUE && mgr->map_addr[i] != NULL) {
            continue;
        }
        (void)shmem_scn_map_node(i);
    }
}

static void shmem_scn_raise_peer_slot(uint32 node_id, uint64 scn)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot;

    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[node_id];
    ub_atomic_raise_u64(&slot->value, scn);
}

void shmem_scn_fanout_raise(uint64 scn)
{
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (!shmem_scn_enabled() || scn == 0 || g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        shmem_scn_raise_peer_slot(i, scn);
    }
}

static uint64 shmem_scn_read_mapped(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot;

    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return 0;
    }
    slot = (shmem_scn_slot_t *)mgr->map_addr[node_id];
    return ub_atomic_read_u64(&slot->value);
}

void shmem_scn_absorb_peers(void)
{
    uint32 self_id;
    uint32 node_count;
    uint32 i;
    uint64 peer_max = 0;

    if (!shmem_scn_enabled() || g_instance == NULL || g_ub_global_scn == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    for (i = 0; i < node_count; i++) {
        uint64 peer_scn;

        if (i == self_id) {
            continue;
        }
        peer_scn = shmem_scn_read_mapped(i);
        if (peer_scn > peer_max) {
            peer_max = peer_scn;
        }
    }
    if (peer_max != 0) {
        ub_atomic_raise_u64(g_ub_global_scn, peer_max);
    }
}

void shmem_scn_bind(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;
    knl_scn_t local_scn;
    uint64 ub_scn = 0;
    uint64 merged = 0;
    bool32 was_active;

    if (!shmem_scn_enabled() || g_instance == NULL) {
        return;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    local_scn = shmem_scn_read_local();
    was_active = (mgr->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;

    slot->owner_node = self_id;
    ub_scn = ub_atomic_read_u64(&slot->value);
    merged = MAX((uint64)local_scn, ub_scn);
    ub_atomic_raise_u64(&slot->value, merged);

    shmem_scn_raise_local((knl_scn_t)merged);
    shmem_scn_publish(slot, self_id);
    OG_LOG_RUN_INF("[SHMEM-SCN] %s remote-sga scn slot, self=%u, addr=%p, value=%llu",
        was_active ? "rebind" : "bind", self_id, slot, merged);
}
#else
status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    (void)node_id;
    return OG_ERROR;
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    (void)node_id;
}

static status_t shmem_scn_create_local(void)
{
    return OG_SUCCESS;
}

void shmem_scn_bind(void)
{
}

static void shmem_scn_try_map_peers(void)
{
}

void shmem_scn_fanout_raise(uint64 scn)
{
    (void)scn;
}

void shmem_scn_absorb_peers(void)
{
}
#endif

static bool32 shmem_scn_is_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;

    if (g_instance == NULL) {
        return OG_FALSE;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_FALSE;
    }

    if (mgr->global_scn_slot == NULL || mgr->owner_id != self_id) {
        return OG_FALSE;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return OG_FALSE;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    return (slot == mgr->global_scn_slot) ? OG_TRUE : OG_FALSE;
}

static status_t shmem_scn_ensure_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    if (shmem_scn_is_local_bound()) {
        return OG_SUCCESS;
    }

    self_id = g_instance->kernel.id;
    if (shmem_scn_ensure_ub_mapped(self_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (mgr->global_scn_slot == NULL) {
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

status_t shmem_scn_rebind_if_needed(void)
{
    return shmem_scn_ensure_local_bound();
}

static void shmem_scn_reset_mgr(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    MEMS_RETVOID_IFERR(memset_s(mgr, sizeof(shmem_scn_mgr_t), 0, sizeof(shmem_scn_mgr_t)));
    mgr->owner_id = OG_INVALID_ID32;
}

status_t shmem_scn_init(void)
{
    shmem_scn_reset_mgr();
    shmem_scn_unpublish();
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    /* remote SGA (incl. scn slot) is created in drc_init_remote_buffer() before this. */
    if (shmem_scn_create_local() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] bind local remote-sga scn slot failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] publish local scn slot failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] init in remote SGA done, self=%u, offset=%llu, local_scn=%llu, peer fan-out deferred",
        g_instance->kernel.id, drc_get_shmem_scn_offset(shmem_scn_remote_sga()), (uint64)shmem_scn_read_local());
    return OG_SUCCESS;
}

void shmem_scn_cleanup(void)
{
    shmem_scn_mgr_t *mgr;
    uint32 i;

    if (g_instance == NULL || DRC_RES_CTX == NULL) {
        return;
    }

    mgr = shmem_scn_mgr();
    shmem_scn_invalidate_cache();

    for (i = 0; i < OG_MAX_INSTANCES; i++) {
        shmem_scn_unmap_node(i);
    }

    (void)mgr;
}

status_t shmem_scn_sync_to_ub(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    knl_scn_t scn;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || mgr->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sync local remote-sga slot failed, local scn=%llu",
            (uint64)shmem_scn_read_local());
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();

    scn = KNL_GET_UB_SCN(&g_instance->kernel.scn);
    shmem_scn_fanout_raise((uint64)scn);
    OG_LOG_RUN_INF("[SHMEM-SCN] sync remote-sga slots done, self=%u, value=%llu", mgr->owner_id, (uint64)scn);
    return OG_SUCCESS;
}

status_t shmem_scn_ensure_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] local scn slot not ready before open");
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

bool32 shmem_scn_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_TRUE;
    }

    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

bool32 shmem_scn_need_broadcast(void)
{
#ifndef WIN32
    return (g_ub_global_scn == NULL) ? OG_TRUE : OG_FALSE;
#else
    return OG_TRUE;
#endif
}
