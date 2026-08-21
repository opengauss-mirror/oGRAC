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
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn.c
 *
 * -------------------------------------------------------------------------
 */
#include "dtc_drc.h"
#include "dtc_shmem_scn.h"
#include "srv_instance.h"
#include "cm_atomic.h"
#include "rc_reform.h"
#include "knl_context.h"
#include "knl_database.h"
#include "knl_common.h"

static bool32 shmem_scn_enabled(void)
{
    if (g_instance == NULL) {
        return OG_FALSE;
    }

    return g_instance->kernel.attr.enable_ubsmem ? OG_TRUE : OG_FALSE;
}

static bool32 shmem_scn_reformer_ready(void)
{
    if (DB_CLUSTER_NO_CMS) {
        return OG_TRUE;
    }

    if (g_rc_ctx == NULL) {
        return OG_FALSE;
    }

    return (g_rc_ctx->info.master_id != OG_INVALID_ID8) ? OG_TRUE : OG_FALSE;
}

static shmem_scn_slot_t *shmem_scn_get_bound_slot(void)
{
    return DRC_RES_CTX->shmem_scn_mgr.global_scn_slot;
}

static knl_scn_t shmem_scn_read_local(void)
{
    if (g_instance == NULL) {
        return KNL_INVALID_SCN;
    }

    return KNL_GET_SCN(&g_instance->kernel.scn);
}

uint32 shmem_scn_get_owner_id(void)
{
    if (DB_CLUSTER_NO_CMS) {
        return 0;
    }

    if (g_rc_ctx == NULL) {
        return 0;
    }

    while (g_rc_ctx->info.master_id == OG_INVALID_ID8) {
        cm_sleep(10);
    }

    return (uint32)g_rc_ctx->info.master_id;
}

bool32 shmem_scn_is_owner(void)
{
    if (g_instance == NULL) {
        return OG_FALSE;
    }

    if (!shmem_scn_reformer_ready()) {
        return OG_FALSE;
    }

    return (g_instance->kernel.id == shmem_scn_get_owner_id()) ? OG_TRUE : OG_FALSE;
}

void shmem_scn_invalidate_cache(void)
{
    shmem_scn_mgr_t *shmem_scn_mgr = &DRC_RES_CTX->shmem_scn_mgr;

    if (shmem_scn_mgr->global_scn_slot != NULL) {
        OG_LOG_RUN_INF("[SHMEM-SCN] invalidate UB scn cache, owner=%u, scn=%llu",
            shmem_scn_mgr->owner_id,
            (uint64)ub_atomic_read_u64(&shmem_scn_mgr->global_scn_slot->value));
    }

    shmem_scn_mgr->global_scn_slot = NULL;
    shmem_scn_mgr->owner_id = OG_INVALID_ID32;
}

void shmem_scn_bind(void)
{
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    shmem_scn_mgr_t *shmem_scn_mgr = &ogx->shmem_scn_mgr;
    uint32 owner_id = shmem_scn_get_owner_id();
    shmem_scn_slot_t *slot = NULL;
    knl_scn_t local_scn;
    uint64 ub_scn;
    uint64 merged;
    bool32 was_active = (shmem_scn_mgr->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;

    if (!shmem_scn_enabled()) {
        return;
    }

    if (owner_id >= OG_MAX_INSTANCES) {
        return;
    }

    if (ogx->remote_sga.map_success[owner_id] != OG_TRUE ||
        ogx->remote_sga.remote_buf_addr[owner_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)(ogx->remote_sga.remote_buf_addr[owner_id] +
                                drc_get_shmem_scn_offset(&ogx->remote_sga));
    slot->owner_node = owner_id;

    if (g_instance != NULL) {
        local_scn = KNL_GET_SCN(&g_instance->kernel.scn);
        ub_scn = ub_atomic_read_u64(&slot->value);
        merged = MAX((uint64)local_scn, ub_scn);
        if (merged > ub_scn) {
            if (cm_ub_update_scn((uint64_t *)(void *)&slot->value, merged) != OG_SUCCESS) {
                knl_panic_log(0, "[SHMEM-SCN] merge local scn to UB failed, local=%llu, ub=%llu",
                    (uint64)local_scn, ub_scn);
            }
        }
    }

    shmem_scn_mgr->global_scn_slot = slot;
    shmem_scn_mgr->owner_id = owner_id;
    if (!was_active) {
        OG_LOG_RUN_INF("[SHMEM-SCN] activated UB shared scn, owner=%u, addr=%p, value=%llu",
            owner_id, slot, (uint64)ub_atomic_read_u64(&slot->value));
    } else {
        OG_LOG_RUN_INF("[SHMEM-SCN] bind global scn shm, owner=%u, addr=%p, value=%llu",
            owner_id, slot, (uint64)ub_atomic_read_u64(&slot->value));
    }
}

status_t shmem_scn_ensure_ub_mapped(uint32 owner_id)
{
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    uint32 scn_owner = owner_id;

    if (scn_owner >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (ogx->remote_sga.map_success[scn_owner] == OG_TRUE &&
        ogx->remote_sga.remote_buf_addr[scn_owner] != NULL) {
        return OG_SUCCESS;
    }

    if (dtc_mmap_remote_data_buf(&ogx->remote_sga, scn_owner) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t shmem_scn_rebind_if_needed(void)
{
    shmem_scn_mgr_t *shmem_scn_mgr = &DRC_RES_CTX->shmem_scn_mgr;
    uint32 owner_id;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (!shmem_scn_reformer_ready()) {
        return OG_SUCCESS;
    }

    owner_id = shmem_scn_get_owner_id();

    if (shmem_scn_mgr->global_scn_slot != NULL && shmem_scn_mgr->owner_id == owner_id) {
        return OG_SUCCESS;
    }

    shmem_scn_invalidate_cache();

    if (shmem_scn_ensure_ub_mapped(owner_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    shmem_scn_bind();
    return (shmem_scn_mgr->global_scn_slot != NULL) ? OG_SUCCESS : OG_ERROR;
}

void shmem_scn_init(void)
{
    shmem_scn_mgr_t *shmem_scn_mgr = &DRC_RES_CTX->shmem_scn_mgr;

    shmem_scn_mgr->global_scn_slot = NULL;
    shmem_scn_mgr->owner_id = OG_INVALID_ID32;

    if (!shmem_scn_enabled()) {
        return;
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] init with local scn=%llu, UB bind deferred until reformer ready",
        (uint64)shmem_scn_read_local());
}

status_t shmem_scn_sync_to_ub(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (!shmem_scn_reformer_ready()) {
        OG_LOG_RUN_INF("[SHMEM-SCN] reformer not ready, keep using local scn=%llu",
            (uint64)shmem_scn_read_local());
        return OG_SUCCESS;
    }

    if (shmem_scn_rebind_if_needed() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sync local scn to UB failed before bind, local scn=%llu",
            (uint64)shmem_scn_read_local());
        return OG_ERROR;
    }

    if (shmem_scn_get_bound_slot() == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] UB scn slot not bound after reformer ready, local scn=%llu",
            (uint64)shmem_scn_read_local());
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] sync local scn to UB done, owner=%u, value=%llu",
        DRC_RES_CTX->shmem_scn_mgr.owner_id,
        (uint64)ub_atomic_read_u64(&DRC_RES_CTX->shmem_scn_mgr.global_scn_slot->value));
    return OG_SUCCESS;
}

status_t shmem_scn_ensure_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_get_bound_slot() != NULL) {
        return OG_SUCCESS;
    }

    if (shmem_scn_sync_to_ub() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (shmem_scn_get_bound_slot() == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] UB scn not ready before open");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

bool32 shmem_scn_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_TRUE;
    }

    return (shmem_scn_get_bound_slot() != NULL) ? OG_TRUE : OG_FALSE;
}

bool32 shmem_scn_need_broadcast(void)
{
    if (g_instance == NULL) {
        return OG_FALSE;
    }

    return !shmem_scn_enabled();
}

knl_scn_t shmem_scn_read_atomic(atomic_t *local_scn)
{
    shmem_scn_slot_t *slot = NULL;

    if (local_scn == NULL) {
        return KNL_INVALID_SCN;
    }

    if (!shmem_scn_enabled()) {
        return KNL_GET_SCN(local_scn);
    }

    slot = shmem_scn_get_bound_slot();
    if (slot == NULL) {
        return KNL_GET_SCN(local_scn);
    }

    return (knl_scn_t)ub_atomic_read_u64(&slot->value);
}

void shmem_scn_update_max_atomic(atomic_t *local_scn, knl_scn_t scn)
{
    shmem_scn_slot_t *slot = NULL;
    knl_scn_t curr_scn;

    if (local_scn == NULL) {
        return;
    }

    if (!shmem_scn_enabled()) {
        curr_scn = KNL_GET_SCN(local_scn);
        if (scn > curr_scn) {
            KNL_SET_SCN(local_scn, scn);
        }
        return;
    }

    slot = shmem_scn_get_bound_slot();
    if (slot == NULL) {
        curr_scn = KNL_GET_SCN(local_scn);
        if (scn > curr_scn) {
            KNL_SET_SCN(local_scn, scn);
        }
        return;
    }

    if (cm_ub_update_scn((uint64_t *)(void *)&slot->value, (uint64)scn) != OG_SUCCESS) {
        knl_panic_log(0, "[SHMEM-SCN] update global scn on UB failed, scn=%llu", (uint64)scn);
    }
}

knl_scn_t shmem_scn_add_atomic(atomic_t *local_scn)
{
    shmem_scn_slot_t *slot = NULL;
    uint64_t old = 0;

    if (local_scn == NULL) {
        return KNL_INVALID_SCN;
    }

    if (!shmem_scn_enabled()) {
        return KNL_INC_SCN(local_scn);
    }

    slot = shmem_scn_get_bound_slot();
    if (slot == NULL) {
        return KNL_INC_SCN(local_scn);
    }

    old = ub_atomic_fetch_add_u64(&slot->value, 1);
    return (knl_scn_t)(old + 1);
}
