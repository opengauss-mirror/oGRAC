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
 * dtc_remote_lock.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_lock.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_session.h"
#include "dtc_remote_lock.h"
#include "cm_spinlock.h"
#include "srv_instance.h"
#include "cm_atomic.h"

void ub_rw_lock_debug_read(const ub_rw_lock_t *lock, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid, int32 *readonly, int32 *readonly_owner_node,
    int32 *readonly_owner_tid);
#define UB_GBP_LAT_CAP 8192

typedef enum en_ub_lat_hist_id {
    UB_LAT_GBP_LOCK_X = 0,
    UB_LAT_GBP_LOCK_S,
    UB_LAT_HOT_REFRESH,
    UB_LAT_HOT_VALIDATED_HIT,
    UB_LAT_HIST_COUNT
} ub_lat_hist_id_t;

typedef struct st_ub_gbp_lat_hist {
    spinlock_t lock;
    uint32 size;
    uint32 next;
    uint64 samples[UB_GBP_LAT_CAP];
} ub_gbp_lat_hist_t;

static ub_gbp_lat_hist_t g_ub_lat_hist[UB_LAT_HIST_COUNT] = { 0 };

static int ub_gbp_lat_cmp_u64(const void *a, const void *b)
{
    uint64 va = *(const uint64 *)a;
    uint64 vb = *(const uint64 *)b;

    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static void drc_ub_lat_hist_record(ub_lat_hist_id_t id, uint64 value)
{
    ub_gbp_lat_hist_t *hist;

    if (id >= UB_LAT_HIST_COUNT) {
        return;
    }
    hist = &g_ub_lat_hist[id];
    cm_spin_lock(&hist->lock, NULL);
    hist->samples[hist->next] = value;
    hist->next = (hist->next + 1) % UB_GBP_LAT_CAP;
    if (hist->size < UB_GBP_LAT_CAP) {
        hist->size++;
    }
    cm_spin_unlock(&hist->lock);
}

static void drc_ub_lat_hist_percentile(ub_lat_hist_id_t id, uint64 *p80_v, uint64 *p90_v, uint64 *p80_count,
    uint64 *p90_count)
{
    ub_gbp_lat_hist_t *hist;
    uint64 local[UB_GBP_LAT_CAP];
    uint32 n;
    uint32 i;
    uint64 p80;
    uint64 p90;
    uint64 c80 = 0;
    uint64 c90 = 0;

    if (p80_v != NULL) {
        *p80_v = 0;
    }
    if (p90_v != NULL) {
        *p90_v = 0;
    }
    if (p80_count != NULL) {
        *p80_count = 0;
    }
    if (p90_count != NULL) {
        *p90_count = 0;
    }
    if (id >= UB_LAT_HIST_COUNT) {
        return;
    }

    hist = &g_ub_lat_hist[id];
    cm_spin_lock(&hist->lock, NULL);
    n = hist->size;
    if (n > 0) {
        errno_t err = memcpy_s(local, sizeof(local), hist->samples, (size_t)n * sizeof(uint64));
        cm_spin_unlock(&hist->lock);
        if (SECUREC_UNLIKELY(err != EOK)) {
            return;
        }
    } else {
        cm_spin_unlock(&hist->lock);
        return;
    }

    qsort(local, n, sizeof(uint64), ub_gbp_lat_cmp_u64);
    p80 = local[(n - 1) * 80 / 100];
    p90 = local[(n - 1) * 90 / 100];
    for (i = 0; i < n; i++) {
        if (local[i] >= p80) {
            c80++;
        }
        if (local[i] >= p90) {
            c90++;
        }
    }

    if (p80_v != NULL) {
        *p80_v = p80;
    }
    if (p90_v != NULL) {
        *p90_v = p90;
    }
    if (p80_count != NULL) {
        *p80_count = c80;
    }
    if (p90_count != NULL) {
        *p90_count = c90;
    }
}

uint8 drc_gbp_lock_home_node(uint64 lock_ptr)
{
    if (lock_ptr >= (uint64)DRC_BASE_ADDR_1) {
        return 1;
    }
    if (lock_ptr >= (uint64)DRC_BASE_ADDR_0) {
        return 0;
    }
    return OG_INVALID_ID8;
}

void drc_gbp_lock_lat_record(bool32 is_x, uint64 time_us)
{
    drc_ub_lat_hist_record(is_x ? UB_LAT_GBP_LOCK_X : UB_LAT_GBP_LOCK_S, time_us);
}

void drc_gbp_lock_lat_percentile(bool32 is_x, uint64 *p80_us, uint64 *p90_us, uint64 *p80_count, uint64 *p90_count)
{
    drc_ub_lat_hist_percentile(is_x ? UB_LAT_GBP_LOCK_X : UB_LAT_GBP_LOCK_S, p80_us, p90_us, p80_count, p90_count);
}

void drc_ub_path_lat_record(bool32 is_hot_refresh, uint64 time_us)
{
    drc_ub_lat_hist_record(is_hot_refresh ? UB_LAT_HOT_REFRESH : UB_LAT_HOT_VALIDATED_HIT, time_us);
}

void drc_ub_path_lat_percentile(bool32 is_hot_refresh, uint64 *p80_us, uint64 *p90_us, uint64 *p80_count,
    uint64 *p90_count)
{
    drc_ub_lat_hist_percentile(is_hot_refresh ? UB_LAT_HOT_REFRESH : UB_LAT_HOT_VALIDATED_HIT, p80_us, p90_us,
        p80_count, p90_count);
}


// The distributed lock is the in-tree atomic implementation (ub_atomic_dist_lock.c),
// so there is no SDK lock queue to initialise.
status_t init_lock_comm_queue()
{
    return OG_SUCCESS;
}

void drc_init_remote_lock(ub_rw_lock_t **ub_lock, ub_lock_config_t *config, ub_location_t *creator)
{
    uint32 node_id = g_instance->kernel.id;
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    uint64 lck_offset = drc_get_dist_lck_offset(remote_sga);

    *ub_lock = (ub_rw_lock_t *)(remote_sga->remote_buf_addr[node_id] + lck_offset);
    remote_sga->lock_buf = (char *)(*ub_lock);
    remote_sga->remote_pool_reserve_offset = lck_offset + remote_sga->remote_lock_alloc_size;
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] remote lock buf addr start: %p, lock_alloc_size: %llu, reserve offset: %llu",
                   *ub_lock, remote_sga->remote_lock_alloc_size, remote_sga->remote_pool_reserve_offset);

    config->lease_time = 60000;
    config->heartbeat_timeout = 500;

    creator->tid = (int32_t)cm_get_current_thread_id();
    creator->node_id = (uint8_t)node_id;
}

static ub_location_t make_location(uint8 node_id)
{
    ub_location_t loc;
    loc.node_id = node_id;
    loc.tid = (int32_t)cm_get_current_thread_id();

    return loc;
}
// The following API implementation are same with atmoic lock
status_t drc_gbp_distribute_lock(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, latch_mode_t mode)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }
    // OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] start to get lock address for offset: %p", lock);
    int ret;
    const char *lock_type;
    drc_lock_mode_e lock_mode = (mode == LATCH_MODE_S ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE);
    ub_location_t lock_location = make_location((uint8)DCS_SELF_INSTID(session));

    if (lock_mode == DRC_LOCK_EXCLUSIVE) {
        ret = ub_rw_lock_x_lock(lock, NULL, &lock_location);
        lock_type = "exlcusive";
    } else {
        ret = ub_rw_lock_s_lock(lock, NULL, &lock_location);
        lock_type = "shared";
    }

    if (ret != UB_LOCK_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to acquire %s lock for page (%u-%u):%d", lock_type, page_id.file,
                       page_id.page, ret);
        return OG_ERROR;
    }

    // OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] Success to acquire %s lock for page (%u-%u):%d", lock_type, page_id.file,
    //                page_id.page, ret);
    return OG_SUCCESS;
}

void drc_gbp_begin_page_store(knl_session_t *session, uint64 lock_ptr)
{
    (void)session;
    if (lock_ptr == 0) {
        OG_LOG_DEBUG_INF("[GBP-LOCK-READONLY-DIAG][begin_page_store] skip lock_ptr=0 tid:%d",
            (int32)cm_get_current_thread_id());
        return;
    }
    ub_rw_lock_begin_page_store((ub_rw_lock_t *)(uintptr_t)lock_ptr);
}

void drc_gbp_end_page_store(knl_session_t *session, uint64 lock_ptr)
{
    (void)session;
    if (lock_ptr == 0) {
        OG_LOG_DEBUG_INF("[GBP-LOCK-READONLY-DIAG][end_page_store] skip lock_ptr=0 tid:%d",
            (int32)cm_get_current_thread_id());
        return;
    }

    ub_rw_lock_end_page_store((ub_rw_lock_t *)(uintptr_t)lock_ptr);
}

status_t drc_gbp_distribute_lock_for_store(knl_session_t *session, uint64 lock_ptr, page_id_t page_id)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }

    ub_location_t lock_location = make_location((uint8)DCS_SELF_INSTID(session));
    int ret = ub_rw_lock_x_lock_for_store(lock, &lock_location);
    if (ret != UB_LOCK_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to acquire store exclusive lock for page (%u-%u):%d",
            page_id.file, page_id.page, ret);
        return OG_ERROR;
    }

    // OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] Success to acquire store exclusive lock for page (%u-%u):%d",
    //     page_id.file, page_id.page, ret);
    return OG_SUCCESS;
}

status_t drc_gbp_distribute_lock_reenter(knl_session_t *session, uint64 lock_ptr, page_id_t page_id)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }

    ub_location_t lock_location = make_location((uint8)DCS_SELF_INSTID(session));
    int ret = ub_rw_lock_x_lock_reenter(lock, &lock_location);
    if (ret != UB_LOCK_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to acquire reenter exclusive lock for page (%u-%u):%d",
            page_id.file, page_id.page, ret);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] Success to acquire reenter exclusive lock for page (%u-%u):%d",
        page_id.file, page_id.page, ret);
    return OG_SUCCESS;
}

status_t drc_gbp_distribute_unlock(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, latch_mode_t mode)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to acquire lock for page");
        return OG_ERROR;
    }

    int ret;
    const char *lock_type;
    drc_lock_mode_e lock_mode;

    if (mode != 0) {
        lock_mode = (mode == LATCH_MODE_S ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE);
    } else {
        int32 state = ub_rw_lock_get_state(lock);
        if (state == 0) {
            // OG_LOG_RUN_INF("[DRC-GBP-LOCK] state %d", state);
            return OG_SUCCESS;
        }
        lock_mode = (state == INT32_MIN ? DRC_LOCK_EXCLUSIVE : DRC_LOCK_SHARE);
    }
    // OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] gbp unlock mode %d page (%u-%u)", lock_mode, page_id.file, page_id.page);
    ub_location_t lock_location = make_location((uint8)DCS_SELF_INSTID(session));

    if (lock_mode == DRC_LOCK_EXCLUSIVE) {
        ret = ub_rw_lock_x_unlock(lock, NULL, &lock_location);
        lock_type = "exlcusive";
    } else {
        ret = ub_rw_lock_s_unlock(lock, NULL, &lock_location);
        lock_type = "shared";
    }

    if (ret != UB_LOCK_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to release %s lock for page (%u-%u):%d", lock_type, page_id.file,
                       page_id.page, ret);
        return OG_ERROR;
    }

    // OG_LOG_DEBUG_INF("[DRC-GBP-LOCK][%u-%u] Success to release %s lock for page: %d",
    //                page_id.file, page_id.page, lock_type, ret);
    return OG_SUCCESS;
}

void drc_gbp_lock_info_debug_snapshot(uint64 lock_ptr, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid, int32 *readonly, int32 *readonly_owner_node,
    int32 *readonly_owner_tid)
{
    if (lock_ptr == 0) {
        *atomic_state = 0;
        *x_owner_node = -1;
        *write_waiters = 0;
        *owner_tid = -1;
        *readonly = 0;
        *readonly_owner_node = -1;
        *readonly_owner_tid = -1;
        return;
    }
    ub_rw_lock_debug_read((const ub_rw_lock_t *)(uintptr_t)lock_ptr, atomic_state, x_owner_node, write_waiters,
        owner_tid, readonly, readonly_owner_node, readonly_owner_tid);
}

