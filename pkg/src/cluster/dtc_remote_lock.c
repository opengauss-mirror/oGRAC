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
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_session.h"
#include "dtc_remote_lock.h"

#if USE_ATOMIC_LOCK
void ub_rw_lock_debug_read(const ub_rw_lock_t *lock, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid);
#endif

#if !USE_ATOMIC_LOCK

static ub_shm_comm_t g_handle_send = NULL;
static ub_shm_comm_t g_handle_recv = NULL;

status_t init_lock_comm_queue()
{
    uint32 node_id = g_instance->kernel.id;
    bool is_master = (node_id == 0);
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    char *shmA = remote_sga->remote_buf_addr[0] + DRC_DIST_QUE_OFFSET;
    char *shmB = remote_sga->remote_buf_addr[1] + DRC_DIST_QUE_OFFSET;
    remote_sga->remote_pool_reserve_offset += DRC_DIST_QUE_OFFSET;

    const size_t kInitSize = 1024;
    const size_t kRingSize = 1376640;

    const uint8_t nodeA = 0;
    const uint8_t nodeB = 1;
    const uint8_t cur = is_master ? nodeA : nodeB;
    const uint8_t peer = is_master ? nodeB : nodeA;
    void *init_region_cur = (is_master ? shmA : shmB);
    void *ring_region_cur = (is_master ? shmA : shmB) + kInitSize;
    void *ring_region_peer = (is_master ? shmB : shmA) + kInitSize;

    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 0: %p", shmA);
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 1: %p", shmB);

    ub_ring_desc_t ring_descs[1];
    ring_descs[0].ring_capacity = 1024;
    ring_descs[0].max_msg_size = 512;
    ring_descs[0].priority = 1;

    ub_comm_conf_t conf;
    conf.max_nodes = 2;
    conf.current_node_id = cur;
    conf.num_rings = 1;
    conf.ring_descs = ring_descs;

    ub_shm_area_t init_area;
    init_area.size = kInitSize;
    init_area.ptr = init_region_cur;

    ub_ring_region_info_t infos[2];
    infos[0].node_id = cur;
    infos[0].region.size = kRingSize;
    infos[0].region.ptr = ring_region_cur;
    infos[1].node_id = peer;
    infos[1].region.size = kRingSize;
    infos[1].region.ptr = ring_region_peer;

    ub_ring_region_map_t ring_map;
    ring_map.entries = infos;
    ring_map.count = 2;

    ub_shm_comm_t *handle = is_master ? &g_handle_send : &g_handle_recv;
    int ret = ub_comm_queue_init(handle, &init_area, &ring_map, &conf);
    if (ret != 0) {
        OG_LOG_RUN_ERR("[DRC-GBP] ub_comm_queue_init failed, return error:%d", ret);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

#else /* USE_ATOMIC_LOCK */

status_t init_lock_comm_queue()
{
    return OG_SUCCESS;
}

#endif /* USE_ATOMIC_LOCK */

void drc_init_remote_lock(ub_rw_lock_t **ub_lock, ub_lock_config_t *config, ub_location_t *creator)
{
    uint32 node_id = g_instance->kernel.id;
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    *ub_lock = (ub_rw_lock_t *)(remote_sga->remote_buf_addr[node_id] + DRC_DIST_LCK_OFFSET);
    remote_sga->remote_pool_reserve_offset += DRC_DIST_LCK_OFFSET;
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock buf addr start: %p, reserve offset:%llu", *ub_lock,
                   remote_sga->remote_pool_reserve_offset);

    config->lease_time = 60000;
    config->heartbeat_timeout = 500;

    creator->tid = (int32_t)(pthread_self() & 0x7FFFFFFF);
    creator->node_id = (uint8_t)node_id;
}

static ub_location_t make_location(uint8 node_id)
{
    ub_location_t loc;
    loc.node_id = node_id;
    loc.tid = (int32_t)(pthread_self() & 0x7FFFFFFF);

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
    OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] start to get lock address for offset: %p", lock);
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

    OG_LOG_RUN_INF("[DRC-GBP-LOCK] Success to acquire %s lock for page (%u-%u):%d", lock_type, page_id.file,
                   page_id.page, ret);
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

    drc_lock_mode_e lock_mode = (mode == LATCH_MODE_S ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE);
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

    OG_LOG_RUN_INF("[DRC-GBP-LOCK][%u-%u] Success to release %s lock for page: %d",
                   page_id.file, page_id.page, lock_type, ret);
    return OG_SUCCESS;
}

void drc_gbp_lock_info_debug_snapshot(uint64 lock_ptr, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid)
{
#if USE_ATOMIC_LOCK
    if (lock_ptr == 0) {
        *atomic_state = 0;
        *x_owner_node = -1;
        *write_waiters = 0;
        *owner_tid = -1;
        return;
    }
    ub_rw_lock_debug_read((const ub_rw_lock_t *)(uintptr_t)lock_ptr, atomic_state, x_owner_node, write_waiters,
        owner_tid);
#else
    (void)lock_ptr;
    *atomic_state = 0;
    *x_owner_node = -1;
    *write_waiters = 0;
    *owner_tid = -1;
#endif
}
