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
#include <dlfcn.h>
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_session.h"
#include "dtc_remote_lock.h"

#if USE_ATOMIC_LOCK
void ub_rw_lock_debug_read(const ub_rw_lock_t *lock, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid);
#endif

static inline bool32 drc_gbp_lock_debug_on(void)
{
    return g_instance->kernel.attr.ub_gbp_lock_debug;
}

static inline bool32 drc_gbp_lock_debug_sess(knl_session_t *session)
{
    (void)session;
    return drc_gbp_lock_debug_on();
}

void drc_gbp_lock_diag_log_page(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, const char *phase)
{
    int32 state = 0;
    int32 x_owner_node = -1;
    int32 write_waiters = 0;
    int32 owner_tid = -1;
    bool32 readonly = OG_FALSE;
    bool32 x_held = OG_FALSE;

    if (!drc_gbp_lock_debug_sess(session)) {
        return;
    }

    drc_gbp_lock_info_debug_snapshot(lock_ptr, &state, &x_owner_node, &write_waiters, &owner_tid);
    if (lock_ptr != 0) {
        ub_gbp_lock_raw_t raw;
        ub_rw_lock_t *lock = (ub_rw_lock_t *)(uintptr_t)lock_ptr;

        ub_gbp_lock_read_raw(lock, &raw);
        readonly = raw.readonly;
        x_held = ub_rw_lock_is_x_held_by_current_thread(lock, (uint8)DCS_SELF_INSTID(session),
            (int32)cm_get_current_thread_id());
        OG_LOG_RUN_INF("[GBP-LOCK-DIAG][%s][%u-%u] lock_ptr:%llu phase:%s g_word:%d g_wait:%u s_readers:%u "
                       "w0:0x%016llx owner_x:0x%016llx(node:%u tid:%d) reserve:0x%016llx(node:%u) bitmap:0x%x "
                       "readonly:%d self_node:%u self_tid:%d x_held:%d",
                       phase, page_id.file, page_id.page, lock_ptr, raw.g_phase, raw.g_lock_word, raw.g_waiters,
                       raw.s_readers, (unsigned long long)raw.word0, (unsigned long long)raw.owner_x,
                       (uint32)raw.owner_x_node, raw.owner_x_tid, (unsigned long long)raw.reserve_owner,
                       (uint32)raw.reserve_node, raw.shared_bitmap, (int32)readonly,
                       (uint32)DCS_SELF_INSTID(session), (int32)cm_get_current_thread_id(), (int32)x_held);
        return;
    }

    OG_LOG_RUN_INF("[GBP-LOCK-DIAG][%s][%u-%u] lock_ptr:%llu state:%d owner_node:%d owner_tid:%d "
                   "write_waiters:%d readonly:%d self_node:%u self_tid:%d x_held:%d",
                   phase, page_id.file, page_id.page, lock_ptr, state, x_owner_node, owner_tid, write_waiters,
                   (int32)readonly, (uint32)DCS_SELF_INSTID(session), (int32)cm_get_current_thread_id(), (int32)x_held);
}

void drc_gbp_lock_log_flow(const char *phase)
{
    if (!drc_gbp_lock_debug_on()) {
        return;
    }

#if USE_ATOMIC_LOCK
    OG_LOG_RUN_WAR("[GBP-LOCK-FLOW][%s] compile_flag USE_ATOMIC_LOCK=1 (see GBP-LOCK-IMPL for runtime proof)",
                   phase);
#else
    OG_LOG_RUN_WAR("[GBP-LOCK-FLOW][%s] compile_flag USE_ATOMIC_LOCK=0 node_id:%u",
                   phase, (uint32)g_instance->kernel.id);
#endif
}

static void drc_gbp_lock_log_symbol_module(const char *phase, const char *sym_name, void *sym_addr)
{
    Dl_info info;

    if (dladdr(sym_addr, &info) == 0) {
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] %s addr:%p dladdr_failed", phase, sym_name, sym_addr);
        return;
    }

    OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] %s addr:%p module:%s sname:%s fbase:%p",
                   phase, sym_name, sym_addr,
                   info.dli_fname != NULL ? info.dli_fname : "(null)",
                   info.dli_sname != NULL ? info.dli_sname : "(null)", info.dli_fbase);
}

void drc_gbp_lock_probe_impl(const char *phase)
{
    static bool32 g_impl_probed = OG_FALSE;
    void *marker = NULL;
    void *create_fn = dlsym(RTLD_DEFAULT, "ub_rw_lock_create");
    const char *verdict = NULL;

    if (g_impl_probed) {
        return;
    }
    g_impl_probed = OG_TRUE;

    marker = dlsym(RTLD_DEFAULT, "ub_gbp_lock_impl_probe_marker");
    if (!drc_gbp_lock_debug_on()) {
        return;
    }

    if (create_fn != NULL) {
        drc_gbp_lock_log_symbol_module(phase, "ub_rw_lock_create", create_fn);
    } else {
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] dlsym(ub_rw_lock_create) failed", phase);
    }

    if (marker != NULL) {
        verdict = "IN-TREE-ATOMIC";
    } else {
        verdict = "EXTERNAL-OR-UNKNOWN";
    }

    OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=%s VERDICT:%s", phase,
                   marker != NULL ? "FOUND" : "NOT_FOUND", verdict);
}

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

status_t drc_dist_comm_coordinated_init(knl_session_t *session)
{
    (void)session;
    return OG_SUCCESS;
}

void drc_process_dist_comm_reset(void *sess, mes_message_t *msg)
{
    mes_message_head_t ack_head = { 0 };

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_reset_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_reset_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset ack send failed (atomic), node:%u",
                       (uint32)g_instance->kernel.id);
    }
}

void drc_process_dist_comm_init(void *sess, mes_message_t *msg)
{
    mes_message_head_t ack_head = { 0 };

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_init_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_init_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    ack_head.status = OG_SUCCESS;
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init ack send failed (atomic), node:%u",
                       (uint32)g_instance->kernel.id);
    }
}

void drc_process_dist_comm_sync(void *sess, mes_message_t *msg)
{
    mes_message_head_t ack_head = { 0 };

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_sync_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_sync_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    ack_head.status = OG_SUCCESS;
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync ack send failed (atomic), node:%u",
                       (uint32)g_instance->kernel.id);
    }
}

status_t init_lock_comm_queue()
{
    return OG_SUCCESS;
}

bool32 drc_lock_comm_queue_is_inited(void)
{
    return OG_TRUE;
}

#endif /* USE_ATOMIC_LOCK */

static ub_lock_config_t g_ub_page_lock_config;
static ub_location_t g_ub_page_lock_creator;
static bool32 g_ub_page_lock_params_ready = OG_FALSE;

static void drc_init_ub_page_lock_create_params(void)
{
    if (g_ub_page_lock_params_ready) {
        return;
    }

    uint32 node_id = g_instance->kernel.id;
    g_ub_page_lock_config.lease_time = 60000;
    g_ub_page_lock_config.heartbeat_timeout = 500;
    g_ub_page_lock_creator.tid = (int32_t)cm_get_current_thread_id();
    g_ub_page_lock_creator.node_id = (uint8_t)node_id;
    g_ub_page_lock_params_ready = OG_TRUE;
}

void drc_init_remote_lock(ub_rw_lock_t **ub_lock)
{
    uint32 node_id = g_instance->kernel.id;
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    *ub_lock = (ub_rw_lock_t *)(remote_sga->remote_buf_addr[node_id] + DRC_DIST_LCK_OFFSET);
    remote_sga->remote_pool_reserve_offset += DRC_DIST_LCK_OFFSET;
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock buf addr start: %p, reserve offset:%llu", *ub_lock,
                   remote_sga->remote_pool_reserve_offset);
    drc_gbp_lock_log_flow("mount_remote_lock_region");
    drc_gbp_lock_probe_impl("mount_remote_lock_region");
}

status_t drc_create_page_ub_lock(ub_rw_lock_t *lock)
{
    drc_init_ub_page_lock_create_params();
    drc_gbp_lock_probe_impl("page_lock_create");
    ub_rw_lock_create(lock, &g_ub_page_lock_config, &g_ub_page_lock_creator);
    return OG_SUCCESS;
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

    OG_LOG_RUN_INF("[DRC-GBP-LOCK] Success to acquire store exclusive lock for page (%u-%u):%d",
        page_id.file, page_id.page, ret);
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

    OG_LOG_RUN_INF("[DRC-GBP-LOCK] Success to acquire reenter exclusive lock for page (%u-%u):%d",
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
            OG_LOG_RUN_INF("[DRC-GBP-LOCK] state %d", state);
            return OG_SUCCESS;
        }
        lock_mode = (state == INT32_MIN ? DRC_LOCK_EXCLUSIVE : DRC_LOCK_SHARE);
    }
    OG_LOG_RUN_INF("[DRC-GBP-LOCK] gbp unlock mode %d page (%u-%u)", lock_mode, page_id.file,
                   page_id.page);
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
