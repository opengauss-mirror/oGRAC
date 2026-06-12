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
#include <string.h>
#include <dlfcn.h>
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_session.h"
#include "dtc_remote_lock.h"
#include "dtc_remote_buffer.h"
#include "dtc_context.h"
#include "mes_func.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "srv_instance.h"
#include "knl_buffer.h"
#include "knl_page.h"

void drc_gbp_lock_log_flow(const char *phase);
void drc_gbp_lock_probe_impl(const char *phase);

static inline bool32 drc_gbp_lock_debug_on(void)
{
    return (g_instance != NULL && g_instance->kernel.attr.ub_gbp_lock_debug);
}

static inline bool32 drc_gbp_lock_debug_sess(knl_session_t *session)
{
    return (session != NULL && session->kernel->attr.ub_gbp_lock_debug);
}

#define DRC_GBP_DBG_WAR(fmt, ...) \
    do { \
        if (drc_gbp_lock_debug_on()) { \
            OG_LOG_RUN_WAR(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#if USE_ATOMIC_LOCK
void ub_rw_lock_debug_read(const ub_rw_lock_t *lock, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid);

void ub_gbp_lock_read_wait_queue(const ub_rw_lock_t *lock, ub_gbp_wait_q_snap_t *snap)
{
    (void)lock;
    if (snap != NULL) {
        (void)memset(snap, 0, sizeof(ub_gbp_wait_q_snap_t));
    }
}
#endif

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

#if !USE_ATOMIC_LOCK

static ub_shm_comm_t g_handle_send = NULL;
static ub_shm_comm_t g_handle_recv = NULL;
static bool32 g_lock_comm_queue_inited = OG_FALSE;
static bool32 g_dist_comm_ub_queue_inited = OG_FALSE;
static bool32 g_ubs_atomic_lib_log_registered = OG_FALSE;

#ifndef UB_ATOMIC_LOG_FUNC_TYPEDEF
typedef int (*ub_atomic_log_func)(int level, const char *file, const char *func, uint32 line, const char *message);
#endif

#ifndef LOG_LEVEL_ERROR
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_WARN  2
#endif

static int drc_gbp_ubs_atomic_lib_log(int level, const char *file, const char *func, uint32 line, const char *message)
{
    (void)file;
    if (message == NULL) {
        return 0;
    }
    if (level >= LOG_LEVEL_ERROR) {
        OG_LOG_RUN_ERR("[UB-LOCK-LIB][%s:%u] %s", (func != NULL ? func : "?"), line, message);
    } else if (level >= LOG_LEVEL_WARN && drc_gbp_lock_debug_on()) {
        OG_LOG_RUN_WAR("[UB-LOCK-LIB][%s:%u] %s", (func != NULL ? func : "?"), line, message);
    }
    return 0;
}

static void drc_gbp_ubs_atomic_try_register_lib_log(void)
{
    void *reg_sym;
    void *level_sym;

    if (g_ubs_atomic_lib_log_registered) {
        return;
    }
    reg_sym = dlsym(RTLD_DEFAULT, "ub_atomic_register_log_func");
    if (reg_sym == NULL) {
        DRC_GBP_DBG_WAR("[GBP-LOCK-FLOW][ubs_atomic_log_hook] dlsym(ub_atomic_register_log_func) not found, skip");
        return;
    }
    ((void (*)(ub_atomic_log_func))reg_sym)(drc_gbp_ubs_atomic_lib_log);
    level_sym = dlsym(RTLD_DEFAULT, "ub_atomic_set_log_level");
    if (level_sym != NULL) {
        ((int (*)(int))level_sym)(LOG_LEVEL_WARN);
    }
    g_ubs_atomic_lib_log_registered = OG_TRUE;
    DRC_GBP_DBG_WAR("[GBP-LOCK-FLOW][ubs_atomic_log_hook] registered ub_atomic_register_log_func");
}

static bool32 drc_lock_comm_queue_prereq_met(remote_sga_t *remote_sga)
{
    for (uint32 node_id = 0; node_id < g_mes.profile.inst_count; node_id++) {
        if (remote_sga->map_success[node_id] != OG_TRUE || remote_sga->remote_buf_addr[node_id] == NULL) {
            DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] comm queue prereq not met, node %u map_success:%u addr:%p",
                           node_id, (uint32)remote_sga->map_success[node_id], remote_sga->remote_buf_addr[node_id]);
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

#define DRC_DIST_COMM_FOLLOWER_WAIT_MS 60000U
#define DRC_DIST_COMM_FOLLOWER_POLL_MS 50U

static spinlock_t g_dist_comm_coord_lock;
static bool32 g_dist_comm_coord_lock_inited = OG_FALSE;
static uint64 g_dist_comm_epoch = 0;

static void drc_dist_comm_coord_lock_ensure(void)
{
    if (!g_dist_comm_coord_lock_inited) {
        OG_INIT_SPIN_LOCK(g_dist_comm_coord_lock);
        g_dist_comm_coord_lock_inited = OG_TRUE;
    }
}

static char *drc_dist_billboard_slot(void *init_region, uint32 node_idx)
{
    return (char *)init_region + (uint64)node_idx * DRC_UB_BILLBOARD_NODE_SLOT_SIZE;
}

/* libubs-atomic demo layout: global Billboard in node0 pool; both nodes map the same init_region. */
static void *drc_dist_shared_billboard_init(remote_sga_t *remote_sga)
{
    return (void *)(remote_sga->remote_buf_addr[0] + DRC_DIST_QUE_OFFSET);
}

static status_t drc_dist_verify_peer_billboard(remote_sga_t *remote_sga, uint32 self_node, uint32 peer_node,
    size_t kInitSize)
{
    void *shared_init = drc_dist_shared_billboard_init(remote_sga);
    char *peer_slot = drc_dist_billboard_slot(shared_init, peer_node);
    volatile uint8_t *inited = (volatile uint8_t *)peer_slot;
    volatile uint64_t *ring_offsets = (volatile uint64_t *)(peer_slot + sizeof(uint64));

    (void)kInitSize;
    if (*inited == 0) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] peer billboard not ready: self:%u peer:%u shared_init:%p",
                       self_node, peer_node, shared_init);
        return OG_ERROR;
    }
    if (ring_offsets[DRC_UB_LOCK_RING_PRIORITY] == UINT64_MAX) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] peer P0 ring offset invalid: self:%u peer:%u shared_init:%p",
                       self_node, peer_node, shared_init);
        return OG_ERROR;
    }
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] peer P0 ring ready: self:%u peer:%u shared_init:%p offset:%llu",
                   self_node, peer_node, shared_init,
                   (unsigned long long)ring_offsets[DRC_UB_LOCK_RING_PRIORITY]);
    return OG_SUCCESS;
}

static status_t drc_dist_comm_init_queue_after_barrier(remote_sga_t *remote_sga, uint32 node_id)
{
    bool is_master = (node_id == 0);
    const size_t kInitSize = 1024;
    const size_t kRingSize = 1376640;
    const uint8_t nodeA = 0;
    const uint8_t nodeB = 1;
    const uint8_t cur = is_master ? nodeA : nodeB;
    const uint8_t peer = is_master ? nodeB : nodeA;
    char *shmA = remote_sga->remote_buf_addr[0] + DRC_DIST_QUE_OFFSET;
    char *shmB = remote_sga->remote_buf_addr[1] + DRC_DIST_QUE_OFFSET;
    void *init_region_shared = drc_dist_shared_billboard_init(remote_sga);
    void *ring_region_cur = (is_master ? (void *)shmA : (void *)shmB) + kInitSize;
    void *ring_region_peer = (is_master ? (void *)shmB : (void *)shmA) + kInitSize;
    ub_ring_desc_t ring_descs[1];
    ub_comm_conf_t conf = { 0 };
    ub_shm_area_t init_area;
    ub_ring_region_info_t infos[2];
    ub_ring_region_map_t ring_map;
    ub_shm_comm_t *handle = is_master ? &g_handle_send : &g_handle_recv;
    int ret;

    ring_descs[0].ring_capacity = 1024;
    ring_descs[0].max_msg_size = 512;
    ring_descs[0].priority = 1;

    conf.cpu_id = -1;
    conf.max_nodes = 2;
    conf.current_node_id = cur;
    conf.num_rings = 1;
    conf.ring_descs = ring_descs;

    init_area.size = kInitSize;
    init_area.ptr = init_region_shared;

    infos[0].node_id = cur;
    infos[0].region.size = kRingSize;
    infos[0].region.ptr = ring_region_cur;
    infos[1].node_id = peer;
    infos[1].region.size = kRingSize;
    infos[1].region.ptr = ring_region_peer;

    ring_map.entries = infos;
    ring_map.count = 2;

    if (g_dist_comm_ub_queue_inited) {
        return OG_SUCCESS;
    }

    ret = ub_comm_queue_init(handle, &init_area, &ring_map, &conf);
    if (ret != 0) {
        OG_LOG_RUN_ERR("[DRC-GBP] ub_comm_queue_init failed after barrier, ret:%d node_id:%u shared_init:%p "
                       "ring_cur:%p ring_peer:%p",
                       ret, node_id, init_region_shared, ring_region_cur, ring_region_peer);
        drc_gbp_lock_log_flow("comm_queue_init_fail");
        return OG_ERROR;
    }

    g_dist_comm_ub_queue_inited = OG_TRUE;
    drc_gbp_ubs_atomic_try_register_lib_log();
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] ub_comm_queue_init ok node:%u shared_init:%p ring_cur:%p ring_peer:%p",
                   node_id, init_region_shared, ring_region_cur, ring_region_peer);
    drc_gbp_lock_log_flow("comm_queue_init_ok");
    return OG_SUCCESS;
}

static status_t drc_dist_comm_finalize_after_init(remote_sga_t *remote_sga, uint32 node_id)
{
    const size_t kInitSize = 1024;
    uint32 peer_node = (node_id == 0) ? 1U : 0U;

    if (!g_dist_comm_ub_queue_inited) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] comm finalize before ub_comm_queue_init, node:%u", node_id);
        return OG_ERROR;
    }

    if (drc_dist_verify_peer_billboard(remote_sga, node_id, peer_node, kInitSize) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] peer billboard verify failed after init barrier, self:%u peer:%u",
                       node_id, peer_node);
        return OG_ERROR;
    }

    if (!g_lock_comm_queue_inited) {
        g_lock_comm_queue_inited = OG_TRUE;
        drc_ubturbo_on_comm_queue_ready();
    }
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm finalize done (shared billboard, no copy) node:%u peer:%u",
                   node_id, peer_node);
    drc_gbp_lock_log_flow("comm_queue_shared_billboard_ok");
    return OG_SUCCESS;
}

static status_t drc_dist_comm_init_queue_local(void)
{
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    uint32 node_id = g_instance->kernel.id;

    if (g_dist_comm_ub_queue_inited) {
        return OG_SUCCESS;
    }
    if (!drc_lock_comm_queue_prereq_met(remote_sga)) {
        drc_gbp_lock_log_flow("comm_queue_init_skip");
        return OG_SUCCESS;
    }
    remote_sga->remote_pool_reserve_offset += DRC_DIST_QUE_OFFSET;
    return drc_dist_comm_init_queue_after_barrier(remote_sga, node_id);
}

static status_t drc_dist_comm_sync_local(void)
{
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    uint32 node_id = g_instance->kernel.id;

    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }
    if (!drc_lock_comm_queue_prereq_met(remote_sga)) {
        drc_gbp_lock_log_flow("comm_queue_init_skip");
        return OG_SUCCESS;
    }
    if (!g_dist_comm_ub_queue_inited) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] sync barrier without ub_comm_queue_init, node:%u", node_id);
        return OG_ERROR;
    }
    return drc_dist_comm_finalize_after_init(remote_sga, node_id);
}

static status_t drc_dist_comm_coordinated_init_follower(void)
{
    uint32 waited_ms = 0;

    while (!g_lock_comm_queue_inited && waited_ms < DRC_DIST_COMM_FOLLOWER_WAIT_MS) {
        cm_sleep(DRC_DIST_COMM_FOLLOWER_POLL_MS);
        waited_ms += DRC_DIST_COMM_FOLLOWER_POLL_MS;
    }
    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }
    OG_LOG_RUN_ERR("[DRC-GBP-LOCK] follower wait comm_queue init timeout after %u ms, node:%u",
                   waited_ms, (uint32)g_instance->kernel.id);
    return OG_ERROR;
}

static status_t drc_dist_comm_coordinated_init_leader(knl_session_t *session)
{
    mes_dist_comm_reset_bcast_t reset_bcast = { 0 };
    mes_dist_comm_init_bcast_t init_bcast = { 0 };
    mes_dist_comm_sync_bcast_t sync_bcast = { 0 };
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    uint64 epoch;

    drc_dist_comm_coord_lock_ensure();
    cm_spin_lock(&g_dist_comm_coord_lock, NULL);
    if (g_lock_comm_queue_inited) {
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_SUCCESS;
    }
    if (!drc_lock_comm_queue_prereq_met(remote_sga)) {
        drc_gbp_lock_log_flow("comm_queue_init_skip");
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_SUCCESS;
    }

    epoch = ++g_dist_comm_epoch;
    g_lock_comm_queue_inited = OG_FALSE;
    g_dist_comm_ub_queue_inited = OG_FALSE;
    drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga);
    drc_gbp_lock_log_flow("ubsm_dist_fresh_reset_leader_before_broadcast");
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm reset leader epoch:%llu node:%u",
                   (unsigned long long)epoch, (uint32)g_instance->kernel.id);

    mes_init_send_head(&reset_bcast.head, MES_CMD_BROADCAST_DIST_COMM_RESET, sizeof(mes_dist_comm_reset_bcast_t),
                       OG_INVALID_ID32, (uint8)g_instance->kernel.id, 0, session->id, OG_INVALID_ID16);
    reset_bcast.epoch = epoch;
    if (mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST, (void *)&reset_bcast, MES_WAIT_MAX_TIME,
                               NULL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset broadcast_and_wait failed, epoch:%llu",
                       (unsigned long long)epoch);
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_ERROR;
    }
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm reset barrier done epoch:%llu", (unsigned long long)epoch);

    if (drc_dist_comm_init_queue_local() != OG_SUCCESS) {
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_ERROR;
    }
    mes_init_send_head(&init_bcast.head, MES_CMD_BROADCAST_DIST_COMM_INIT, sizeof(mes_dist_comm_init_bcast_t),
                       OG_INVALID_ID32, (uint8)g_instance->kernel.id, 0, session->id, OG_INVALID_ID16);
    init_bcast.epoch = epoch;
    if (mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST, (void *)&init_bcast, MES_WAIT_MAX_TIME,
                               NULL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init broadcast_and_wait failed, epoch:%llu",
                       (unsigned long long)epoch);
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_ERROR;
    }
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm init barrier done epoch:%llu", (unsigned long long)epoch);

    if (drc_dist_comm_sync_local() != OG_SUCCESS) {
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_ERROR;
    }
    mes_init_send_head(&sync_bcast.head, MES_CMD_BROADCAST_DIST_COMM_SYNC, sizeof(mes_dist_comm_sync_bcast_t),
                       OG_INVALID_ID32, (uint8)g_instance->kernel.id, 0, session->id, OG_INVALID_ID16);
    sync_bcast.epoch = epoch;
    if (mes_broadcast_and_wait(session->id, MES_BROADCAST_ALL_INST, (void *)&sync_bcast, MES_WAIT_MAX_TIME,
                               NULL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync broadcast_and_wait failed, epoch:%llu",
                       (unsigned long long)epoch);
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_ERROR;
    }

    cm_spin_unlock(&g_dist_comm_coord_lock);
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm coordinated init done epoch:%llu node:%u",
                   (unsigned long long)epoch, (uint32)g_instance->kernel.id);
    return OG_SUCCESS;
}

status_t drc_dist_comm_coordinated_init(knl_session_t *session)
{
    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }
    if (session == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] coordinated init requires session");
        return OG_ERROR;
    }
    if (g_instance->kernel.id == 0) {
        return drc_dist_comm_coordinated_init_leader(session);
    }
    return drc_dist_comm_coordinated_init_follower();
}

void drc_process_dist_comm_reset(void *sess, mes_message_t *msg)
{
    mes_dist_comm_reset_bcast_t *bcast = (mes_dist_comm_reset_bcast_t *)msg->buffer;
    mes_message_head_t ack_head = { 0 };
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_reset_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_reset_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm reset handler epoch:%llu node:%u",
                   (unsigned long long)bcast->epoch, (uint32)g_instance->kernel.id);
    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        g_lock_comm_queue_inited = OG_FALSE;
        g_dist_comm_ub_queue_inited = OG_FALSE;
        drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga);
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset ack send failed, node:%u", (uint32)g_instance->kernel.id);
    }
}

void drc_process_dist_comm_init(void *sess, mes_message_t *msg)
{
    mes_dist_comm_init_bcast_t *bcast = (mes_dist_comm_init_bcast_t *)msg->buffer;
    mes_message_head_t ack_head = { 0 };
    status_t ret = OG_SUCCESS;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_init_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_init_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm init handler epoch:%llu node:%u",
                   (unsigned long long)bcast->epoch, (uint32)g_instance->kernel.id);

    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        ret = drc_dist_comm_init_queue_local();
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init handler failed, node:%u", (uint32)g_instance->kernel.id);
        }
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    ack_head.status = ret;
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init ack send failed, node:%u", (uint32)g_instance->kernel.id);
    }
}

void drc_process_dist_comm_sync(void *sess, mes_message_t *msg)
{
    mes_dist_comm_sync_bcast_t *bcast = (mes_dist_comm_sync_bcast_t *)msg->buffer;
    mes_message_head_t ack_head = { 0 };
    status_t ret = OG_SUCCESS;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_sync_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_sync_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] dist comm sync handler epoch:%llu node:%u",
                   (unsigned long long)bcast->epoch, (uint32)g_instance->kernel.id);

    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        ret = drc_dist_comm_sync_local();
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync handler failed, node:%u", (uint32)g_instance->kernel.id);
        }
    }

    mes_init_ack_head(msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    ack_head.status = ret;
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&ack_head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync ack send failed, node:%u", (uint32)g_instance->kernel.id);
    }
}

status_t init_lock_comm_queue()
{
    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }

    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] init_lock_comm_queue without session, skip leader (db_open/mmap retry)");
    if (g_instance->kernel.id == 0) {
        return OG_SUCCESS;
    }
    return drc_dist_comm_coordinated_init_follower();
}

#if 0 /* replaced by drc_dist_comm_coordinated_init — kept reference only */
status_t init_lock_comm_queue_old()
{
    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }

    uint32 node_id = g_instance->kernel.id;
    bool is_master = (node_id == 0);
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;

    if (!drc_lock_comm_queue_prereq_met(remote_sga)) {
        DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] skip comm queue init until all node shm are mapped, node_id:%u",
                       node_id);
        drc_gbp_lock_log_flow("comm_queue_init_skip");
        return OG_SUCCESS;
    }

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

    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 0: %p", shmA);
    DRC_GBP_DBG_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 1: %p", shmB);

    /*
     * Both nodes are mapped: zero comm+lock shm on every pool before ub_comm_queue_init /
     * ub_rw_lock_create so dual-node simultaneous startup and atomic<->ubturbo switch
     * always see a clean dist-lock layer.
     */
    drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga);
    drc_gbp_lock_log_flow("ubsm_dist_fresh_reset_before_comm_queue");

    ub_ring_desc_t ring_descs[1];
    ring_descs[0].ring_capacity = 1024;
    ring_descs[0].max_msg_size = 512;
    ring_descs[0].priority = 1;

    ub_comm_conf_t conf = { 0 };
    conf.cpu_id = -1;
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
        OG_LOG_RUN_ERR("[DRC-GBP] ub_comm_queue_init failed, ret:%d node_id:%u cur:%u is_master:%d "
                       "shmA:%p shmB:%p init:%p ring_cur:%p ring_peer:%p cpu_id:%d",
                       ret, node_id, (uint32)cur, (int)is_master, shmA, shmB, init_region_cur, ring_region_cur,
                       ring_region_peer, conf.cpu_id);
        drc_gbp_lock_log_flow("comm_queue_init_fail");
        return OG_ERROR;
    }
    g_lock_comm_queue_inited = OG_TRUE;
    drc_gbp_ubs_atomic_try_register_lib_log();
    drc_gbp_lock_log_flow("comm_queue_init_ok");
    drc_ubturbo_on_comm_queue_ready();
    return OG_SUCCESS;
}
#endif /* reference: init_lock_comm_queue_old */

bool32 drc_lock_comm_queue_is_inited(void)
{
    return g_lock_comm_queue_inited;
}

status_t drc_wait_lock_comm_queue_prereq(uint32 timeout_ms)
{
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    uint32 waited_ms = 0;
    const uint32 step_ms = 10;

    while (waited_ms < timeout_ms) {
        if (drc_lock_comm_queue_prereq_met(remote_sga)) {
            return OG_SUCCESS;
        }
        cm_sleep(step_ms);
        waited_ms += step_ms;
    }

    (void)drc_lock_comm_queue_prereq_met(remote_sga);
    OG_LOG_RUN_ERR("[DRC-GBP-LOCK] wait comm queue prereq timeout after %u ms", timeout_ms);
    return OG_ERROR;
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

status_t drc_wait_lock_comm_queue_prereq(uint32 timeout_ms)
{
    (void)timeout_ms;
    return OG_SUCCESS;
}

void drc_ubturbo_on_comm_queue_ready(void)
{
}

status_t drc_gbp_ensure_lock_attached(knl_session_t *session, uint64 lock_ptr, page_id_t page_id)
{
    (void)session;
    (void)lock_ptr;
    (void)page_id;
    return OG_SUCCESS;
}

#endif /* USE_ATOMIC_LOCK */
void drc_gbp_lock_log_flow(const char *phase)
{
    if (!drc_gbp_lock_debug_on()) {
        return;
    }

#if USE_ATOMIC_LOCK
    OG_LOG_RUN_WAR("[GBP-LOCK-FLOW][%s] compile_flag USE_ATOMIC_LOCK=1 (see GBP-LOCK-IMPL for runtime proof)",
                   phase);
#else
    OG_LOG_RUN_WAR("[GBP-LOCK-FLOW][%s] compile_flag USE_ATOMIC_LOCK=0 comm_queue:%s node_id:%u",
                   phase, drc_lock_comm_queue_is_inited() ? "inited" : "not_inited",
                   (uint32)g_instance->kernel.id);
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
    void *xlock_fn = dlsym(RTLD_DEFAULT, "ub_rw_lock_x_lock");
    void *slock_fn = dlsym(RTLD_DEFAULT, "ub_rw_lock_s_lock");
    const char *verdict = NULL;
    Dl_info create_info;

    if (g_impl_probed) {
        return;
    }
    g_impl_probed = OG_TRUE;

    marker = dlsym(RTLD_DEFAULT, "ub_gbp_lock_impl_probe_marker");
#if !USE_ATOMIC_LOCK
    if (marker != NULL) {
        OG_LOG_RUN_ERR("[GBP-LOCK-IMPL][%s] MISMATCH: in-tree atomic linked while USE_ATOMIC_LOCK=0", phase);
    }
#endif
    if (!drc_gbp_lock_debug_on()) {
        return;
    }

    if (create_fn != NULL) {
        drc_gbp_lock_log_symbol_module(phase, "ub_rw_lock_create", create_fn);
    } else {
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] dlsym(ub_rw_lock_create) failed", phase);
    }
    if (xlock_fn != NULL) {
        drc_gbp_lock_log_symbol_module(phase, "ub_rw_lock_x_lock", xlock_fn);
    }
    if (slock_fn != NULL) {
        drc_gbp_lock_log_symbol_module(phase, "ub_rw_lock_s_lock", slock_fn);
    }

    if (marker != NULL) {
        verdict = "IN-TREE-ATOMIC";
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=FOUND text:%s", phase, (const char *)marker);
    } else if (create_fn != NULL && dladdr(create_fn, &create_info) != 0 && create_info.dli_fname != NULL &&
        strstr(create_info.dli_fname, "ubs-atomic") != NULL) {
        verdict = "UBS-ATOMIC-DYNAMIC-LIB";
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=NOT_FOUND module:%s", phase, create_info.dli_fname);
    } else if (create_fn != NULL && dladdr(create_fn, &create_info) != 0 && create_info.dli_fname != NULL &&
        strstr(create_info.dli_fname, "ubturbo") != NULL) {
        verdict = "UBTURBO-DYNAMIC-LIB";
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=NOT_FOUND module:%s", phase, create_info.dli_fname);
    } else if (create_fn != NULL && dladdr(create_fn, &create_info) != 0 && create_info.dli_fname != NULL) {
        verdict = "CHECK-MODULE-PATH";
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=NOT_FOUND module:%s", phase, create_info.dli_fname);
    } else {
        verdict = "UNKNOWN";
        OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] probe_marker=NOT_FOUND dlsym/dladdr failed", phase);
    }

    OG_LOG_RUN_WAR("[GBP-LOCK-IMPL][%s] VERDICT:%s", phase, verdict);
}

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
