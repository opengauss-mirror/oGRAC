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

/*
 * UBSM per-node pool layout (remote_sga->remote_buf_addr[node_id], see dtc_remote_buffer.h):
 *
 *   +-- DRC_REMOTE_BUF_OFFSET (0)
 *   |     GBP page data: remote_page_info_t + page + tail_lsn per slot
 *   |     size: DRC_REMOTE_BUF_SIZE (256 MiB)
 *   +-- DRC_DIST_QUE_OFFSET (= DRC_REMOTE_BUF_SIZE)
 *   |     Distributed comm queue (ubturbo / USE_ATOMIC_LOCK=0 only)
 *   |     size: DRC_DIST_QUE_SIZE (256 MiB)
 *   |     Per-node sub-layout at remote_buf_addr[N] + DRC_DIST_QUE_OFFSET:
 *   |       +0                              init/billboard area (DRC_UB_COMM_INIT_AREA_SIZE)
 *   |       +DRC_UB_COMM_INIT_AREA_SIZE     ring region      (DRC_UB_COMM_RING_AREA_SIZE)
 *   |     Global billboard is pinned at node-0 init area; both nodes map the same pointer.
 *   |     Per-node billboard slot: node_idx * DRC_UB_BILLBOARD_NODE_SLOT_SIZE (128 B):
 *   |       +0  uint8   inited
 *   |       +8  uint64  ring_offsets[priority]  (P0 = DRC_UB_LOCK_RING_PRIORITY)
 *   +-- DRC_DIST_LCK_OFFSET (= DRC_DIST_QUE_OFFSET + DRC_DIST_QUE_SIZE)
 *         Per-page ub_rw_lock objects (dense array)
 *         size: DRC_DISK_LCK_SIZE (256 MiB)
 *         base: drc_init_remote_lock() -> g_ub_lock (local node's lock region)
 *         page lock_ptr: g_ub_lock + page_index * UB_RW_LOCK_SIZE
 *
 * ---------------------------------------------------------------------------
 * Two-node relationship (USE_ATOMIC_LOCK=0 / ubturbo)
 * ---------------------------------------------------------------------------
 *
 * Each node owns one UBSM pool (remote_buf_addr[self]) and mmap-imports the peer
 * pool into remote_buf_addr[peer]. After DB open both nodes must satisfy
 * drc_lock_comm_queue_prereq_met(): map_success[0/1] and remote_buf_addr[0/1] set.
 *
 *   Node 0 UBSM                         Node 1 UBSM
 *   [data|comm|lock]                    [data|comm|lock]
 *        ^                                   ^
 *        |         cross-node mmap           |
 *        +----------- both nodes ------------+
 *
 * Comm queue wiring (libubs-atomic demo, 2-node):
 *   - Billboard (init_area): single copy at node-0 comm base; both nodes pass the
 *     same pointer into ub_comm_queue_init.
 *   - Rings: node-0 ring lives in node-0 comm slice; node-1 ring in node-1 slice.
 *     Each node registers BOTH rings (local + peer) in ring_map.
 *   - Handles: node 0 -> g_handle_send, node 1 -> g_handle_recv.
 *
 * Lock objects: each node initializes locks in its OWN DRC_DIST_LCK region
 * (drc_init_remote_lock uses remote_buf_addr[self]). Cross-node GBP access uses
 * the peer's page data via mmap; lock_ptr in page meta points to the owner's
 * lock slot in the owner's lock region.
 *
 * ---------------------------------------------------------------------------
 * Initialization timeline (ubturbo)
 * ---------------------------------------------------------------------------
 *
 * Phase A — per-node local setup (drc_init_remote_buffer, no peer required):
 *   1. ubsmem allocate local pool
 *   2. drc_init_remote_buf_struct: data_buf layout, assign page lock_ptr offsets,
 *      zero local GBP pages + dist areas (comm/lock) on this node
 *   3. Page ub_rw_lock_create is NOT done yet (deferred until comm queue ready)
 *
 * Phase B — cross-node mmap (DB open / broadcast_remote_buf_mmap):
 *   1. Each node mmap-imports every peer pool (dtc_mmap_remote_data_buf)
 *   2. broadcast_remote_buf_allocated -> drc_process_remote_buf_mmap on peers
 *   3. When all nodes mapped, prereq_met becomes true
 *
 * Phase C — coordinated comm queue (drc_dist_comm_coordinated_init):
 *   Entry: knl_database.c DB open, or drc_process_remote_buf_mmap once prereq met.
 *   Node 0 (leader) runs three MES broadcast barriers; node 1 (follower) only
 *   executes handlers and polls g_lock_comm_queue_inited.
 *
 *   RESET  (all nodes):
 *     - Clear comm+lock regions on every mapped pool (fresh start after reattach)
 *   INIT   (all nodes, after leader's local ub_comm_queue_init):
 *     - ub_comm_queue_init on local handle + shared billboard + both ring regions
 *   SYNC   (all nodes):
 *     - Verify peer billboard slot (inited + ring offset valid)
 *     - Set g_lock_comm_queue_inited, call drc_ubturbo_on_comm_queue_ready()
 *       -> drc_init_page_locks() -> ub_rw_lock_create for every page
 *
 * Phase D — runtime lock attach (drc_gbp_ensure_lock_attached):
 *   Lazy ub_rw_lock_create on first lock acquisition if page lock was not created
 *   during Phase C (should not happen in normal startup).
 *
 * USE_ATOMIC_LOCK=1: skip Phase C; drc_init_page_locks runs in Phase A because
 * in-tree atomic locks do not need ub_comm_queue_init.
 */

#if !USE_ATOMIC_LOCK

/* ub_comm_queue_init sub-regions within each node's DRC_DIST_QUE area (libubs-atomic demo layout). */
#define DRC_UB_COMM_INIT_AREA_SIZE  1024U
#define DRC_UB_COMM_RING_AREA_SIZE  1376640U
#define DRC_UB_COMM_RING_CAPACITY   1024U
#define DRC_UB_COMM_MAX_MSG_SIZE    512U

#endif /* !USE_ATOMIC_LOCK */

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

#if !USE_ATOMIC_LOCK

static ub_shm_comm_t g_handle_send = NULL;
static ub_shm_comm_t g_handle_recv = NULL;
static bool32 g_lock_comm_queue_inited = OG_FALSE;
static bool32 g_dist_comm_ub_queue_inited = OG_FALSE;
static bool32 drc_lock_comm_queue_prereq_met(remote_sga_t *remote_sga)
{
    /* Both nodes must mmap-import every peer pool before comm queue init. */
    for (uint32 node_id = 0; node_id < g_mes.profile.inst_count; node_id++) {
        if (remote_sga->map_success[node_id] != OG_TRUE || remote_sga->remote_buf_addr[node_id] == NULL) {
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
    /* init_region: node-0 DRC_DIST_QUE + 0; slot stride = DRC_UB_BILLBOARD_NODE_SLOT_SIZE (128 B). */
    return (char *)init_region + (uint64)node_idx * DRC_UB_BILLBOARD_NODE_SLOT_SIZE;
}

/* Global billboard: both nodes map node-0 pool base + DRC_DIST_QUE_OFFSET. */
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
    return OG_SUCCESS;
}

static status_t drc_dist_comm_init_queue_after_barrier(remote_sga_t *remote_sga, uint32 node_id)
{
    bool is_master = (node_id == 0);
    const uint8_t nodeA = 0;
    const uint8_t nodeB = 1;
    const uint8_t cur = is_master ? nodeA : nodeB;
    const uint8_t peer = is_master ? nodeB : nodeA;
    /* Each node's comm shm: [init 1024 B][ring 1376640 B] within DRC_DIST_QUE_SIZE (256 MiB). */
    char *shmA = remote_sga->remote_buf_addr[0] + DRC_DIST_QUE_OFFSET;
    char *shmB = remote_sga->remote_buf_addr[1] + DRC_DIST_QUE_OFFSET;
    void *init_region_shared = drc_dist_shared_billboard_init(remote_sga);
    void *ring_region_cur = (is_master ? (void *)shmA : (void *)shmB) + DRC_UB_COMM_INIT_AREA_SIZE;
    void *ring_region_peer = (is_master ? (void *)shmB : (void *)shmA) + DRC_UB_COMM_INIT_AREA_SIZE;
    /*
     * Node 0: g_handle_send, ring on shmA, peer ring on shmB.
     * Node 1: g_handle_recv, ring on shmB, peer ring on shmA.
     * init_area.ptr is always node-0 billboard (shared across both mappings).
     */
    ub_ring_desc_t ring_descs[1];
    ub_comm_conf_t conf = { 0 };
    ub_shm_area_t init_area;
    ub_ring_region_info_t infos[2];
    ub_ring_region_map_t ring_map;
    ub_shm_comm_t *handle = is_master ? &g_handle_send : &g_handle_recv;
    int ret;

    ring_descs[0].ring_capacity = DRC_UB_COMM_RING_CAPACITY;
    ring_descs[0].max_msg_size = DRC_UB_COMM_MAX_MSG_SIZE;
    ring_descs[0].priority = 1;

    conf.cpu_id = -1;
    conf.max_nodes = 2;
    conf.current_node_id = cur;
    conf.num_rings = 1;
    conf.ring_descs = ring_descs;

    init_area.size = DRC_UB_COMM_INIT_AREA_SIZE;
    init_area.ptr = init_region_shared;

    infos[0].node_id = cur;
    infos[0].region.size = DRC_UB_COMM_RING_AREA_SIZE;
    infos[0].region.ptr = ring_region_cur;
    infos[1].node_id = peer;
    infos[1].region.size = DRC_UB_COMM_RING_AREA_SIZE;
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
        return OG_ERROR;
    }

    g_dist_comm_ub_queue_inited = OG_TRUE;
    return OG_SUCCESS;
}

static status_t drc_dist_comm_finalize_after_init(remote_sga_t *remote_sga, uint32 node_id)
{
    uint32 peer_node = (node_id == 0) ? 1U : 0U;

    if (!g_dist_comm_ub_queue_inited) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] comm finalize before ub_comm_queue_init, node:%u", node_id);
        return OG_ERROR;
    }

    if (drc_dist_verify_peer_billboard(remote_sga, node_id, peer_node, DRC_UB_COMM_INIT_AREA_SIZE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] peer billboard verify failed after init barrier, self:%u peer:%u",
                       node_id, peer_node);
        return OG_ERROR;
    }

    if (!g_lock_comm_queue_inited) {
        g_lock_comm_queue_inited = OG_TRUE;
        drc_ubturbo_on_comm_queue_ready();
    }
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
    /* Node 1: RESET/INIT/SYNC handlers run via MES; wait until leader finishes SYNC. */
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
    /*
     * Three-phase cluster barrier (node 0 leader):
     *   1. RESET  - zero comm+lock UBSM on all nodes
     *   2. INIT   - each node calls ub_comm_queue_init on its DRC_DIST_QUE slice
     *   3. SYNC   - verify peer billboard, then drc_init_page_locks()
     */
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
        cm_spin_unlock(&g_dist_comm_coord_lock);
        return OG_SUCCESS;
    }

    epoch = ++g_dist_comm_epoch;
    g_lock_comm_queue_inited = OG_FALSE;
    g_dist_comm_ub_queue_inited = OG_FALSE;
    drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga);

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
    return OG_SUCCESS;
}

status_t drc_dist_comm_coordinated_init(knl_session_t *session)
{
    /*
     * Public entry (DB open / post-mmap). Node 0 drives RESET->INIT->SYNC barriers;
     * node 1 participates in broadcast handlers and polls completion here.
     */
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
    /* RESET handler (all nodes): drop comm/page-lock ready flags and zero dist shm. */
    mes_message_head_t ack_head = { 0 };
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_reset_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm reset msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_reset_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }
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
    /* INIT handler (all nodes): ub_comm_queue_init on local comm slice. */
    mes_message_head_t ack_head = { 0 };
    status_t ret = OG_SUCCESS;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_init_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm init msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_init_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

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
    /* SYNC handler (all nodes): verify peer billboard, then create page locks. */
    mes_message_head_t ack_head = { 0 };
    status_t ret = OG_SUCCESS;

    (void)sess;
    if (msg->head->size != sizeof(mes_dist_comm_sync_bcast_t)) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] dist comm sync msg size mismatch recv:%u expect:%u",
                       msg->head->size, (uint32)sizeof(mes_dist_comm_sync_bcast_t));
        mes_release_message_buf(msg->buffer);
        return;
    }

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
    /* Legacy follower wait; primary path is drc_dist_comm_coordinated_init at DB open. */
    if (g_lock_comm_queue_inited) {
        return OG_SUCCESS;
    }
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
        return OG_SUCCESS;
    }

    char *shmA = remote_sga->remote_buf_addr[0] + DRC_DIST_QUE_OFFSET;
    char *shmB = remote_sga->remote_buf_addr[1] + DRC_DIST_QUE_OFFSET;
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 0: %p", shmA);
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 1: %p", shmB);
    remote_sga->remote_pool_reserve_offset += DRC_DIST_QUE_OFFSET;

    const uint8_t nodeA = 0;
    const uint8_t nodeB = 1;
    const uint8_t cur = is_master ? nodeA : nodeB;
    const uint8_t peer = is_master ? nodeB : nodeA;
    void *init_region_cur = (is_master ? shmA : shmB);
    void *ring_region_cur = (is_master ? shmA : shmB) + DRC_UB_COMM_INIT_AREA_SIZE;
    void *ring_region_peer = (is_master ? shmB : shmA) + DRC_UB_COMM_INIT_AREA_SIZE;


    /*
     * Both nodes are mapped: zero comm+lock shm on every pool before ub_comm_queue_init /
     * ub_rw_lock_create so dual-node simultaneous startup and atomic<->ubturbo switch
     * always see a clean dist-lock layer.
     */
    drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga);

    ub_ring_desc_t ring_descs[1];
    ring_descs[0].ring_capacity = DRC_UB_COMM_RING_CAPACITY;
    ring_descs[0].max_msg_size = DRC_UB_COMM_MAX_MSG_SIZE;
    ring_descs[0].priority = 1;

    ub_comm_conf_t conf = { 0 };
    conf.cpu_id = -1;
    conf.max_nodes = 2;
    conf.current_node_id = cur;
    conf.num_rings = 1;
    conf.ring_descs = ring_descs;

    ub_shm_area_t init_area;
    init_area.size = DRC_UB_COMM_INIT_AREA_SIZE;
    init_area.ptr = init_region_cur;

    ub_ring_region_info_t infos[2];
    infos[0].node_id = cur;
    infos[0].region.size = DRC_UB_COMM_RING_AREA_SIZE;
    infos[0].region.ptr = ring_region_cur;
    infos[1].node_id = peer;
    infos[1].region.size = DRC_UB_COMM_RING_AREA_SIZE;
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
        return OG_ERROR;
    }
    g_lock_comm_queue_inited = OG_TRUE;
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

#if !USE_ATOMIC_LOCK
#define DRC_GBP_ASSERT_COMM_QUEUE_READY() CM_ASSERT(g_lock_comm_queue_inited)
#else
#define DRC_GBP_ASSERT_COMM_QUEUE_READY()
#endif

static uint32 drc_gbp_lock_timeout_ms(knl_session_t *session)
{
    uint32 timeout_ms = session->kernel->attr.ub_gbp_lock_timeout_ms;

    if (timeout_ms == 0) {
        timeout_ms = OG_DEFAULT_UB_GBP_LOCK_TIMEOUT_MS;
    }
    return timeout_ms;
}

static void drc_gbp_fill_lock_policy(knl_session_t *session, ub_lock_policy_t *policy)
{
    policy->timeout_ts = (time_ms_t)drc_gbp_lock_timeout_ms(session);
    policy->allow_delay_release = false;
    policy->recursive = false;
}

static ub_location_t make_location(uint8 node_id)
{
    ub_location_t loc;

    loc.node_id = node_id;
    loc.tid = (int32_t)cm_get_current_thread_id();
    return loc;
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

    /*
     * Lock pool base: local node's UBSM pool + DRC_DIST_LCK_OFFSET (256 MiB region).
     * Each GBP page slot gets lock_ptr = base + index * UB_RW_LOCK_SIZE (assigned in
     * drc_init_remote_buf_struct, dtc_remote_buffer.c).
     */
    *ub_lock = (ub_rw_lock_t *)(remote_sga->remote_buf_addr[node_id] + DRC_DIST_LCK_OFFSET);
    remote_sga->remote_pool_reserve_offset += DRC_DIST_LCK_OFFSET;
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock buf addr start: %p, reserve offset:%llu", *ub_lock,
                   remote_sga->remote_pool_reserve_offset);
}

status_t drc_create_page_ub_lock(ub_rw_lock_t *lock)
{
    drc_init_ub_page_lock_create_params();
    ub_rw_lock_create(lock, &g_ub_page_lock_config, &g_ub_page_lock_creator);
    return OG_SUCCESS;
}

#if !USE_ATOMIC_LOCK
void drc_ubturbo_on_comm_queue_ready(void)
{
    /* Phase C tail: comm queue is live; create per-page locks in local DRC_DIST_LCK region. */
    if (drc_init_page_locks() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] page_locks init after comm_queue failed");
    }
}

status_t drc_gbp_ensure_lock_attached(knl_session_t *session, uint64 lock_ptr, page_id_t page_id)
{
    (void)page_id;

    if (lock_ptr == 0) {
        return OG_ERROR;
    }

    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    (void)drc_create_page_ub_lock((ub_rw_lock_t *)(uintptr_t)lock_ptr);
    (void)session;
    return OG_SUCCESS;
}
#endif /* !USE_ATOMIC_LOCK */

status_t drc_gbp_distribute_lock(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, latch_mode_t mode)
{
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }
    if (drc_gbp_ensure_lock_attached(session, lock_ptr, page_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] start to get lock address for offset: %p", lock);
    int ret;
    const char *lock_type;
    drc_lock_mode_e lock_mode = (mode == LATCH_MODE_S ? DRC_LOCK_SHARE : DRC_LOCK_EXCLUSIVE);
    ub_location_t lock_location = make_location((uint8)DCS_SELF_INSTID(session));
    ub_lock_policy_t lock_policy;

    drc_gbp_fill_lock_policy(session, &lock_policy);

#if !USE_ATOMIC_LOCK
    if (lock_mode == DRC_LOCK_EXCLUSIVE) {
        ret = (int)ub_gbp_x_lock_fence(lock, &lock_policy, &lock_location);
        lock_type = "exlcusive";
    } else {
        ret = (int)ub_gbp_s_lock_fence(lock, &lock_policy, &lock_location);
        lock_type = "shared";
    }
#else
    if (lock_mode == DRC_LOCK_EXCLUSIVE) {
        ret = ub_rw_lock_x_lock(lock, &lock_policy, &lock_location);
        lock_type = "exlcusive";
    } else {
        ret = ub_rw_lock_s_lock(lock, &lock_policy, &lock_location);
        lock_type = "shared";
    }
#endif

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
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
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
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    ub_rw_lock_end_page_store((ub_rw_lock_t *)(uintptr_t)lock_ptr);
}

status_t drc_gbp_distribute_lock_for_store(knl_session_t *session, uint64 lock_ptr, page_id_t page_id)
{
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }
    if (drc_gbp_ensure_lock_attached(session, lock_ptr, page_id) != OG_SUCCESS) {
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
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to get lock address for offset: %llu", lock_ptr);
        return OG_ERROR;
    }
    if (drc_gbp_ensure_lock_attached(session, lock_ptr, page_id) != OG_SUCCESS) {
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
    DRC_GBP_ASSERT_COMM_QUEUE_READY();
    ub_rw_lock_t *lock = (ub_rw_lock_t *)lock_ptr;
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] Failed to acquire lock for page");
        return OG_ERROR;
    }
    if (drc_gbp_ensure_lock_attached(session, lock_ptr, page_id) != OG_SUCCESS) {
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
    ub_lock_policy_t lock_policy;

    drc_gbp_fill_lock_policy(session, &lock_policy);

    if (lock_mode == DRC_LOCK_EXCLUSIVE) {
        ret = ub_rw_lock_x_unlock(lock, &lock_policy, &lock_location);
        lock_type = "exlcusive";
    } else {
        ret = ub_rw_lock_s_unlock(lock, &lock_policy, &lock_location);
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
    if (lock_ptr == 0) {
        *atomic_state = 0;
        *x_owner_node = -1;
        *write_waiters = 0;
        *owner_tid = -1;
        return;
    }
    ub_rw_lock_t *lock = (ub_rw_lock_t *)(uintptr_t)lock_ptr;
    ub_gbp_lock_raw_t raw;

    ub_gbp_lock_read_raw(lock, &raw);
    *atomic_state = raw.g_lock_word;
    *write_waiters = (int32)raw.g_waiters;
    *x_owner_node = -1;
    *owner_tid = -1;
    if (raw.g_lock_word == 0 && raw.owner_x != 0 && raw.owner_x != 0xFF00000000ULL) {
        *x_owner_node = (int32)raw.owner_x_node;
        *owner_tid = raw.owner_x_tid;
    }
#endif
}
