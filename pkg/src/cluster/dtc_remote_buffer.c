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
 * dtc_remote_buffer.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_buffer.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/syscall.h>
#include "knl_cluster_module.h"
#include "cm_defs.h"
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_drc_stat.h"
#include "dtc_remote_lock.h"
#include "dtc_database.h"
#include "cm_malloc.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "cs_ub.h"
#include "srv_sga.h"
#include "cm_ubs_mem.h"
#include "knl_common.h"
#include "knl_buffer.h"

#include "ub_dist_comm_queue.h"
#include "dtc_remote_lock.h"

static ub_rw_lock_t *g_ub_lock = NULL;

static void drc_reset_ubsm_node_dist_areas(char *base)
{
    if (base == NULL) {
        return;
    }
    knl_reset_large_memory(base + DRC_DIST_QUE_OFFSET, DRC_DIST_QUE_SIZE);
    knl_reset_large_memory(base + DRC_DIST_LCK_OFFSET, DRC_DISK_LCK_SIZE);
}

static void drc_reset_ubsm_local_gbp_page_bufs(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 page_size = sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64);

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        buf_set_t *set = &buf_ctx->buf_set[i];
        uint64 bytes = (uint64)page_size * set->capacity;
        if (set->page_buf != NULL && bytes > 0) {
            knl_reset_large_memory(set->page_buf, bytes);
        }
    }
    OG_LOG_RUN_WAR("[DRC-GBP] reset local GBP page bufs, node:%u data_buf:%p sets:%u",
                   g_instance->kernel.id, remote_sga->data_buf, buf_ctx->buf_set_count);
}

void drc_ubsm_reset_mapped_dist_for_fresh_start(remote_sga_t *remote_sga)
{
    if (!g_dtc->kernel->attr.enable_remote_distribute_lock) {
        return;
    }

    for (uint32 node_id = 0; node_id < g_mes.profile.inst_count; node_id++) {
        if (remote_sga->map_success[node_id] != OG_TRUE || remote_sga->remote_buf_addr[node_id] == NULL) {
            continue;
        }
        drc_reset_ubsm_node_dist_areas(remote_sga->remote_buf_addr[node_id]);
        OG_LOG_RUN_WAR("[DRC-GBP] reset UBSM comm+lock regions for fresh start, node:%u base:%p self:%u",
                       node_id, remote_sga->remote_buf_addr[node_id], g_instance->kernel.id);
    }
}

// page_info_t + page + end_lsn + bucket_t + buf_ctrl_t
#define REMOTE_BUF_PAGE_COST                                                       \
    (sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64) + \
     BUCKET_TIMES * sizeof(buf_bucket_t) + sizeof(buf_ctrl_t))

static inline uint64 drc_calc_buf_size(uint64 size)
{
    uint64 align_size = CM_CALC_ALIGN(size + SGA_BARRIER_SIZE, OG_MAX_ALIGN_SIZE_4K);
    return align_size;
}

static uint64 drc_calc_remote_data_buf_size(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    /* adjust buf_ctx_count to match the data_buf_size */
    if ((g_dtc->profile.remote_buf_pool_num > 1) &&
        (g_dtc->profile.remote_data_buf_size < BUF_POOL_SIZE_THRESHOLD * g_dtc->profile.remote_buf_pool_num)) {
        buf_ctx->buf_set_count = MAX(1, (uint32)(g_dtc->profile.remote_data_buf_size / BUF_POOL_SIZE_THRESHOLD));
        OG_LOG_RUN_WAR("[DRC] The parameter buffer pool num (%d) is too large, reset to (%d), each buffer"
                       "pool must not be smaller than (%lld).",
                       g_dtc->profile.remote_buf_pool_num, buf_ctx->buf_set_count, BUF_POOL_SIZE_THRESHOLD);
    } else {
        buf_ctx->buf_set_count = g_dtc->profile.remote_buf_pool_num;
    }
    g_dtc->profile.remote_data_buf_part_size = g_dtc->profile.remote_data_buf_size / buf_ctx->buf_set_count;
    g_dtc->profile.remote_data_buf_part_align_size = drc_calc_buf_size(g_dtc->profile.remote_data_buf_part_size);
    remote_sga->remote_buf_alloc_size = g_dtc->profile.remote_data_buf_part_size * buf_ctx->buf_set_count;
    remote_sga->remote_pool_reserve_offset = remote_sga->remote_buf_alloc_size;
    return remote_sga->remote_buf_alloc_size;
}

status_t dtc_mmap_remote_data_buf(remote_sga_t *remote_sga, uint32 node_id)
{
    int ret = OG_ERROR;
    void *start = (void *)(node_id == 0 ? DRC_BASE_ADDR_0 : DRC_BASE_ADDR_1);
    remote_sga->remote_total_pool_size = ALIGN_TO_128M(DRC_SHM_SIZE);
    char data_buf_name[MAX_REGION_NAME_DESC_LENGTH] = { 0 };
    struct passwd *pwd;
    pwd = getpwuid(getuid());
    OG_LOG_RUN_WAR("[DRC-GBP] uid %d, name: %s", getuid(), pwd->pw_name);
    ret = sprintf_s(data_buf_name, sizeof(data_buf_name), "%s_data_buf_part_%d", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC-GBP] sprintf remote data buf name fail,return error:%d", ret);
        return ret;
    }

    if (remote_sga->map_success[node_id] == OG_TRUE) {
        OG_LOG_RUN_WAR("[DRC-GBP] remote data buf part %d has been mapped, skip.", node_id);
        return OG_SUCCESS;
    }

    ret = ubsmem_shmem_map(start, remote_sga->remote_total_pool_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                           data_buf_name, 0, (void **)&(remote_sga->remote_buf_addr[node_id]));
    OG_LOG_RUN_WAR("[DRC-GBP] sprintf remote data buf addr start: %p", remote_sga->remote_buf_addr[node_id]);
    if (ret != EOK) {
        OG_LOG_RUN_ERR("[DRC-GBP] Failed to map data buffer %s on node_id %u, return error:%d", data_buf_name, node_id,
                       ret);
        return ret;
    }

    remote_sga->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[DRC-GBP-BUFFER] Successfully mapped data buffer %s on node_id %u, addr: %p", data_buf_name,
                   node_id, remote_sga->remote_buf_addr[node_id]);
    return OG_SUCCESS;
}

static status_t drc_alloc_mmap_remote_buffer_pool(remote_sga_t *remote_sga)
{
    uint32 node_id = g_instance->kernel.id;
    remote_sga->remote_total_pool_size = ALIGN_TO_128M(DRC_SHM_SIZE);
    /* NOTICE: for demo test, we set inst_count = 2. then the single node test or multi nodes test can use UB shm. */
    g_mes.profile.inst_count = 2;

    int ret = ub_create_shm_region(node_id, g_mes.profile.inst_count,
        g_instance->kernel.attr.ubs_cluster_hosts);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] drc create sgm region fail, return error:%d", ret);
        return ret;
    }

    char data_buf_name[MAX_SHM_NAME_LENGTH] = { 0 };
    struct passwd *pwd;
    pwd = getpwuid(getuid());
    ret = sprintf_s(data_buf_name, sizeof(data_buf_name), "%s_data_buf_part_%d", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] sprintf remote data buf name fail,return error:%d", ret);
        return ret;
    }

    char region_name[MAX_REGION_NAME_DESC_LENGTH] = { 0 };
    ret = sprintf_s(region_name, sizeof(region_name), "shm_pool_%d", node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] sprintf remote data buf region name fail,return error:%d", ret);
        return ret;
    }

    ret = ubsmem_shmem_allocate(region_name, data_buf_name, remote_sga->remote_total_pool_size, 0600,
                                UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE);
    if (ret == UBSM_ERR_ALREADY_EXIST) {
        OG_LOG_RUN_WAR("[DRC]data buffer %s already exist, ret: %d", data_buf_name, ret);
    } else if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[DRC]data buffer %s allocate fail, ret: %d", data_buf_name, ret);
        return ret;
    }

    // after allocate remote data buf, map the buf on self node.
    ret = dtc_mmap_remote_data_buf(remote_sga, node_id);
    if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[DRC]mmap remote data buf %s on node %u failed, ret: %d", data_buf_name, node_id, ret);
    }
    return ret;
}

static inline void drc_set_remote_buffer(char **buf, char *remote_buf_addr, uint64 size, uint64 *offset)
{
    char *barrier = NULL;

    *buf = remote_buf_addr + *offset;
    barrier = remote_buf_addr + *offset + size;
    *offset += srv_calc_buf_size(size);

    MEMS_RETVOID_IFERR(memset_s(barrier, SGA_BARRIER_SIZE, 0xFF, SGA_BARRIER_SIZE));
}

static void drc_set_data_buf(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 node_id = g_instance->kernel.id;
    uint32 data_buf_part_size = g_dtc->profile.remote_data_buf_part_size;
    char *temp_buf = NULL;
    uint64 offset = (OG_MAX_ALIGN_SIZE_4K - ((uint64)remote_sga->remote_buf_addr[node_id]) % OG_MAX_ALIGN_SIZE_4K);

    /* * allocate each data buffer part */
    drc_set_remote_buffer(&remote_sga->data_buf, remote_sga->remote_buf_addr[node_id], data_buf_part_size, &offset);

    for (uint32 i = 1; i < buf_ctx->buf_set_count; i++) {
        drc_set_remote_buffer(&temp_buf, remote_sga->remote_buf_addr[node_id], data_buf_part_size, &offset);
    }
}

static void buf_init_list(buf_set_t *set)
{
    for (uint32 i = 0; i < LRU_LIST_TYPE_COUNT; i++) {
        set->list[i] = g_init_list_t;
        set->list[i].type = i;
    }
}

static void drc_init_remote_buf_struct(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 page_size = sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64);

    buf_set_t *set = NULL;
    uint64 offset;
    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        drc_init_remote_lock(&g_ub_lock);
    }

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        set = &buf_ctx->buf_set[i];
        set->lock = 0;
        set->size = g_dtc->profile.remote_data_buf_part_size;
        set->addr = remote_sga->data_buf + i * g_dtc->profile.remote_data_buf_part_align_size;  // start addr of each
                                                                                                // buf_set in UB shm.
        cm_init_cond(&set->set_cond);
        /* set->size <= 32T, BUF_PAGE_COST >= 8360, set->capacity cannot overflow */
        set->capacity = (uint32)(set->size / REMOTE_BUF_PAGE_COST);
        set->hwm = 0;
        set->page_buf = set->addr;  // in UB shm, page_buf includes remote_page_info_t, page and tail_lsn

        offset = (uint64)page_size * set->capacity;
        set->ctrls = (buf_ctrl_t *)(set->addr + offset);
        offset += (uint64)set->capacity * sizeof(buf_ctrl_t);
        set->buckets = (buf_bucket_t *)(set->addr + offset);
        set->bucket_num = BUCKET_TIMES * set->capacity;
    }

    /*
     * Zero local GBP page meta/data and dist areas on every startup so reattach after
     * USE_ATOMIC_LOCK=1/0 switch or crash does not reuse stale lock/comm_queue state.
     */
    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        drc_reset_ubsm_local_gbp_page_bufs(remote_sga, buf_ctx);
        drc_reset_ubsm_node_dist_areas(remote_sga->remote_buf_addr[g_instance->kernel.id]);
    }

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        set = &buf_ctx->buf_set[i];

        for (uint32 j = 0; j < set->capacity; j++) {
            char *page_addr = set->page_buf + j * page_size;
            remote_page_info_t *page_info = (remote_page_info_t *)page_addr;
            if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
                uint64 lock_match_start = (uint64)((char *)g_ub_lock + i * set->capacity * UB_RW_LOCK_SIZE);
                page_info->lock_ptr = (uint64)((char *)lock_match_start + j * UB_RW_LOCK_SIZE);
            }
        }

        knl_reset_large_memory((char *)set->buckets, (uint64)sizeof(buf_bucket_t) * set->bucket_num);
        buf_init_list(set);
    }

    cm_init_thread_lock(&buf_ctx->buf_mutex);

    return;
}

static status_t drc_validate_lock_region_size(remote_buf_context_t *buf_ctx)
{
    if (!g_dtc->kernel->attr.enable_remote_distribute_lock) {
        return OG_SUCCESS;
    }

    uint64 total_pages = 0;
    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        total_pages += buf_ctx->buf_set[i].capacity;
    }

    uint64 lock_bytes = total_pages * (uint64)UB_RW_LOCK_SIZE;
    if (lock_bytes > DRC_DISK_LCK_SIZE) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] lock region overflow: need %llu bytes, limit %llu",
                       lock_bytes, (uint64)DRC_DISK_LCK_SIZE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 g_page_locks_inited = OG_FALSE;

static status_t drc_create_page_locks(remote_buf_context_t *buf_ctx)
{
    uint32 page_size = sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64);

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        buf_set_t *set = &buf_ctx->buf_set[i];
        for (uint32 j = 0; j < set->capacity; j++) {
            char *page_addr = set->page_buf + j * page_size;
            remote_page_info_t *page_info = (remote_page_info_t *)page_addr;
            if (page_info->lock_ptr == 0) {
                OG_LOG_RUN_ERR("[DRC-GBP-LOCK] page %u lock_ptr is NULL", j);
                return OG_ERROR;
            }
            if (drc_create_page_ub_lock((ub_rw_lock_t *)(page_info->lock_ptr)) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DRC-GBP-LOCK] page %u ub_rw_lock_create failed", j);
                return OG_ERROR;
            }
            OG_LOG_RUN_INF("[DRC-GBP-LOCK] page %u, addr %p, lock addr: %p", j, (void *)page_addr,
                           (void *)page_info->lock_ptr);
        }
    }
    return OG_SUCCESS;
}

status_t drc_init_page_locks(void)
{
    if (g_page_locks_inited) {
        return OG_SUCCESS;
    }
    if (!g_dtc->kernel->attr.enable_remote_distribute_lock) {
        return OG_SUCCESS;
    }

    drc_res_ctx_t *ogx = DRC_RES_CTX;
    status_t ret = drc_create_page_locks(&ogx->buf_ctx);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] drc_create_page_locks failed");
        return ret;
    }
    g_page_locks_inited = OG_TRUE;
    drc_gbp_lock_log_flow("page_locks_batch_init_done");
    return OG_SUCCESS;
}

status_t drc_init_remote_buffer()
{
    drc_res_ctx_t *ogx = DRC_RES_CTX;
    status_t ret = drc_alloc_mmap_remote_buffer_pool(&ogx->remote_sga);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC]alloc mmap remote buffer pool fail,return error:%u", ret);
        return ret;
    }

    (void)drc_calc_remote_data_buf_size(&ogx->remote_sga, &ogx->buf_ctx);
    drc_set_data_buf(&ogx->remote_sga, &ogx->buf_ctx);
    drc_init_remote_buf_struct(&ogx->remote_sga, &ogx->buf_ctx);
    ret = drc_validate_lock_region_size(&ogx->buf_ctx);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC] validate lock region size fail, return error:%u", ret);
        return ret;
    }
#if USE_ATOMIC_LOCK
    return drc_init_page_locks();
#else
    return OG_SUCCESS;
#endif
}

void broadcast_remote_buf_allocated()
{
    mes_remote_buf_mmap_bcast_t bcast;
    uint64 success_inst;
    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_REMOTE_BUF_MMAP, sizeof(mes_remote_buf_mmap_bcast_t),
                       OG_INVALID_ID32, g_dtc->profile.inst_id, OG_INVALID_ID8, 0, OG_INVALID_ID16);
    bcast.node_id = g_dtc->profile.inst_id;

    mes_broadcast(0, MES_BROADCAST_ALL_INST, &bcast, &success_inst);
}

void drc_process_remote_buf_mmap(void *sess, mes_message_t *msg)
{
    drc_res_ctx_t *ogx = DRC_RES_CTX;

    if (sizeof(mes_remote_buf_mmap_bcast_t) != msg->head->size) {
        OG_LOG_RUN_ERR("[DRC]recv remote buf mmap bcast msg length not match, recv %u", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_remote_buf_mmap_bcast_t *bcast = (mes_remote_buf_mmap_bcast_t *)msg->buffer;
    uint32 node_id = bcast->node_id;
    if (msg->head->src_inst >= OG_MAX_INSTANCES) {
        mes_release_message_buf(msg->buffer);
        OG_LOG_RUN_ERR("[DRC]Do not process remote buf mmap broadcast, because src_inst is invalid: %u",
                       msg->head->src_inst);
        return;
    }
    mes_release_message_buf(msg->buffer);
    OG_LOG_RUN_WAR("[DRC-GBP]drc_process_remote_buf_mmap, node id %u", node_id);
    (void)dtc_mmap_remote_data_buf(&ogx->remote_sga, node_id);
    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        knl_session_t *knl_sess = (knl_session_t *)sess;
        if (drc_dist_comm_coordinated_init(knl_sess) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DRC-GBP] dist comm coordinated init failed after mmap, node:%u", node_id);
        }
        drc_gbp_lock_log_flow("broadcast_mmap_comm_queue_retry");
    }
}

#define GBP_READONLY_WAIT_MAX_TIMES 1000

static status_t dtc_buf_wait_readonly_clear(ub_rw_lock_t *lock, page_id_t page_id)
{
    uint32 times = 0;

    while (ub_rw_lock_get_readonly(lock)) {
        times++;
        if (SECUREC_UNLIKELY(times > GBP_READONLY_WAIT_MAX_TIMES)) {
            OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] wait readonly clear timeout", page_id.file, page_id.page);
            return OG_ERROR;
        }
        if (times % 50 == 0) {
            cm_sleep(1);
        }
    }

    return OG_SUCCESS;
}

static inline status_t dcs_copy_page_from_shmem(knl_session_t *session, buf_ctrl_t *ctrl)
{
    char *page = (char *)ctrl->shmem_page_addr;
    errno_t err = memcpy_s(ctrl->page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(err);

    return OG_SUCCESS;
}

/*
 * Copy page from GBP shmem; if head/tail pcn mismatch and lock is readonly,
 * wait for readonly to clear and copy once more.
 */
static status_t dtc_buf_copy_from_gbp_shmem(knl_session_t *session, buf_ctrl_t *ctrl, uint64 lock_offset)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)(uintptr_t)lock_offset;
    status_t ret;

    dcs_copy_page_from_shmem(session, ctrl);
    if (CHECK_PAGE_PCN(ctrl->page)) {
        return OG_SUCCESS;
    }

    if (!ub_rw_lock_get_readonly(lock)) {
        OG_LOG_RUN_WAR("[DTC-GBP-COPY][%u-%u] page pcn mismatch without readonly, head pcn:%u, tail pcn:%u",
            ctrl->page_id.file, ctrl->page_id.page, (uint32)ctrl->page->pcn, (uint32)PAGE_TAIL(ctrl->page)->pcn);
        return OG_ERROR;
    }

    OG_LOG_RUN_WAR("[DTC-GBP-COPY][%u-%u] page pcn mismatch while readonly, head pcn:%u, tail pcn:%u, wait and recopy",
        ctrl->page_id.file, ctrl->page_id.page, (uint32)ctrl->page->pcn, (uint32)PAGE_TAIL(ctrl->page)->pcn);

    ret = dtc_buf_wait_readonly_clear(lock, ctrl->page_id);
    if (ret != OG_SUCCESS) {
        return ret;
    }

    dcs_copy_page_from_shmem(session, ctrl);
    if (!CHECK_PAGE_PCN(ctrl->page)) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] page pcn still mismatch after readonly clear, head pcn:%u, tail pcn:%u",
            ctrl->page_id.file, ctrl->page_id.page, (uint32)ctrl->page->pcn, (uint32)PAGE_TAIL(ctrl->page)->pcn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void dtc_buf_gbp_hold(buf_ctrl_t *ctrl, latch_mode_t mode)
{
    ctrl->gbp_lock_count++;
    ctrl->gbp_lock_mode = (uint8)mode;
}

status_t dtc_buf_gbp_unhold(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode)
{
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    status_t ret = OG_SUCCESS;

    if (shmem_page_meta == NULL) {
        return OG_SUCCESS;
    }

    ret = drc_gbp_distribute_unlock(session, shmem_page_meta->lock_ptr, ctrl->page_id, mode);
    if (ctrl->gbp_lock_count > 0) {
        ctrl->gbp_lock_count--;
        if (ctrl->gbp_lock_count == 0) {
            ctrl->gbp_lock_mode = DRC_LOCK_NULL;
        }
    }
    return ret;
}

static uint32 dtc_buf_gbp_release_session_s_locks(knl_session_t *session, buf_ctrl_t *ctrl, uint32 *saved_indices,
    uint32 max_saved)
{
    uint32 saved_count = 0;

    for (uint32 i = 0; i < session->page_stack.depth; i++) {
        if (session->page_stack.pages[i] != ctrl) {
            continue;
        }
        if (session->page_stack.gbp_lock_modes[i] != LATCH_MODE_S) {
            continue;
        }
        if (saved_count < max_saved) {
            saved_indices[saved_count] = i;
        }
        saved_count++;
        (void)dtc_buf_gbp_unhold(session, ctrl, LATCH_MODE_S);
        session->page_stack.gbp_lock_modes[i] = DRC_LOCK_NULL;
    }
    return saved_count;
}

static void dtc_buf_gbp_restore_session_s_locks(knl_session_t *session, buf_ctrl_t *ctrl, uint64 lock_offset,
    const uint32 *saved_indices, uint32 saved_count)
{
    for (uint32 j = 0; j < saved_count; j++) {
        uint32 i = saved_indices[j];

        if (session->page_stack.gbp_lock_modes[i] != DRC_LOCK_NULL) {
            continue;
        }
        if (drc_gbp_distribute_lock(session, lock_offset, ctrl->page_id, LATCH_MODE_S) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC-GBP-CHECK][%u-%u] failed to restore S lock after X upgrade rollback",
                ctrl->page_id.file, ctrl->page_id.page);
            continue;
        }
        session->page_stack.gbp_lock_modes[i] = LATCH_MODE_S;
        dtc_buf_gbp_hold(ctrl, LATCH_MODE_S);
    }
}

bool32 dtc_buf_session_owns_gbp_store_fence(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (!ctrl->gbp_store_pending) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < session->changed_count; i++) {
        if (session->changed_pages[i] == ctrl) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static void dtc_buf_gbp_abort_x_after_upgrade(knl_session_t *session, buf_ctrl_t *ctrl, uint64 lock_offset,
    bool32 x_already_held, bool32 did_s_upgrade, const uint32 *saved_indices, uint32 saved_count)
{
    if (!x_already_held) {
        (void)drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, LATCH_MODE_X);
    }
    if (did_s_upgrade) {
        dtc_buf_gbp_restore_session_s_locks(session, ctrl, lock_offset, saved_indices, saved_count);
    }
}

bool32 dtc_buf_gbp_should_unlock_on_leave(knl_session_t *session, buf_ctrl_t *ctrl, uint32 stack_idx,
    latch_mode_t mode)
{
    if (mode != LATCH_MODE_X) {
        return OG_TRUE;
    }

    /*
     * UB X lock is reentrant per thread. Only the outermost X stack frame should x_unlock;
     * inner reenter frames skip unlock to match a single gbp_lock_count increment.
     */
    for (uint32 i = 0; i < stack_idx; i++) {
        if (session->page_stack.pages[i] == ctrl && session->page_stack.gbp_lock_modes[i] == LATCH_MODE_X) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

status_t dtc_buf_check_local_page(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, bool32 *is_load)
{
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    uint64 lock_offset = shmem_page_meta->lock_ptr;
    status_t ret;
    bool32 x_already_held = OG_FALSE;
    bool32 did_s_upgrade = OG_FALSE;
    bool32 skip_shmem_s_lock = OG_FALSE;
    uint32 s_upgraded[KNL_MAX_PAGE_STACK_DEPTH];
    uint32 s_upgraded_count = 0;

    if (mode == LATCH_MODE_X) {
        ub_rw_lock_t *lock = (ub_rw_lock_t *)(uintptr_t)lock_offset;
        x_already_held = ub_rw_lock_is_x_held_by_current_thread(lock, (uint8)DCS_SELF_INSTID(session),
            (int32)cm_get_current_thread_id());
        s_upgraded_count = dtc_buf_gbp_release_session_s_locks(session, ctrl, s_upgraded,
            KNL_MAX_PAGE_STACK_DEPTH);
        did_s_upgrade = (s_upgraded_count > 0);
    }
    
    // The same session reenter witch s lock. if like that Conditionallockbufferforcleanup in pg.
    skip_shmem_s_lock = (bool32)(mode == LATCH_MODE_S && dtc_buf_session_owns_gbp_store_fence(session, ctrl));
    if (skip_shmem_s_lock) {
        OG_LOG_DEBUG_INF("[DTC-GBP-CHECK][%u-%u]: skip S lock while store fence owned by session",
            ctrl->page_id.file, ctrl->page_id.page);
        ret = OG_SUCCESS;
    } else if (mode == LATCH_MODE_X && dtc_buf_session_owns_gbp_store_fence(session, ctrl)) {
        OG_LOG_DEBUG_INF("[DTC-GBP-CHECK][%u-%u]: reenter X after leave(changed), bypass store fence",
            ctrl->page_id.file, ctrl->page_id.page);
        ret = drc_gbp_distribute_lock_reenter(session, lock_offset, ctrl->page_id);
    } else {
        ret = drc_gbp_distribute_lock(session, lock_offset, ctrl->page_id, mode);
    }
    if (ret != OG_SUCCESS) {
        if (mode == LATCH_MODE_X && did_s_upgrade) {
            dtc_buf_gbp_restore_session_s_locks(session, ctrl, lock_offset, s_upgraded, s_upgraded_count);
        }
        OG_LOG_RUN_WAR("[DTC-GBP-CHECK][%u-%u] failed to lock shmem page, return", ctrl->page_id.file,
                        ctrl->page_id.page);
        return ret;
    }
    if (!skip_shmem_s_lock) {
        ctrl->gbp_lock_mode = mode;
    }

    // check page identifier of remote buf meta with ctrl->page_id
    if (shmem_page_meta->file_id != ctrl->page_id.file || shmem_page_meta->page_id != ctrl->page_id.page) {
        datafile_t *df = NULL;
        df = DATAFILE_GET(session, ctrl->page_id.file);
        OG_LOG_RUN_ERR("[BUFFER-GBP] page in gbp %u-%u is incorret: local buffer file id %u, page id %u, file name %s",
                       shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page,
                       df->ctrl->name);
        if (mode == LATCH_MODE_X) {
            dtc_buf_gbp_abort_x_after_upgrade(session, ctrl, lock_offset, x_already_held, did_s_upgrade, s_upgraded,
                s_upgraded_count);
        } else if (!skip_shmem_s_lock) {
            (void)drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
        }
        return OG_ERROR;
    }

    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);

    if (remote_head_lsn != remote_tail_lsn) {
        OG_LOG_RUN_ERR("[DTC-GBP-CHECK][%u-%u]: head/tail lsn mismatch, head lsn(%llu), tail lsn(%llu)",
            ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, remote_tail_lsn);
        if (mode == LATCH_MODE_X) {
            dtc_buf_gbp_abort_x_after_upgrade(session, ctrl, lock_offset, x_already_held, did_s_upgrade, s_upgraded,
                s_upgraded_count);
        } else if (!skip_shmem_s_lock) {
            ret = drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
            if (ret != OG_SUCCESS) {
                return ret;
            }
        }
        return OG_ERROR;
    }

    // LSN Check: Ensure the requester doesn't have a "newer" LSN than the gbp owner
    bool32 readonly = ub_rw_lock_get_readonly((ub_rw_lock_t *)(uintptr_t)lock_offset);
    if (remote_head_lsn < ctrl->page->lsn && readonly == false) {
        OG_LOG_RUN_ERR("[DTC-GBP-CHECK][%u-%u]: lsn check failed, remote page lsn(%llu), ctrl->page->lsn(%llu), "
            "readonly:%d tid:%d",
            ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn, (int32)readonly,
            (int32)cm_get_current_thread_id());
        if (mode == LATCH_MODE_X) {
            dtc_buf_gbp_abort_x_after_upgrade(session, ctrl, lock_offset, x_already_held, did_s_upgrade, s_upgraded,
                s_upgraded_count);
        } else if (!skip_shmem_s_lock) {
            ret = drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
            if (ret != OG_SUCCESS) {
                return ret;
            }
        }
        return OG_ERROR;
    }

    // there is occurs that page in gbp update, local ctrl->page is old so need to load from gbp again
    if (remote_head_lsn > ctrl->page->lsn) {
        *is_load = OG_TRUE;
    } else {
        /* two case which mean that ctrl->page->lsn is newest
         * one case: ctrl->page->lsn == remote_head_lsn, indicate that no one wirte this page.
         * two case: ctrl->page->lsn > remote_head_lsn. current node write this page with unlock remote lock,
         *           but readonly is true, ctrl->page->lsn is newest.
         */
        OG_LOG_DEBUG_INF(
            "[DTC-GBP-CHECK][%u-%u]: use current local page, remote page lsn(%llu), local page lsn(%llu), mode: %u",
            ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn, mode);
    }
    OG_LOG_RUN_INF(
        "[DTC-GBP-CHECK][%u-%u]: check local page success, remote page lsn(%llu), local page lsn(%llu), mode: %u, "
        "skip_shmem_s_lock %d, is_load %d, readonly %d, tid:%d",
        ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn, mode,
        skip_shmem_s_lock, *is_load, readonly, (int32)cm_get_current_thread_id());
    
    if (!(mode == LATCH_MODE_X && x_already_held) && !skip_shmem_s_lock) {
        dtc_buf_gbp_hold(ctrl, mode);
    }
    return OG_SUCCESS;
}

status_t dtc_buf_try_load_from_gbp(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode)
{
    remote_sga_t *remote_sga = &DRC_RES_CTX->remote_sga;
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    uint64 lock_offset = shmem_page_meta->lock_ptr;
    status_t ret;

    uint8 gbp_owner_id = shmem_page_meta->claimed_owner;

    if (gbp_owner_id != DCS_SELF_INSTID(session)) {
        if (remote_sga->map_success[gbp_owner_id] != OG_TRUE) {
            int ret = dtc_mmap_remote_data_buf(remote_sga, gbp_owner_id);
            if (ret != UBSM_OK) {
                OG_LOG_RUN_ERR("[DRC]mmap remote data buf on node %u failed, ret: %d", gbp_owner_id, ret);
            }
        }
    }

    ret = dtc_buf_copy_from_gbp_shmem(session, ctrl, lock_offset);
    if (ret != OG_SUCCESS) {
        (void)dtc_buf_gbp_unhold(session, ctrl, mode);
        OG_LOG_RUN_WAR("[BUFFER-GBP] copy_from_gbp_shmem fail: local buffer file id %u, page id %u. "
            "remote file %u, remote page %u",
            shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page);
        return OG_ERROR;
    }

    heap_page_t *heap_page = (heap_page_t *)ctrl->page;
    OG_LOG_DEBUG_INF("[DTC_HEAP_COPY_GBP] page[%u-%u], oid: %d, page addr: %p, page_lsn %llu, page addr by meta: %p, "
                   "meta addr: %p.", AS_PAGID(heap_page->head.id).file, AS_PAGID(heap_page->head.id).page,
                   heap_page->oid, ctrl->shmem_page_addr, heap_page->head.lsn,
                   GET_PAGE_ADDR_IN_GBP((char *)shmem_page_meta), shmem_page_meta);

    // check page identifier of remote buf meta with remote page
    if (shmem_page_meta->file_id != AS_PAGID(heap_page->head.id).file ||
        shmem_page_meta->page_id != AS_PAGID(heap_page->head.id).page) {
        datafile_t *df = NULL;
        df = DATAFILE_GET(session, ctrl->page_id.file);
        // if mode is X, no need to unlock, unlock after write finished
        ret = dtc_buf_gbp_unhold(session, ctrl, mode);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC-GBP][%u-%u] failed to unlock shmem page.", ctrl->page_id.file, ctrl->page_id.page);
            return ret;
        }
        OG_LOG_RUN_ERR("[BUFFER-GBP] page in gbp %u-%u is incorret: local buffer file id %u, page id %u, file name %s",
                       shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page,
                       df->ctrl->name);
        return OG_ERROR;
    }
    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);

    if (remote_head_lsn != remote_tail_lsn) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u]: head/tail lsn mismatch, head lsn(%llu), tail lsn(%llu), pcn: %u, "
            "tail pcn: %u", ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, remote_tail_lsn,
            (ctrl->page)->pcn, PAGE_TAIL(ctrl->page)->pcn);
        ret = dtc_buf_gbp_unhold(session, ctrl, mode);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC-GBP][%u-%u] failed to unlock shmem page.", ctrl->page_id.file, ctrl->page_id.page);
            return ret;
        }
        return OG_ERROR;
    }

    // to do: dtc_update_lsn(session, remote_head_lsn), need to think how to set.
    // to do：dtc_update_scn(session, ctrl->scn); need to think how to set.
    dtc_update_lsn(session, remote_head_lsn);

    /*
     * lock_mode and transfer_status no need for page in gbp. When gbp page is transfer back to local buffer,
     * we must consider how to handel ctrl->lock_mode.
     */
    ctrl->lock_mode = DRC_LOCK_NULL;
    ctrl->transfer_status = BUF_TRANS_NONE;

    // ctrl->load_status need to set BUF_IS_LOADED, because commit need to check this status
    ctrl->load_status = (uint8)BUF_IS_LOADED;

    return OG_SUCCESS;
}

status_t dtc_buf_try_store_to_gbp(knl_session_t *session, buf_ctrl_t *ctrl, uint64 curr_lsn)
{
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    page_head_t *shmem_page_addr = ctrl->shmem_page_addr;
    uint8 curr_node_id = DCS_SELF_INSTID(session);

    // to do: check local ctrl page lsn and remote page lsn
    uint64 ctrl_page_lsn = ctrl->page->lsn;
    uint64 remote_page_lsn = curr_lsn;

    // Has acquired global lock  when copy from gbp ->local
    remote_page_info_t new_shmem_page_meta;
    new_shmem_page_meta.lock_ptr = ctrl->shmem_page_meta->lock_ptr;
    new_shmem_page_meta.head_lsn = remote_page_lsn;
    new_shmem_page_meta.file_id = ctrl->page_id.file;
    new_shmem_page_meta.page_id = ctrl->page_id.page;
    new_shmem_page_meta.claimed_owner = ctrl->shmem_page_meta->claimed_owner;
    new_shmem_page_meta.touch_number = shmem_page_meta->touch_number + 1;
    new_shmem_page_meta.ref_num = 0;
    new_shmem_page_meta.xlog_owner_node = curr_node_id;
    new_shmem_page_meta.xlog_owner_node_timeline_id[curr_node_id] = curr_node_id;

    char *page_tail_lsn_addr = (char *)shmem_page_meta + OFFSET_TAIL_LSN;
    uint64 page_tail_lsn = remote_page_lsn;

    errno_t err = memcpy_s(shmem_page_meta, sizeof(remote_page_info_t), &new_shmem_page_meta,
                           sizeof(remote_page_info_t));
    knl_securec_check(err);

    err = memcpy_s(shmem_page_addr, DEFAULT_PAGE_SIZE(session), ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(err);

    // tail lsn
    err = memcpy_s(page_tail_lsn_addr, sizeof(uint64), &page_tail_lsn, sizeof(uint64));
    knl_securec_check(err);
    
    ctrl_page_lsn = ctrl->page->lsn;
    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);
    OG_LOG_RUN_INF("[LBP-COPY-TO-GBP][%u-%u] check lsn, current page lsn: %llu, remote page lsn head: %llu, "
        "remote page lsn tail: %llu", ctrl->page_id.file, ctrl->page_id.page, ctrl_page_lsn,
        remote_head_lsn, remote_tail_lsn);

    // Release global Lock: drc_gbp_distribute_unlock(session, lock_ptr, page_req->page_id, LATCH_MODE_X);
    OG_LOG_RUN_INF("[LBP-COPY-TO-GBP][%u-%u]: Success to copy page to gbp", ctrl->page_id.file, ctrl->page_id.page);
    
    return OG_SUCCESS;
}
