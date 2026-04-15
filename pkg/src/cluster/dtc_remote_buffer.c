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
#include "pcr_heap.h"

#include "dtc_remote_lock.h"

static ub_rw_lock_t *g_ub_lock = NULL;
static ub_lock_config_t g_ub_lock_config = { 0 };
static ub_location_t g_ub_lock_creator = { 0 };

// page_info_t + page + end_lsn + bucket_t + buf_ctrl_t
#define REMOTE_BUF_PAGE_COST                                                       \
    (sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64) + \
     BUCKET_TIMES * sizeof(buf_bucket_t) + sizeof(buf_ctrl_t))

static inline uint64 drc_calc_buf_size(uint64 size)
{
    uint64 align_size = CM_CALC_ALIGN(size + SGA_BARRIER_SIZE, OG_MAX_ALIGN_SIZE_4K);
    return align_size;
}

static inline uint64 drc_calc_remote_data_region_size(remote_buf_context_t *buf_ctx)
{
    /* include max 4K head padding, same as srv_create_sga malloc slack */
    return OG_MAX_ALIGN_SIZE_4K +
        (uint64)buf_ctx->buf_set_count * g_dtc->profile.remote_data_buf_part_align_size;
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
    remote_sga->remote_buf_alloc_size = drc_calc_remote_data_region_size(buf_ctx);
    remote_sga->remote_pool_reserve_offset = remote_sga->remote_buf_alloc_size;
    return remote_sga->remote_buf_alloc_size;
}

static status_t drc_check_remote_lock_capacity(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint64 page_cost;
    uint64 capacity_per_set;
    uint64 total_page_count;
    uint64 lock_mem_needed;
    uint64 max_lock_count;

    if (!g_dtc->kernel->attr.enable_remote_distribute_lock) {
        remote_sga->remote_lock_alloc_size = 0;
        return OG_SUCCESS;
    }

    page_cost = REMOTE_BUF_PAGE_COST;
    if (page_cost == 0) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] invalid remote buf page cost 0");
        return OG_ERROR;
    }

    if (UB_RW_LOCK_SIZE == 0) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] invalid lock size 0");
        return OG_ERROR;
    }

    capacity_per_set = g_dtc->profile.remote_data_buf_part_size / page_cost;
    if (capacity_per_set == 0) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] remote data buf part size %llu is smaller than page cost %llu",
                       g_dtc->profile.remote_data_buf_part_size, page_cost);
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DTC_REMOTE_DATA_BUF_SIZE", (int64)page_cost);
        return OG_ERROR;
    }

    total_page_count = (uint64)buf_ctx->buf_set_count * capacity_per_set;
    lock_mem_needed = total_page_count * (uint64)UB_RW_LOCK_SIZE;
    max_lock_count = (uint64)DRC_DISK_LCK_SIZE / (uint64)UB_RW_LOCK_SIZE;

    if (lock_mem_needed > DRC_DISK_LCK_SIZE) {
        OG_LOG_RUN_ERR("[DRC-GBP-LOCK] remote lock memory %llu exceeds limit %llu, "
                       "remote_buf_page_cost %llu, total_page_count %llu, lock_size %u, max_lock_count %llu",
                       lock_mem_needed, (uint64)DRC_DISK_LCK_SIZE, page_cost, total_page_count,
                       (uint32)UB_RW_LOCK_SIZE, max_lock_count);
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "DTC_REMOTE_DATA_BUF_SIZE", (int64)DRC_DISK_LCK_SIZE);
        return OG_ERROR;
    }

    remote_sga->remote_lock_alloc_size = lock_mem_needed;
    OG_LOG_RUN_INF("[DRC-GBP-LOCK] remote_buf_alloc_size %llu, remote_buf_page_cost %llu, total_page_count %llu, "
                   "remote_lock_alloc_size %llu, lock_size %u, max_lock_count %llu",
                   remote_sga->remote_buf_alloc_size, page_cost, total_page_count, remote_sga->remote_lock_alloc_size,
                   (uint32)UB_RW_LOCK_SIZE, max_lock_count);

    return OG_SUCCESS;
}

static status_t drc_check_remote_pool_layout(remote_sga_t *remote_sga)
{
    uint64 layout_end = drc_get_node_flush_lsn_offset(remote_sga) + DRC_NODE_FLUSH_LSN_SIZE;

    if (layout_end > remote_sga->remote_total_pool_size) {
        OG_LOG_RUN_ERR("[DRC-GBP] remote pool layout %llu exceeds total pool size %llu, "
                       "data_region %llu, que_size %llu, lock_alloc_size %llu, node_flush_lsn_size %llu",
                       layout_end, remote_sga->remote_total_pool_size, remote_sga->remote_buf_alloc_size,
                       (uint64)DRC_DIST_QUE_SIZE, remote_sga->remote_lock_alloc_size,
                       (uint64)DRC_NODE_FLUSH_LSN_SIZE);
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "DTC_REMOTE_DATA_BUF_SIZE", (int64)remote_sga->remote_total_pool_size);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t dtc_mmap_remote_data_buf(remote_sga_t *remote_sga, uint32 node_id)
{
    int ret = OG_ERROR;
    void *start = (void *)(node_id == 0 ? DRC_BASE_ADDR_0 : DRC_BASE_ADDR_1);
    remote_sga->remote_total_pool_size = align_to_128m(g_dtc->profile.remote_sga_size);
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
    remote_sga->remote_total_pool_size = align_to_128m(g_dtc->profile.remote_sga_size);
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

static status_t drc_set_remote_buffer(char **buf, char *remote_buf_addr, uint64 pool_size, uint64 size,
    uint64 *offset)
{
    char *barrier = NULL;
    uint64 next_offset = *offset + srv_calc_buf_size(size);

    if (next_offset > pool_size) {
        OG_LOG_RUN_ERR("[DRC-GBP] remote buffer allocation exceeds pool size %llu, need %llu, offset %llu, size %llu",
                       pool_size, next_offset, *offset, size);
        return OG_ERROR;
    }

    *buf = remote_buf_addr + *offset;
    barrier = remote_buf_addr + *offset + size;
    *offset = next_offset;

    MEMS_RETURN_IFERR(memset_s(barrier, SGA_BARRIER_SIZE, 0xFF, SGA_BARRIER_SIZE));
    return OG_SUCCESS;
}

static status_t drc_set_data_buf(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 node_id = g_instance->kernel.id;
    uint32 data_buf_part_size = g_dtc->profile.remote_data_buf_part_size;
    char *temp_buf = NULL;
    uint64 offset = (OG_MAX_ALIGN_SIZE_4K - ((uint64)remote_sga->remote_buf_addr[node_id]) % OG_MAX_ALIGN_SIZE_4K);
    status_t ret;

    /* * allocate each data buffer part */
    ret = drc_set_remote_buffer(&remote_sga->data_buf, remote_sga->remote_buf_addr[node_id],
                                remote_sga->remote_total_pool_size, data_buf_part_size, &offset);
    if (ret != OG_SUCCESS) {
        return ret;
    }

    for (uint32 i = 1; i < buf_ctx->buf_set_count; i++) {
        ret = drc_set_remote_buffer(&temp_buf, remote_sga->remote_buf_addr[node_id],
                                    remote_sga->remote_total_pool_size, data_buf_part_size, &offset);
        if (ret != OG_SUCCESS) {
            return ret;
        }
    }
    if (offset > remote_sga->remote_buf_alloc_size) {
        OG_LOG_RUN_ERR("[DRC-GBP] remote data buf actual size %llu exceeds reserved data region %llu",
                       offset, remote_sga->remote_buf_alloc_size);
        return OG_ERROR;
    }

    return OG_SUCCESS;
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
        drc_init_remote_lock(&g_ub_lock, &g_ub_lock_config, &g_ub_lock_creator);
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

        for (uint32 j = 0; j < set->capacity; j++) {
            char *page_addr = set->page_buf + j * page_size;
            remote_page_info_t *page_info = (remote_page_info_t *)page_addr;
            gbp_ckpt_set_state(page_info, 0);
            if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
                // each page corresponds to a lock in the lock buffer.
                uint64 lock_match_start = (uint64)((char *)g_ub_lock + i * set->capacity * UB_RW_LOCK_SIZE);
                page_info->lock_ptr = (uint64)((char *)lock_match_start + j * UB_RW_LOCK_SIZE);
                ub_rw_lock_create((ub_rw_lock_t *)(page_info->lock_ptr), &g_ub_lock_config, &g_ub_lock_creator);
                OG_LOG_RUN_INF("[DRC-GBP-LOCK] page %u, addr %p, lock addr: %p", j, (void *)page_addr,
                               (void *)page_info->lock_ptr);
            }
        }

        knl_reset_large_memory((char *)set->buckets, (uint64)sizeof(buf_bucket_t) * set->bucket_num);
        buf_init_list(set);
    }

    cm_init_thread_lock(&buf_ctx->buf_mutex);

    return;
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
    ret = drc_check_remote_lock_capacity(&ogx->remote_sga, &ogx->buf_ctx);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC]remote lock capacity check fail, return error:%u", ret);
        return ret;
    }
    ret = drc_check_remote_pool_layout(&ogx->remote_sga);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC]remote pool layout check fail, return error:%u", ret);
        return ret;
    }
    ret = drc_set_data_buf(&ogx->remote_sga, &ogx->buf_ctx);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC]set remote data buf fail, return error:%u", ret);
        return ret;
    }
    drc_init_remote_buf_struct(&ogx->remote_sga, &ogx->buf_ctx);

    uint32 node_id = g_instance->kernel.id;
    uint64 node_flush_lsn_offset = drc_get_node_flush_lsn_offset(&ogx->remote_sga);
    ogx->remote_sga.node_flush_lsn = ogx->remote_sga.remote_buf_addr[node_id] + node_flush_lsn_offset;
    ogx->remote_sga.remote_pool_reserve_offset = node_flush_lsn_offset + DRC_NODE_FLUSH_LSN_SIZE;

    if (ogx->remote_sga.node_flush_lsn != NULL) {
        knl_reset_large_memory(ogx->remote_sga.node_flush_lsn, sizeof(atomic_t) * 2);
        uint32 self_id = g_instance->kernel.id;
        uint64 my_timeline_id = g_instance->kernel.db.ctrl.core.instance_timeline_id[self_id];
        drc_set_node_timeline_id(&ogx->remote_sga, my_timeline_id);
    }
    return OG_SUCCESS;
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
}

#define GBP_READONLY_WAIT_MAX_TIMES 1000
#define GBP_RELOAD_WAIT_MAX_TIMES   10000

static buf_bucket_t *dtc_buf_get_bucket(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_set_t *set = &session->kernel->buf_ctx.buf_set[ctrl->buf_pool_id];

    return BUF_GET_BUCKET(set, ctrl->bucket_id);
}

static bool32 dtc_buf_gbp_reload_try_begin(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_bucket_t *bucket = dtc_buf_get_bucket(session, ctrl);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    if (ctrl->gbp_reload_in_progress) {
        cm_spin_unlock(&bucket->lock);
        return OG_FALSE;
    }
    ctrl->gbp_reload_in_progress = 1;
    ctrl->gbp_reload_sid = session->id;
    cm_spin_unlock(&bucket->lock);
    return OG_TRUE;
}

typedef enum {
    GBP_RELOAD_DECIDE_LEADER = 0,
    GBP_RELOAD_DECIDE_NONE,
    GBP_RELOAD_DECIDE_NEED_WAIT,
} gbp_reload_decide_t;

status_t dtc_buf_gbp_wait_reload_done(knl_session_t *session, buf_ctrl_t *ctrl);

/*
 * Under bucket lock: compare remote/local LSN and set reload flag atomically,
 * so no other session can pass reload wait between LSN check and try_begin.
 */
static gbp_reload_decide_t dtc_buf_gbp_reload_decide(knl_session_t *session, buf_ctrl_t *ctrl,
    uint64 remote_head_lsn, bool32 *is_load)
{
    buf_bucket_t *bucket = dtc_buf_get_bucket(session, ctrl);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    if (ctrl->gbp_reload_in_progress) {
        if (ctrl->gbp_reload_sid == session->id) {
            *is_load = OG_TRUE;
            cm_spin_unlock(&bucket->lock);
            return GBP_RELOAD_DECIDE_LEADER;
        }
        cm_spin_unlock(&bucket->lock);
        return GBP_RELOAD_DECIDE_NEED_WAIT;
    }

    if (remote_head_lsn > ctrl->page->lsn) {
        *is_load = OG_TRUE;
        ctrl->gbp_reload_in_progress = 1;
        ctrl->gbp_reload_sid = session->id;
        cm_spin_unlock(&bucket->lock);
        return GBP_RELOAD_DECIDE_LEADER;
    }

    *is_load = OG_FALSE;
    cm_spin_unlock(&bucket->lock);
    return GBP_RELOAD_DECIDE_NONE;
}

static status_t dtc_buf_gbp_reload_decide_or_wait(knl_session_t *session, buf_ctrl_t *ctrl,
    remote_page_info_t *shmem_page_meta, bool32 *is_load)
{
    status_t ret;

    for (;;) {
        uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
        uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);
        gbp_reload_decide_t decide;

        if (remote_head_lsn != remote_tail_lsn) {
            OG_LOG_RUN_ERR("[DTC-GBP-CHECK][%u-%u]: head/tail lsn mismatch, head lsn(%llu), tail lsn(%llu)",
                ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, remote_tail_lsn);
            return OG_ERROR;
        }

        decide = dtc_buf_gbp_reload_decide(session, ctrl, remote_head_lsn, is_load);
        if (decide != GBP_RELOAD_DECIDE_NEED_WAIT) {
            return OG_SUCCESS;
        }

        ret = dtc_buf_gbp_wait_reload_done(session, ctrl);
        if (ret != OG_SUCCESS) {
            return ret;
        }
    }
}

static void dtc_buf_gbp_reload_end(knl_session_t *session, buf_ctrl_t *ctrl, bool32 success)
{
    buf_bucket_t *bucket = dtc_buf_get_bucket(session, ctrl);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    if (success) {
        ctrl->gbp_reload_generation++;
    }
    ctrl->gbp_reload_in_progress = 0;
    ctrl->gbp_reload_sid = OG_INVALID_ID16;
    cm_spin_unlock(&bucket->lock);
}

status_t dtc_buf_gbp_wait_reload_done(knl_session_t *session, buf_ctrl_t *ctrl)
{
    uint32 times = 0;

    if (!ctrl->gbp_reload_in_progress || dtc_buf_gbp_reload_owned_by_session(session, ctrl)) {
        return OG_SUCCESS;
    }

    while (ctrl->gbp_reload_in_progress) {
        times++;
        /* log at most once per ~500 spin/sleep cycles; skip times==1 to avoid storm under concurrency */
        if (times % 500 == 0) {
            OG_LOG_DEBUG_INF("[DTC-GBP-CHECK-WAIT-RELOAD][%u-%u]: waiting reload, times %u, gen %u, tid:%d",
                ctrl->page_id.file, ctrl->page_id.page, times, ctrl->gbp_reload_generation,
                (int32)cm_get_current_thread_id());
        }
        if (SECUREC_UNLIKELY(times > GBP_RELOAD_WAIT_MAX_TIMES)) {
            OG_LOG_RUN_ERR("[DTC-GBP-CHECK-WAIT-RELOAD][%u-%u]: wait reload timeout, gen %u, tid:%d",
                ctrl->page_id.file, ctrl->page_id.page, ctrl->gbp_reload_generation,
                (int32)cm_get_current_thread_id());
            return OG_ERROR;
        }
        if (times % 50 == 0) {
            cm_sleep(1);
        } else {
            cm_spin_sleep();
        }
    }

    return OG_SUCCESS;
}

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

static inline status_t dcs_copy_page_to_temp(knl_session_t *session, buf_ctrl_t *ctrl, char *temp_page)
{
    char *page = (char *)ctrl->shmem_page_addr;
    uint32 page_size = DEFAULT_PAGE_SIZE(session);
    errno_t err;

    if (temp_page == NULL || page == NULL || page_size == 0) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] invalid copy args, temp_page=%p, shmem_page_addr=%p, page_size=%u",
            ctrl->page_id.file, ctrl->page_id.page, temp_page, page, page_size);
        return OG_ERROR;
    }

    err = memcpy_s(temp_page, page_size, page, page_size);
    if (err != EOK) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] memcpy_s from shmem failed, err=%d, temp_page=%p, shmem_page_addr=%p",
            ctrl->page_id.file, ctrl->page_id.page, (int32)err, temp_page, page);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t dtc_buf_commit_temp_page(knl_session_t *session, buf_ctrl_t *ctrl, char *temp_page)
{
    uint32 page_size = DEFAULT_PAGE_SIZE(session);
    buf_bucket_t *bucket = dtc_buf_get_bucket(session, ctrl);
    errno_t err;

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    err = memcpy_s(ctrl->page, page_size, temp_page, page_size);
    knl_securec_check(err);
    cm_spin_unlock(&bucket->lock);

    return OG_SUCCESS;
}

/*
 * Copy page from GBP shmem into a temp buffer first; validate PCN on temp page,
 * then commit to ctrl->page atomically under bucket lock.
 */
static status_t dtc_buf_copy_from_gbp_shmem_inner(knl_session_t *session, buf_ctrl_t *ctrl, uint64 lock_offset)
{
    ub_rw_lock_t *lock = (ub_rw_lock_t *)(uintptr_t)lock_offset;
    status_t ret;
    uint32 page_size = DEFAULT_PAGE_SIZE(session);
    page_head_t *temp_page = (page_head_t *)cm_push(session->stack, page_size);

    if (temp_page == NULL) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] session stack overflow while copying from gbp shmem",
            ctrl->page_id.file, ctrl->page_id.page);
        return OG_ERROR;
    }

    ret = dcs_copy_page_to_temp(session, ctrl, (char *)temp_page);
    if (ret != OG_SUCCESS) {
        return ret;
    }
    if (CHECK_PAGE_PCN(temp_page)) {
        return dtc_buf_commit_temp_page(session, ctrl, (char *)temp_page);
    }

    if (!ub_rw_lock_get_readonly(lock)) {
        OG_LOG_RUN_WAR("[DTC-GBP-COPY][%u-%u] page pcn mismatch without readonly, head pcn:%u, tail pcn:%u",
            ctrl->page_id.file, ctrl->page_id.page, (uint32)temp_page->pcn, (uint32)PAGE_TAIL(temp_page)->pcn);
        return OG_ERROR;
    }

    ret = dtc_buf_wait_readonly_clear(lock, ctrl->page_id);
    if (ret != OG_SUCCESS) {
        return ret;
    }

    ret = dcs_copy_page_to_temp(session, ctrl, (char *)temp_page);
    if (ret != OG_SUCCESS) {
        return ret;
    }
    if (!CHECK_PAGE_PCN(temp_page)) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u] page pcn still mismatch after readonly clear, head pcn:%u, tail pcn:%u",
            ctrl->page_id.file, ctrl->page_id.page, (uint32)temp_page->pcn, (uint32)PAGE_TAIL(temp_page)->pcn);
        return OG_ERROR;
    }

    return dtc_buf_commit_temp_page(session, ctrl, (char *)temp_page);
}

static status_t dtc_buf_copy_from_gbp_shmem(knl_session_t *session, buf_ctrl_t *ctrl, uint64 lock_offset)
{
    status_t ret;

    CM_SAVE_STACK(session->stack);
    ret = dtc_buf_copy_from_gbp_shmem_inner(session, ctrl, lock_offset);
    CM_RESTORE_STACK(session->stack);

    return ret;
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

    // LSN Check: Ensure the requester doesn't have a "newer" LSN than the gbp owner
    bool32 readonly = ub_rw_lock_get_readonly((ub_rw_lock_t *)(uintptr_t)lock_offset);
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

    /*
     * Atomically compare remote/local LSN and mark gbp_reload_in_progress under bucket lock.
     * Followers wait and retry until leader finishes, eliminating TOCTOU between reload wait and try_begin.
     */
    ret = dtc_buf_gbp_reload_decide_or_wait(session, ctrl, shmem_page_meta, is_load);
    if (ret != OG_SUCCESS) {
        if (mode == LATCH_MODE_X) {
            dtc_buf_gbp_abort_x_after_upgrade(session, ctrl, lock_offset, x_already_held, did_s_upgrade, s_upgraded,
                s_upgraded_count);
        } else if (!skip_shmem_s_lock) {
            (void)drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
        }
        return ret;
    }
    remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    OG_LOG_DEBUG_INF(
        "[DTC-GBP-CHECK][%u-%u]: check local page success, remote page lsn(%llu), local page lsn(%llu), mode: %u, "
        "skip_shmem_s_lock %d, is_load %d, readonly %d, reload %d, gen %u, tid:%d",
        ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn, mode,
        skip_shmem_s_lock, *is_load, readonly, (int32)ctrl->gbp_reload_in_progress,
        ctrl->gbp_reload_generation, (int32)cm_get_current_thread_id());

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
    uint64 remote_head_lsn = 0;

    uint8 gbp_owner_id = shmem_page_meta->claimed_owner;

    if (gbp_owner_id != DCS_SELF_INSTID(session)) {
        if (remote_sga->map_success[gbp_owner_id] != OG_TRUE) {
            int ret = dtc_mmap_remote_data_buf(remote_sga, gbp_owner_id);
            if (ret != UBSM_OK) {
                OG_LOG_RUN_ERR("[DRC]mmap remote data buf on node %u failed, ret: %d", gbp_owner_id, ret);
            }
        }
    }

    if (dtc_buf_gbp_reload_owned_by_session(session, ctrl)) {
        /* leader: check 里 is_load=1 时已 try_begin */
    } else if (ctrl->gbp_reload_in_progress) {
        /* follower: 等 leader 完成 reload */
        ret = dtc_buf_gbp_wait_reload_done(session, ctrl);
        if (ret != OG_SUCCESS) {
            (void)dtc_buf_gbp_unhold(session, ctrl, mode);
            return ret;
        }

        remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
        if (remote_head_lsn <= ctrl->page->lsn && CHECK_PAGE_PCN(ctrl->page)) {
            OG_LOG_DEBUG_INF("[DTC-GBP-RELOAD-END][%u-%u]: follower skip reload, gen %u, tid:%d",
                ctrl->page_id.file, ctrl->page_id.page, ctrl->gbp_reload_generation,
                (int32)cm_get_current_thread_id());
            return OG_SUCCESS;
        }
        /* leader 失败或页仍过期，尝试接任 leader */
        if (!dtc_buf_gbp_reload_try_begin(session, ctrl)) {
            OG_LOG_RUN_ERR("[DTC-GBP-RELOAD][%u-%u]: failed to take over reload, tid:%d",
                ctrl->page_id.file, ctrl->page_id.page, (int32)cm_get_current_thread_id());
            (void)dtc_buf_gbp_unhold(session, ctrl, mode);
            return OG_ERROR;
        }
    } else if (!dtc_buf_gbp_reload_try_begin(session, ctrl)) {
        /* BUF_NEED_LOAD_FROM_GBP 等未经 check try_begin 的路径 */
        OG_LOG_RUN_ERR("[DTC-GBP-RELOAD][%u-%u]: failed to begin reload, tid:%d",
            ctrl->page_id.file, ctrl->page_id.page, (int32)cm_get_current_thread_id());
        (void)dtc_buf_gbp_unhold(session, ctrl, mode);
        return OG_ERROR;
    }

    // OG_LOG_DEBUG_INF("[DTC-GBP-RELOAD-BEGIN][%u-%u]: remote lsn(%llu), local lsn(%llu), gen %u, tid:%d",
    //     ctrl->page_id.file, ctrl->page_id.page,
    //     *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN), ctrl->page->lsn,
    //     ctrl->gbp_reload_generation, (int32)cm_get_current_thread_id());

    ret = dtc_buf_copy_from_gbp_shmem(session, ctrl, lock_offset);
    if (ret != OG_SUCCESS) {
        dtc_buf_gbp_reload_end(session, ctrl, OG_FALSE);
        (void)dtc_buf_gbp_unhold(session, ctrl, mode);
        OG_LOG_RUN_WAR("[BUFFER-GBP] copy_from_gbp_shmem fail: local buffer file id %u, page id %u. "
            "remote file %u, remote page %u",
            shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page);
        return OG_ERROR;
    }

    heap_page_t *heap_page = (heap_page_t *)ctrl->page;
    // OG_LOG_DEBUG_INF("[DTC_HEAP_COPY_GBP] page[%u-%u], oid: %d, page addr: %p, page_lsn %llu, page addr by meta: %p, "
    //                "meta addr: %p.", AS_PAGID(heap_page->head.id).file, AS_PAGID(heap_page->head.id).page,
    //                heap_page->oid, ctrl->shmem_page_addr, heap_page->head.lsn,

    // check page identifier of remote buf meta with remote page
    if (shmem_page_meta->file_id != AS_PAGID(heap_page->head.id).file ||
        shmem_page_meta->page_id != AS_PAGID(heap_page->head.id).page) {
        datafile_t *df = NULL;
        df = DATAFILE_GET(session, ctrl->page_id.file);
        dtc_buf_gbp_reload_end(session, ctrl, OG_FALSE);
        // if mode is X, no need to unlock, unlock after write finished
        ret = dtc_buf_gbp_unhold(session, ctrl, mode);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[BUFFER-GBP][%u-%u] failed to unlock shmem page.", ctrl->page_id.file, ctrl->page_id.page);
            return ret;
        }
        OG_LOG_RUN_ERR("[BUFFER-GBP] page in gbp %u-%u is incorret: local buffer file id %u, page id %u, file name %s",
                       shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page,
                       df->ctrl->name);
        return OG_ERROR;
    }
    remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);

    if (remote_head_lsn != remote_tail_lsn) {
        OG_LOG_RUN_ERR("[DTC-GBP-COPY][%u-%u]: head/tail lsn mismatch, head lsn(%llu), tail lsn(%llu), pcn: %u, "
            "tail pcn: %u", ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, remote_tail_lsn,
            (ctrl->page)->pcn, PAGE_TAIL(ctrl->page)->pcn);
        dtc_buf_gbp_reload_end(session, ctrl, OG_FALSE);
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

    dtc_buf_gbp_reload_end(session, ctrl, OG_TRUE);
    OG_LOG_DEBUG_INF("[DTC-GBP-RELOAD-END][%u-%u]: reload success, gen %u, pcn_ok 1, tid:%d",
        ctrl->page_id.file, ctrl->page_id.page, ctrl->gbp_reload_generation,
        (int32)cm_get_current_thread_id());
    // if (((heap_page_t *)ctrl->page)->head.type == PAGE_TYPE_PCRH_DATA) {
    // }

    return OG_SUCCESS;
}

status_t dtc_buf_try_store_to_gbp(knl_session_t *session, buf_ctrl_t *ctrl, uint64 curr_lsn)
{
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    page_head_t *shmem_page_addr = ctrl->shmem_page_addr;
    uint8 curr_node_id = DCS_SELF_INSTID(session);

    // to do: check local ctrl page lsn and remote page lsn
    uint64 remote_page_lsn = curr_lsn;

    // Has acquired global lock when copy from gbp -> local
    remote_page_info_t new_shmem_page_meta = {0};
    new_shmem_page_meta.lock_ptr = shmem_page_meta->lock_ptr;
    new_shmem_page_meta.head_lsn = remote_page_lsn;
    new_shmem_page_meta.file_id = ctrl->page_id.file;
    new_shmem_page_meta.page_id = ctrl->page_id.page;
    new_shmem_page_meta.claimed_owner = shmem_page_meta->claimed_owner;
    new_shmem_page_meta.touch_number = shmem_page_meta->touch_number + 1;
    new_shmem_page_meta.ref_num = 0;
    new_shmem_page_meta.xlog_owner_node = curr_node_id;
    remote_page_info_set_timeline_id(&new_shmem_page_meta,
                                     session->kernel->db.ctrl.core.instance_timeline_id[curr_node_id]);

    char *page_tail_lsn_addr = (char *)shmem_page_meta + OFFSET_TAIL_LSN;
    uint64 page_tail_lsn = remote_page_lsn;

    errno_t err = memcpy_s(shmem_page_meta, offsetof(remote_page_info_t, ckpt_flush_state), &new_shmem_page_meta,
                           offsetof(remote_page_info_t, ckpt_flush_state));
    knl_securec_check(err);

    err = memcpy_s(shmem_page_addr, DEFAULT_PAGE_SIZE(session), ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(err);

    // tail lsn
    err = memcpy_s(page_tail_lsn_addr, sizeof(uint64), &page_tail_lsn, sizeof(uint64));
    knl_securec_check(err);

#ifdef DB_DEBUG_VERSION
    uint64 ctrl_page_lsn = ctrl->page->lsn;
    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);
    // Release global Lock: drc_gbp_distribute_unlock(session, lock_ptr, page_req->page_id, LATCH_MODE_X);
    OG_LOG_DEBUG_INF("[OG_LOG_DEBUG_INF][%u-%u]: Success to copy page to gbp, current page lsn: %llu, "
        "remote page lsn head: %llu, remote page lsn tail: %llu", ctrl->page_id.file, ctrl->page_id.page,
        ctrl_page_lsn, remote_head_lsn, remote_tail_lsn);
#endif
    return OG_SUCCESS;
}
