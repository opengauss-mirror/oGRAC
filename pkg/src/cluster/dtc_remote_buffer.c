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
#include "cs_ub.h"
#include "srv_sga.h"
#include "cm_ubs_mem.h"
#include "knl_common.h"
#include "knl_buffer.h"

#include "ub_dist_comm_queue.h"
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

    int ret = ub_create_shm_region(node_id, g_mes.profile.inst_count);
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
    drc_set_data_buf(&ogx->remote_sga, &ogx->buf_ctx);
    drc_init_remote_buf_struct(&ogx->remote_sga, &ogx->buf_ctx);
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

static inline status_t dcs_copy_page_from_shmem(knl_session_t *session, buf_ctrl_t *ctrl)
{
    char *page = (char *)ctrl->shmem_page_addr;
    errno_t err = memcpy_s(ctrl->page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(err);

    return OG_SUCCESS;
}

status_t dtc_buf_check_local_page(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, bool32 *is_load)
{
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    uint64 lock_offset = shmem_page_meta->lock_ptr;
    status_t ret;

    ctrl->gbp_lock_mode = mode;

    // to do, if mode is S, not lock; if mode is X, need lock
    if (g_dtc->kernel->attr.enable_remote_distribute_lock) {
        // Acquire remote global lock
        ret = drc_gbp_distribute_lock(session, lock_offset, ctrl->page_id, mode);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[DCS-GBP][%u-%u] failed to lock shmem page, return", ctrl->page_id.file,
                           ctrl->page_id.page);
            return ret;
        }
    }

    // check page identifier of remote buf meta with ctrl->page_id
    if (shmem_page_meta->file_id != ctrl->page_id.file || shmem_page_meta->page_id != ctrl->page_id.page) {
        datafile_t *df = NULL;
        df = DATAFILE_GET(session, ctrl->page_id.file);
        OG_LOG_RUN_ERR("[BUFFER-GBP] page in gbp %u-%u is incorret: local buffer file id %u, page id %u, file name %s",
                       shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page,
                       df->ctrl->name);
        // to do: unlock remote mate
        return OG_ERROR;
    }

    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    uint64 remote_tail_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_TAIL_LSN);

    // to do: check remote_head_lsn, remote_tail_lsn is max and no set, need to set
    if (remote_head_lsn != remote_tail_lsn) {
        OG_LOG_RUN_WAR("[DTC-GBP-COPY][%llu-%llu] failed to check lsn, return", remote_head_lsn, remote_tail_lsn);
        // TODO: when we find the page is invalid, unlock remote mate and return error
    }

    // LSN Check: Ensure the requester doesn't have a "newer" LSN than the gbp owner
    if (remote_head_lsn < ctrl->page->lsn) {
        OG_LOG_RUN_ERR("[[DTC-GBP-COPY][%u-%u]: lsn check failed, remote page lsn(%llu), ctrl->page->lsn(%llu)",
            ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn);
        // Release and free global lock
        ret = drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
        ctrl->gbp_lock_mode = DRC_LOCK_NULL;
        if (ret != OG_SUCCESS) {
            return ret;
        }
        return OG_ERROR;
    }
   
    // there is occurs that page in gbp update, local ctrl->page is old so need to load from gbp again
    if (remote_head_lsn > ctrl->page->lsn) {
        *is_load = OG_TRUE;
        OG_LOG_RUN_WAR(
            "[[DTC-LOCAL-PAGE-CHECK][%u-%u]: check local page, remote page lsn(%llu), local page lsn(%llu)",
            ctrl->page_id.file, ctrl->page_id.page, remote_head_lsn, ctrl->page->lsn);
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

    dcs_copy_page_from_shmem(session, ctrl);

    heap_page_t *heap_page = (heap_page_t *)ctrl->page;
    OG_LOG_RUN_WAR("[DTC_HEAP_COPY_GBP] page[%u-%u], oid: %d, page addr: %p, page_lsn %llu, page addr by meta: %p",
                   AS_PAGID(heap_page->head.id).file, AS_PAGID(heap_page->head.id).page, heap_page->oid,
                   ctrl->shmem_page_addr, heap_page->head.lsn, GET_PAGE_ADDR_IN_GBP((char *)shmem_page_meta));

    // check page identifier of remote buf meta with remote page
    if (shmem_page_meta->file_id != AS_PAGID(heap_page->head.id).file ||
        shmem_page_meta->page_id != AS_PAGID(heap_page->head.id).page) {
        datafile_t *df = NULL;
        df = DATAFILE_GET(session, ctrl->page_id.file);
        OG_LOG_RUN_WAR("[BUFFER-GBP] page in gbp %u-%u is incorret: local buffer file id %u, page id %u, file name %s",
                       shmem_page_meta->file_id, shmem_page_meta->page_id, ctrl->page_id.file, ctrl->page_id.page,
                       df->ctrl->name);
        // if mode is X, no need to unlock, unlock after write finished
        ret = drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, mode);
        ctrl->gbp_lock_mode = DRC_LOCK_NULL;
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DCS][%u-%u] failed to unlock shmem page, return", ctrl->page_id.file, ctrl->page_id.page);
            return ret;
        }
        return OG_ERROR;
    }

    uint64 remote_head_lsn = *(uint64 *)((uint8 *)shmem_page_meta + OFFSET_HEAD_LSN);
    // to do: dtc_update_lsn(session, remote_head_lsn), need to think how to set.
    // to do：dtc_update_scn(session, ctrl->scn); need to think how to set.
    dtc_update_lsn(session, remote_head_lsn);
    // to do: check ctrl->lock_mode how to set
    ctrl->lock_mode = mode;
    // ctrl->load_status need to set BUF_IS_LOADED, because commit need to check this status
    ctrl->load_status = (uint8)BUF_IS_LOADED;

    return OG_SUCCESS;
}

status_t dtc_buf_try_store_to_gbp(knl_session_t *session, uint64 curr_lsn)
{
    buf_ctrl_t *ctrl = session->curr_page_ctrl;
    remote_page_info_t *shmem_page_meta = ctrl->shmem_page_meta;
    page_head_t *shmem_page_addr = ctrl->shmem_page_addr;
    uint64 lock_offset = shmem_page_meta->lock_ptr;
    status_t ret;
    uint8 curr_node_id = DCS_SELF_INSTID(session);

    // to do: check local ctrl page lsn and remote page lsn
    uint64 ctrl_page_lsn = ctrl->page->lsn;
    uint64 remote_page_lsn = curr_lsn;
    OG_LOG_RUN_WAR("[LBP-COPY-TO-GBP][%llu-%llu] check lsn", ctrl_page_lsn, remote_page_lsn);

    // Has acquired global lock  when copy from gbp ->local
    remote_page_info_t new_shmem_page_meta;
    new_shmem_page_meta.lock_ptr = ctrl->shmem_page_meta->lock_ptr;
    new_shmem_page_meta.head_lsn = remote_page_lsn;
    new_shmem_page_meta.file_id = ctrl->page_id.file;
    new_shmem_page_meta.page_id = ctrl->page_id.page;
    new_shmem_page_meta.claimed_owner = ctrl->shmem_page_meta->claimed_owner;
    new_shmem_page_meta.touch_number += 1;
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

    // Release global Lock: drc_gbp_distribute_unlock(session, lock_ptr, page_req->page_id, LATCH_MODE_X);
    OG_LOG_DEBUG_INF("[LBP-COPY-TO-GBP][%u-%u]: Success to copy page to gbp", ctrl->page_id.file, ctrl->page_id.page);
    
    ret = drc_gbp_distribute_unlock(session, lock_offset, ctrl->page_id, ctrl->gbp_lock_mode);
    ctrl->gbp_lock_mode = DRC_LOCK_NULL;
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DCS][%u-%u] failed to unlock shmem page, return", ctrl->page_id.file, ctrl->page_id.page);
        return ret;
    }
    
    return OG_SUCCESS;
}
