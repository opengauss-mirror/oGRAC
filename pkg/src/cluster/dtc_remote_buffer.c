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
#include "knl_cluster_module.h"
#include "cm_defs.h"
#include "dtc_drc.h"
#include "dtc_context.h"
#include "dtc_drc_stat.h"
#include "cm_malloc.h"
#include "cm_date.h"
#include "cs_ub.h"
#include "srv_sga.h"
#include "cm_ubs_mem.h"
#include "knl_common.h"
#include "knl_buffer.h"


#define REMOTE_BUF_PAGE_COST (sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64) + \
                BUCKET_TIMES * sizeof(buf_bucket_t) + sizeof(buf_ctrl_t))  //page_info_t + page + end_lsn + bucket_t + buf_ctrl_t

static inline uint64 drc_calc_buf_size(uint64 size)
{
    uint64 align_size = CM_CALC_ALIGN(size + SGA_BARRIER_SIZE, OG_MAX_ALIGN_SIZE_4K);
    return align_size;
}

uint64 drc_calc_remote_data_buf_size(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    /*adjust buf_ctx_count to match the data_buf_size */
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
    remote_sga->remote_buf_alloc_size = ALIGN_TO_4M(g_dtc->profile.remote_data_buf_part_align_size * buf_ctx->buf_set_count);
    return remote_sga->remote_buf_alloc_size;
}

status_t dtc_mmap_remote_data_buf(remote_sga_t *remote_sga, uint32 node_id)
{
    int ret = OG_ERROR;
    void *start = (void *)DRC_REMOTE_BUF_START_ADDR;
    uint64 data_buf_size = remote_sga->remote_buf_alloc_size;
    void *start_temp = start + node_id * data_buf_size;
    char data_buf_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    ret = sprintf_s(data_buf_name, sizeof(data_buf_name), "data_buf_part_%d", node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] sprintf remote data buf name fail,return error:%d", ret);
        return ret;
    }

    if (remote_sga->map_success[node_id] == OG_TRUE) {
        OG_LOG_RUN_WAR("[DRC] remote data buf part %d has been mapped, skip.", node_id);
        return OG_SUCCESS;
    }

    ret = ubsmem_shmem_map(start_temp, data_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
        data_buf_name, 0, (void **)&(remote_sga->remote_buf_addr[node_id]));
    if (ret != EOK) {
        OG_LOG_RUN_ERR("[DRC] Failed to map data buffer %s on node_id %u, return error:%d", data_buf_name, node_id, ret);
        return ret;
    }

    remote_sga->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[DRC] Successfully mapped data buffer %s on node_id %u, addr: %p", data_buf_name, node_id, remote_sga->remote_buf_addr[node_id]);
    return OG_SUCCESS;
}

status_t drc_alloc_mmap_remote_buffer_pool(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 node_id = g_instance->kernel.id;
    uint64 remote_buf_size = drc_calc_remote_data_buf_size(remote_sga, buf_ctx);    

    /* NOTICE: for demo test, we set inst_count = 2. then the single node test or multi nodes test can use UB shm. */
    g_mes.profile.inst_count = 2;

    int ret = ub_create_shm_region(node_id, g_mes.profile.inst_count);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] drc create sgm region fail, return error:%d", ret);
        return ret;
    }

    char data_buf_name[MAX_SHM_NAME_LENGTH] = {0};
    ret = sprintf_s(data_buf_name, sizeof(data_buf_name), "data_buf_part_%d", node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] sprintf remote data buf name fail,return error:%d", ret);
        return ret;
    }

    char region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    ret = sprintf_s(region_name, sizeof(region_name), "shm_pool_%d", node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[DRC] sprintf remote data buf region name fail,return error:%d", ret);
        return ret;
    }

    ret = ubsmem_shmem_allocate(region_name, data_buf_name, remote_buf_size, 0600, UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE);
    if (ret == UBSM_ERR_ALREADY_EXIST) {
        OG_LOG_RUN_WAR("[DRC]data buffer %s already exist, ret: %d", data_buf_name, ret);
    } else if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[DRC]data buffer %s allocate fail, ret: %d", data_buf_name, ret);
        return ret;
    }

    //after allocate remote data buf, map the buf on self node.
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

void drc_init_remote_buf_struct(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    uint32 page_size = sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size + sizeof(uint64);

    buf_set_t *set = NULL;
    uint64 offset;

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        set = &buf_ctx->buf_set[i];
        set->lock = 0;
        set->size = g_dtc->profile.remote_data_buf_part_size;
        set->addr = remote_sga->data_buf + i * g_dtc->profile.remote_data_buf_part_align_size;  //start addr of each buf_set in UB shm.
        cm_init_cond(&set->set_cond);
        /* set->size <= 32T, BUF_PAGE_COST >= 8360, set->capacity cannot overflow */
        set->capacity = (uint32)(set->size / REMOTE_BUF_PAGE_COST);
        set->hwm = 0;
        set->page_buf = set->addr;   //in UB shm, page_buf includes remote_page_info_t, page and tail_lsn
        offset = (uint64)page_size * set->capacity;
        set->ctrls = (buf_ctrl_t *)(set->addr + offset);
        set->buckets = (buf_bucket_t *)(set->addr + offset);
        set->bucket_num = BUCKET_TIMES * set->capacity;

        knl_reset_large_memory((char *)set->buckets, (uint64)sizeof(buf_bucket_t) * set->bucket_num);
        buf_init_list(set);
    }
    
    cm_init_thread_lock(&buf_ctx->buf_mutex);

    return;
}

status_t drc_init_remote_buffer(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx)
{
    status_t ret = drc_alloc_mmap_remote_buffer_pool(remote_sga, buf_ctx);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC]alloc mmap remote buffer pool fail,return error:%u", ret);
        return ret;
    }

    drc_set_data_buf(remote_sga, buf_ctx);

    drc_init_remote_buf_struct(remote_sga, buf_ctx);
    return OG_SUCCESS;
}

void broadcast_remote_buf_allocated()
{
    mes_remote_buf_mmap_bcast_t bcast;
    uint64 success_inst;

    mes_init_send_head(&bcast.head, MES_CMD_BROADCAST_REMOTE_BUF_MMAP, sizeof(mes_remote_buf_mmap_bcast_t), OG_INVALID_ID32,
                        g_dtc->profile.inst_id, OG_INVALID_ID8, 0, OG_INVALID_ID16);
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
        OG_LOG_RUN_ERR("[DRC]Do not process remote buf mmap broadcast, because src_inst is invalid: %u", msg->head->src_inst);
        return;
    }
    mes_release_message_buf(msg->buffer);
    (void)dtc_mmap_remote_data_buf(&ogx->remote_sga, node_id);
}


