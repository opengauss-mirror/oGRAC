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
 * dtc_remote_buffer.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_buffer.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_REMOTE_BUFFER_H
#define DTC_REMOTE_BUFFER_H

#include "cm_defs.h"
#include "dtc_drc_util.h"
#include "knl_session.h"
#include "knl_context.h"
#include "srv_instance.h"
#include "dtc_reform.h"
#include "mes_func.h"
#include "dtc_drc_stat.h"
#include "dtc_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRC_REMOTE_BUF_START_ADDR 0x80000000000

typedef struct st_remote_buf_context {
    buf_set_t buf_set[OG_MAX_BUF_POOL_NUM];
    uint32 buf_set_count;
    thread_lock_t buf_mutex;
} remote_buf_context_t;

typedef struct st_mes_remote_buf_mmap_bcast {
    mes_message_head_t head;
    uint32 node_id;
} mes_remote_buf_mmap_bcast_t;

typedef struct st_remote_sga {
    uint64 remote_buf_alloc_size;
    char *remote_buf_addr[OG_MAX_INSTANCES];  /* allocated in UB shared memory */
    bool map_success[OG_MAX_INSTANCES];
    char *data_buf;   /* each remote data buf is managed by master node. */
} remote_sga_t;

#pragma pack(push, 1)
typedef struct st_remote_page_info {
    uint32 lock_ptr;
    uint32 lock_padded;
    uint64 head_lsn;
    uint64 page_id;
    uint64 page_access_count;
    uint16 log_owner_node;
    uint8 log_owner_node_timeline_id[6];
} remote_page_info_t;

#pragma pack(pop)

status_t drc_init_remote_buffer(remote_sga_t *remote_sga, remote_buf_context_t *buf_ctx);
void broadcast_remote_buf_allocated();
EXTER_ATTACK void drc_process_remote_buf_mmap(void *sess, mes_message_t *msg);


#ifdef __cplusplus
}
#endif
#endif


