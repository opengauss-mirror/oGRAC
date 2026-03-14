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
#include <sys/syscall.h>
#include "dtc_drc.h"
#include "dtc_dcs.h"
#include "knl_session.h"
#include "ub_dist_comm_queue.h"
#include "ub_dist_lock.h"

static ub_shm_comm_t g_handle_send = NULL;
static ub_shm_comm_t g_handle_recv = NULL;

status_t init_lock_comm_queue()
{
    uint32 node_id = g_instance->kernel.id;
    bool is_master = (node_id == 0);
    remote_sga_t *remote_queue = &DRC_RES_CTX->remote_queue;
    char *shmA = remote_queue->remote_buf_addr[0];
    char *shmB = remote_queue->remote_buf_addr[1];

    const size_t kInitSize = 1024;
    const size_t kRingSize = 1376640;

    const uint8_t nodeA = 0;
    const uint8_t nodeB = 1;
    const uint8_t cur = is_master ? nodeA : nodeB;
    const uint8_t peer = is_master ? nodeB : nodeA;
    void *init_region_cur = (is_master ? shmA : shmB);
    void *ring_region_cur = (is_master ? shmA : shmB) + kInitSize;
    void *ring_region_peer = (is_master ? shmB : shmA) + kInitSize;

    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 0: %p", remote_queue->remote_buf_addr[0]);
    OG_LOG_RUN_WAR("[DRC-GBP-LOCK] sprintf remote lock comm_queue addr start 1: %p", remote_queue->remote_buf_addr[1]);

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