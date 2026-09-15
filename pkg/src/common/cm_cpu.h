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
 * cm_cpu.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_cpu.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CPU_H__
#define __CM_CPU_H__

#include "cm_defs.h"

#ifdef WIN32
#else
#include <sched.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_INFO_STR_SIZE 10240
#define CPU_SEG_MAX_NUM 64
#define SMALL_RECORD_SIZE 128
#define HW_TOPO_CPU_DIR      "/sys/devices/system/cpu/cpu%u"
#define HW_TOPO_CLUSTER_LIST "/sys/devices/system/cpu/cpu%u/topology/cluster_cpus_list"
#define HW_TOPO_NODE_DIR     "/sys/devices/system/node/node%u"
#define HW_TOPO_PATH_LEN     128
#define HW_TOPO_LIST_LEN     64
#define HW_TOPO_MAX_GROUPS   64

typedef struct {
    uint32 group_count;    /* cluster count if has_cluster, else numa count */
    uint32 cpu_of_each_g;  /* total CPU count */
    uint32 numa_count;     /* total numa count */
    bool8  has_cluster;    /* TRUE: cluster_cpus_list available; FALSE: fell back to numa */
} hw_topo_info_t;

status_t hw_topo_get_info(hw_topo_info_t *info);
int get_cpu_group_num(void);
cpu_set_t* get_cpu_masks(void);
int* get_cpu_info(void);
char *get_g_cpu_info(void);
status_t init_cpu_info(void);
int* get_cpu_info_count_ptr(void);
int* get_cpu_session_use_idx(void);

#ifdef __cplusplus
}
#endif

#endif
