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
 * mes_config.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_config.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_log_module.h"
#include <stdlib.h>
#include <string.h>
#include "mes_func.h"
#include "mes_config.h"

#define MAX_LSID_BUFFER 80
#define LSID_TYPE 2
#define MAX_NODE_COUNT 2
#define MAX_CLUSTER_ID 65535

static char g_uuid[OG_MAX_INSTANCES][37];
static uint32 g_lsid[OG_MAX_INSTANCES];
int64 g_mes_config_time[MES_TIME_STAMP_NUM];
status_t mes_set_inst_lsid(uint16 cluster_id, uint16 pid, uint32 inst_id, int64* time_stamp)
{
    FILE *fp = NULL;
    char get_buff[MAX_LSID_BUFFER];
    char cmd_buff[OG_MAX_CMD_LEN];
    int ret;
    int64 step0 = cm_now();
    if (!g_enable_dbstor) {
        ret = sprintf_s(cmd_buff, OG_MAX_CMD_LEN, "python /home/regress/oGRACKernel/pkg/deploy/action/obtains_lsid.py %u %u %u %u",
            LSID_TYPE, cluster_id, pid, inst_id);
    } else {
        ret = sprintf_s(cmd_buff, OG_MAX_CMD_LEN, "python3 /opt/ograc/action/obtains_lsid.py %u %u %u %u",
            LSID_TYPE, cluster_id, pid, inst_id);
    }
    if (ret < 0) {
        OG_LOG_RUN_INF("oGRAC obtain lsid failed, ret=%d.", ret);
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("generate lsid cluster id %d, pid %d, inst id %d", cluster_id, pid, inst_id);
    int64 step1 = cm_now();
    time_stamp[CM_DIGITAL_0] = step1 - step0;
    fp = popen(cmd_buff, "r");
    if (fp == NULL) {
        OG_LOG_RUN_ERR("execute generate lsid cmd failed");
        return OG_ERROR;
    }
    int64 step2 = cm_now();
    time_stamp[CM_DIGITAL_1] = step2 - step1;
    // get lsid
    if (fgets(get_buff, sizeof(get_buff), fp) != NULL) {
        g_lsid[inst_id] = strtol(get_buff, NULL, 0);
    } else {
        OG_LOG_RUN_ERR("generate lsid failed.");
        pclose(fp);
        return OG_ERROR;
    }
    int64 step3 = cm_now();
    time_stamp[CM_DIGITAL_2] = step3 - step2;
    // get uuid
    if (fgets(g_uuid[inst_id], sizeof(g_uuid[inst_id]), fp) == NULL) {
        OG_LOG_RUN_ERR("get uuid failed");
        pclose(fp);
        return OG_ERROR;
    }
    int64 step4 = cm_now();
    time_stamp[CM_DIGITAL_3] = step4 - step3;
    pclose(fp);
    int64 step5 = cm_now();
    time_stamp[CM_DIGITAL_4] = step5 - step4;
    return OG_SUCCESS;
}

status_t set_all_inst_lsid(uint16 cluster_id, uint16 pid)
{
    int index;
    int i;
    int one_node_record = (MES_TIME_STAMP_NUM >> 1);
    int64 time_stamp[MES_TIME_STAMP_NUM] = {0};

    for (index = 0; index < MAX_NODE_COUNT; index++) {
        if (mes_set_inst_lsid(cluster_id, pid, index, time_stamp) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("generate inst %d lsid failed.", index);
            return OG_ERROR;
        }
        for (i = 0; i < one_node_record; i++) {
            g_mes_config_time[i + (index * one_node_record)] = time_stamp[i];
        }
    }
    OG_LOG_RUN_INF("generate all lsid, uuid success.");
    return OG_SUCCESS;
}

uint32 get_config_lsid(uint32 inst_id)
{
    knl_panic_log(inst_id < MAX_NODE_COUNT, "get lsid of %d failed", inst_id);
    return g_lsid[inst_id];
}

char* get_config_uuid(uint32 inst_id)
{
    knl_panic_log(inst_id < MAX_NODE_COUNT, "get lsid of %d failed", inst_id);
    return g_uuid[inst_id];
}
