/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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
 * cms_xalarm.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_xalarm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_XALARM_H
#define CMS_XALARM_H

#include "cm_defs.h"
#include "cms_defs.h"
#include "cms_client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_cms_xalarm_alarm_report_t {
    uint32 source_node_id;
    uint32 alarm_node_id;
    uint32 cna;
    uint32 alarm_id;
    uint32 alarm_type;
    int64  alarm_time;
    char   alarm_desc[CMS_INFO_BUFFER_SIZE];
} cms_xalarm_alarm_report_t;

status_t cms_xalarm_start_threads(void);
void cms_xalarm_shutdown(void);
void cms_xalarm_event_entry(thread_t *thread);
void cms_xalarm_handle_cluster_alarm(const cms_xalarm_alarm_report_t *alarm);
void cms_proc_msg_req_xalarm_report(cms_packet_head_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* CMS_XALARM_H */
