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
 * cms_xalarm.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_xalarm.c
 *
 * -------------------------------------------------------------------------
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "cms_log_module.h"
#include "cms_param.h"
#include "cms_log.h"
#include "cms_instance.h"
#include "cms_stat.h"
#include "cms_node_fault.h"
#include "cms_comm.h"
#include "cms_msg_def.h"
#include "cms_msgque.h"
#include "cms_iofence.h"
#include "cms_gcc.h"
#include "cms_disk_lock.h"
#include "cms_uds_server.h"
#include "cms_interface.h"
#include "cms_xalarm.h"

#ifdef ENABLE_XALARMD

#include <xalarm/register_xalarm.h>
#include "cms_xalarm_compat.h"

#define CMS_XALARM_REBOOT_EVENT_ID         1003
#define CMS_XALARM_REBOOT_ACK_EVENT_ID     1004
#define CMS_XALARM_OOM_EVENT_ID            1005
#define CMS_XALARM_OOM_ACK_EVENT_ID        1006
#define CMS_XALARM_PANIC_EVENT_ID          1007
#define CMS_XALARM_PANIC_ACK_EVENT_ID      1008
#define CMS_XALARM_KERNEL_REBOOT_EVENT_ID  1009
#define CMS_XALARM_KERNEL_REBOOT_ACK_EVENT_ID 1010
#define CMS_XALARM_UBUS_MEM_EVENT_ID       1013
#define CMS_XALARM_NODE_MAP_MAX            CMS_MAX_NODE_COUNT
#define CMS_XALARM_NODE_MAP_TEXT_LEN       (CMS_PATH_BUFFER_SIZE * 4)
#define CMS_XALARM_INVALID_NODE_ID         CMS_MAX_NODE_COUNT
#define CMS_XALARM_PRIMARY_SWITCH_WAIT_MS  30000
#define CMS_XALARM_REGISTER_RETRY_MS       1000
#define CMS_XALARM_ELECTION_ROUND_MS       1000
#define CMS_XALARM_NOTIFY_DB_TIMEOUT_MS    3000
#define CMS_XALARM_DECIMAL_BASE            10
#define CMS_XALARM_SUBSCRIBE_EVENT_COUNT   3
#define CMS_XALARM_ACK_RES_SUCCESS         0UL
#define CMS_XALARM_ACK_RES_FAIL            1UL
#define CMS_XALARM_ACK_BUF_LEN             8192
#define CMS_XALARM_ACK_MSGID_BUF_LEN       128

static bool32 cms_xalarm_is_shared_storage(void)
{
    return (g_cms_param->gcc_type == CMS_DEV_TYPE_SD || g_cms_param->gcc_type == CMS_DEV_TYPE_LUN);
}

typedef struct st_cms_xalarm_node_map_item_t {
    uint32 node_id;
    uint32 cna;
} cms_xalarm_node_map_item_t;

static struct alarm_register *g_xalarm_event_register = NULL;
static cms_xalarm_node_map_item_t g_xalarm_node_map[CMS_XALARM_NODE_MAP_MAX];
static uint32 g_xalarm_node_map_count = 0;

static void cms_xalarm_trim_trailing_blanks(char *str)
{
    if (str == NULL) {
        return;
    }
    int32 len = (int32)strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        --len;
    }
}

static char *cms_xalarm_skip_leading_blanks(char *str)
{
    if (str == NULL) {
        return NULL;
    }
    while (*str != '\0' && isspace((unsigned char)*str)) {
        ++str;
    }
    return str;
}

static bool32 cms_xalarm_parse_uint32_text(const char *text, uint32 *value)
{
    if (text == NULL || text[0] == '\0' || value == NULL) {
        return OG_FALSE;
    }
    char *end_ptr = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end_ptr, CMS_XALARM_DECIMAL_BASE);
    if (errno != 0 || end_ptr == text || *end_ptr != '\0' || parsed > (unsigned long)UINT_MAX) {
        return OG_FALSE;
    }
    *value = (uint32)parsed;
    return OG_TRUE;
}

static bool32 cms_xalarm_load_node_map(void)
{
    g_xalarm_node_map_count = 0;
    if (g_cms_param->xalarm_node_map[0] == '\0') {
        CMS_LOG_INF("xalarm_node_map is not configured, xalarm event will not be mapped.");
        return OG_FALSE;
    }

    char map_text[CMS_XALARM_NODE_MAP_TEXT_LEN] = { 0 };
    errno_t rc = strncpy_s(map_text, sizeof(map_text), g_cms_param->xalarm_node_map, sizeof(map_text) - 1);
    if (rc != EOK) {
        CMS_LOG_ERR("copy xalarm_node_map failed, rc=%d", rc);
        return OG_FALSE;
    }

    bool32 node_id_seen[CMS_XALARM_NODE_MAP_MAX] = { OG_FALSE };
    uint32 cna_list[CMS_XALARM_NODE_MAP_MAX] = { 0 };
    cms_xalarm_node_map_item_t parsed_items[CMS_XALARM_NODE_MAP_MAX];
    uint32 map_count = 0;
    uint32 cluster_node_count = cms_get_gcc_node_count();
    bool32 check_cluster_count =
        (cluster_node_count > 0 && cluster_node_count <= CMS_MAX_NODE_COUNT);

    char *save_ptr = NULL;
    char *entry = strtok_r(map_text, ";", &save_ptr);
    while (entry != NULL) {
        char *pair_text = cms_xalarm_skip_leading_blanks(entry);
        if (pair_text == NULL || pair_text[0] == '\0') {
            CMS_LOG_ERR("invalid xalarm_node_map item, empty nodeId:cna pair");
            return OG_FALSE;
        }
        cms_xalarm_trim_trailing_blanks(pair_text);

        char *sep = strchr(pair_text, ':');
        if (sep == NULL || strchr(sep + 1, ':') != NULL) {
            CMS_LOG_ERR("invalid xalarm_node_map item \"%s\", format must be nodeId:cna", pair_text);
            return OG_FALSE;
        }
        *sep = '\0';
        char *node_id_text = cms_xalarm_skip_leading_blanks(pair_text);
        char *cna_text = cms_xalarm_skip_leading_blanks(sep + 1);
        cms_xalarm_trim_trailing_blanks(node_id_text);
        cms_xalarm_trim_trailing_blanks(cna_text);

        uint32 node_id = 0;
        uint32 cna = 0;
        if (!cms_xalarm_parse_uint32_text(node_id_text, &node_id) ||
            !cms_xalarm_parse_uint32_text(cna_text, &cna)) {
            CMS_LOG_ERR("invalid xalarm_node_map item \"%s:%s\", nodeId and cna must be non-negative integers",
                node_id_text, cna_text);
            return OG_FALSE;
        }
        if (node_id >= CMS_MAX_NODE_COUNT || cna == 0) {
            CMS_LOG_ERR("xalarm_node_map item out of range, nodeId=%u (valid 0..%u), cna=%u",
                node_id, CMS_MAX_NODE_COUNT - 1, cna);
            return OG_FALSE;
        }
        if (check_cluster_count && node_id >= cluster_node_count) {
            CMS_LOG_ERR("xalarm_node_map item out of range, nodeId=%u (valid 0..%u), cna=%u",
                node_id, cluster_node_count - 1, cna);
            return OG_FALSE;
        }
        if (check_cluster_count && map_count >= cluster_node_count) {
            CMS_LOG_ERR("too many xalarm_node_map items, expected %u", cluster_node_count);
            return OG_FALSE;
        }
        if (node_id_seen[node_id]) {
            CMS_LOG_ERR("duplicated nodeId in xalarm_node_map: %u", node_id);
            return OG_FALSE;
        }
        for (uint32 i = 0; i < map_count; ++i) {
            if (cna_list[i] == cna) {
                CMS_LOG_ERR("duplicated cna in xalarm_node_map: %u", cna);
                return OG_FALSE;
            }
        }
        if (map_count >= CMS_XALARM_NODE_MAP_MAX) {
            CMS_LOG_ERR("too many xalarm_node_map items, max %u", CMS_XALARM_NODE_MAP_MAX);
            return OG_FALSE;
        }

        node_id_seen[node_id] = OG_TRUE;
        cna_list[map_count] = cna;
        parsed_items[map_count].node_id = node_id;
        parsed_items[map_count].cna = cna;
        ++map_count;
        entry = strtok_r(NULL, ";", &save_ptr);
    }

    if (map_count == 0) {
        CMS_LOG_ERR("xalarm_node_map has no valid nodeId:cna pairs");
        return OG_FALSE;
    }

    if (check_cluster_count) {
        if (map_count != cluster_node_count) {
            CMS_LOG_ERR("xalarm_node_map item count (%u) must equal cluster node count (%u)",
                map_count, cluster_node_count);
            return OG_FALSE;
        }
        for (uint32 id = 0; id < cluster_node_count; ++id) {
            if (!node_id_seen[id]) {
                CMS_LOG_ERR("xalarm_node_map missing nodeId %u, must contain 0..%u exactly once",
                    id, cluster_node_count - 1);
                return OG_FALSE;
            }
        }
    }

    for (uint32 i = 0; i < map_count; ++i) {
        g_xalarm_node_map[i] = parsed_items[i];
    }
    g_xalarm_node_map_count = map_count;
    CMS_LOG_INF("loaded %u xalarm map items from cms.ini", g_xalarm_node_map_count);
    return OG_TRUE;
}

static uint32 cms_xalarm_find_node_by_cna(uint32 cna)
{
    for (uint32 i = 0; i < g_xalarm_node_map_count; ++i) {
        if (g_xalarm_node_map[i].cna == cna) {
            return g_xalarm_node_map[i].node_id;
        }
    }
    return CMS_XALARM_INVALID_NODE_ID;
}

static bool32 cms_xalarm_parse_remote_node_desc(const char *alarm_desc, uint32 *cna)
{
    const char *payload = strstr(alarm_desc, "{cna:");
    if (payload == NULL) {
        return OG_FALSE;
    }
    return (sscanf_s(payload, "{cna:%u", cna) == 1);
}

static bool32 cms_xalarm_need_process_event(int alarm_id)
{
    return (alarm_id == (int)CMS_XALARM_PANIC_EVENT_ID || alarm_id == (int)CMS_XALARM_KERNEL_REBOOT_EVENT_ID);
}

static uint32 cms_xalarm_map_alarm_id_to_ack(int alarm_id)
{
    switch (alarm_id) {
        case (int)CMS_XALARM_REBOOT_EVENT_ID:
            return CMS_XALARM_REBOOT_ACK_EVENT_ID;
        case (int)CMS_XALARM_OOM_EVENT_ID:
            return CMS_XALARM_OOM_ACK_EVENT_ID;
        case (int)CMS_XALARM_PANIC_EVENT_ID:
            return CMS_XALARM_PANIC_ACK_EVENT_ID;
        case (int)CMS_XALARM_KERNEL_REBOOT_EVENT_ID:
            return CMS_XALARM_KERNEL_REBOOT_ACK_EVENT_ID;
        default:
            return 0;
    }
}

static bool32 cms_xalarm_is_ack_with_cna_eid(int alarm_id)
{
    return (alarm_id == (int)CMS_XALARM_PANIC_EVENT_ID ||
        alarm_id == (int)CMS_XALARM_KERNEL_REBOOT_EVENT_ID);
}

static bool32 cms_xalarm_build_ack_payload(int alarm_id, const char *alarm_desc, unsigned long res,
    char *ack_buf, size_t ack_buf_len)
{
    int rc;
    if (alarm_desc == NULL || alarm_desc[0] == '\0') {
        rc = snprintf_s(ack_buf, ack_buf_len, ack_buf_len - 1, "0_%lu", res);
        return (rc != -1);
    }
    if (cms_xalarm_is_ack_with_cna_eid(alarm_id)) {
        rc = snprintf_s(ack_buf, ack_buf_len, ack_buf_len - 1, "%s_%lu", alarm_desc, res);
        return (rc != -1);
    }

    const char *underscore = strchr(alarm_desc, '_');
    if (underscore == NULL) {
        rc = snprintf_s(ack_buf, ack_buf_len, ack_buf_len - 1, "%s_%lu", alarm_desc, res);
        return (rc != -1);
    }

    size_t msgid_len = (size_t)(underscore - alarm_desc);
    char msgid_buf[CMS_XALARM_ACK_MSGID_BUF_LEN] = { 0 };
    if (msgid_len == 0 || msgid_len >= sizeof(msgid_buf)) {
        return OG_FALSE;
    }
    if (strncpy_s(msgid_buf, sizeof(msgid_buf), alarm_desc, msgid_len) != EOK) {
        return OG_FALSE;
    }
    rc = snprintf_s(ack_buf, ack_buf_len, ack_buf_len - 1, "%s_%lu", msgid_buf, res);
    return (rc != -1);
}

static void cms_xalarm_report_event_ack(int alarm_id, const char *alarm_desc, unsigned long res)
{
    uint32 ack_id = cms_xalarm_map_alarm_id_to_ack(alarm_id);
    if (ack_id == 0) {
        return;
    }

    char ack_buf[CMS_XALARM_ACK_BUF_LEN] = { 0 };
    if (!cms_xalarm_build_ack_payload(alarm_id, alarm_desc, res, ack_buf, sizeof(ack_buf))) {
        CMS_LOG_ERR("format xalarm ack payload failed, alarmId=%d", alarm_id);
        return;
    }

#ifdef CM_XALARM_REPORT_EVENT_HAS_LEN
    size_t payload_len = strlen(ack_buf);
    int rpt_ret = xalarm_report_event((unsigned short)ack_id, ack_buf, payload_len);
#else
    int rpt_ret = xalarm_report_event((unsigned short)ack_id, ack_buf);
#endif
    if (rpt_ret != 0) {
        CMS_LOG_WAR("xalarm_report_event ack failed, ret=%d errno=%d ackId=%u srcAlarmId=%d res=%lu",
            rpt_ret, errno, ack_id, alarm_id, res);
    } else {
        CMS_LOG_DEBUG_INF("xalarm_report_event ack ok, ackId=%u srcAlarmId=%u res=%lu payload=%s",
            ack_id, (uint32)alarm_id, res, ack_buf);
    }
}

static bool32 cms_xalarm_wait_master_switch(uint32 fault_node_id, uint32 timeout_ms)
{
    uint32 waited_ms = 0;
    while (waited_ms < timeout_ms) {
        uint16 master_node = OG_INVALID_ID16;
        if (cms_get_master_node(&master_node) == OG_SUCCESS &&
            master_node < CMS_MAX_NODE_COUNT &&
            master_node != (uint16)fault_node_id &&
            !cms_node_is_invalid(master_node)) {
            CMS_LOG_INF("confirm cms master switched, faultNodeId=%u, currentMasterNodeId=%u",
                fault_node_id, master_node);
            return OG_TRUE;
        }
        cms_do_try_master();
        if (cms_xalarm_is_shared_storage()) {
            (void)cms_try_be_master();
        }
        cm_sleep(CMS_XALARM_ELECTION_ROUND_MS);
        waited_ms += CMS_XALARM_ELECTION_ROUND_MS;
    }
    CMS_LOG_WAR("wait cms master switch timeout, faultNodeId=%u, waited %u ms", fault_node_id, timeout_ms);
    return OG_FALSE;
}

static void cms_xalarm_try_master_election(void)
{
    cms_do_try_master();
    if (cms_xalarm_is_shared_storage()) {
        (void)cms_try_be_master();
    }
}

/*
 * Classify xalarm dispatch into a 2x2 matrix:
 *   local_is_master = (master_id == cur_id)
 *   master_is_fault = (master_id == fault_id)
 *
 * Case 1: local master, master not fault  -> kick fault node immediately
 * Case 2: local master, master is fault   -> skip (survivors will elect new master)
 * Case 3: local not master, master fault  -> force-clean LUN/SD master lock,
 *                                            elect CMS master, then kick if we become master
 * Case 4: local not master, master healthy -> skip (case 1 runs on the master node)
 */
typedef enum en_cms_xalarm_dispatch_case {
    CMS_XALARM_CASE_HEALTHY_MASTER_KICK = 1,
    CMS_XALARM_CASE_FAULT_MASTER_LOCAL_SKIP = 2,
    CMS_XALARM_CASE_SURVIVOR_ELECT_AND_KICK = 3,
    CMS_XALARM_CASE_DELEGATE_TO_MASTER = 4,
} cms_xalarm_dispatch_case_t;

static cms_xalarm_dispatch_case_t cms_xalarm_classify_dispatch(
    uint16 cur_id, uint16 master_id, uint16 fault_id)
{
    bool32 local_is_master = (master_id == cur_id);
    bool32 master_is_fault = (master_id == fault_id);

    if (local_is_master && !master_is_fault) {
        return CMS_XALARM_CASE_HEALTHY_MASTER_KICK;
    }
    if (local_is_master && master_is_fault) {
        return CMS_XALARM_CASE_FAULT_MASTER_LOCAL_SKIP;
    }
    if (!local_is_master && master_is_fault) {
        return CMS_XALARM_CASE_SURVIVOR_ELECT_AND_KICK;
    }
    return CMS_XALARM_CASE_DELEGATE_TO_MASTER;
}

static status_t cms_xalarm_find_local_db_session(uint64 *session_id)
{
    cms_res_status_list_t stat_list;
    errno_t err = memset_s(&stat_list, sizeof(stat_list), 0, sizeof(stat_list));
    if (err != EOK) {
        CMS_LOG_ERR("xalarm notify: memset stat_list failed, rc=%d", err);
        return OG_ERROR;
    }

    if (cms_get_cluster_stat_bytype(CMS_RES_TYPE_DB, 0, &stat_list) != OG_SUCCESS) {
        CMS_LOG_ERR("xalarm notify: get DB resource status failed");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < stat_list.inst_count; i++) {
        cms_res_status_t *stat = &stat_list.inst_list[i];
        if (stat->node_id == g_cms_param->node_id && stat->stat == CMS_RES_ONLINE &&
            stat->session_id != (uint64)CMS_CLI_INVALID_SESS_ID) {
            *session_id = stat->session_id;
            return OG_SUCCESS;
        }
    }

    CMS_LOG_WAR("xalarm notify: local DB is not online or not registered");
    return OG_ERROR;
}

static void cms_xalarm_notify_local_db(const cms_xalarm_alarm_report_t *alarm)
{
    uint64 session_id = 0;
    if (cms_xalarm_find_local_db_session(&session_id) != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm notify local DB skipped, alarmId=%u, faultNode=%u",
            alarm->alarm_id, alarm->alarm_node_id);
        return;
    }

    cms_cli_msg_req_xalarm_notify_t req;
    cms_cli_msg_res_xalarm_notify_t res;
    errno_t err = memset_s(&req, sizeof(req), 0, sizeof(req));
    if (err != EOK) {
        CMS_LOG_ERR("xalarm notify: memset req failed, rc=%d", err);
        return;
    }
    err = memset_s(&res, sizeof(res), 0, sizeof(res));
    if (err != EOK) {
        CMS_LOG_ERR("xalarm notify: memset res failed, rc=%d", err);
        return;
    }

    req.head.msg_type = CMS_CLI_MSG_REQ_XALARM_NOTIFY;
    req.head.msg_size = sizeof(cms_cli_msg_req_xalarm_notify_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_node = g_cms_param->node_id;
    req.head.dest_node = g_cms_param->node_id;
    req.head.uds_sid = session_id;
    req.alarm_id = alarm->alarm_id;
    req.alarm_node_id = alarm->alarm_node_id;
    req.cna = alarm->cna;
    req.source_node_id = alarm->source_node_id;

    CMS_LOG_INF("xalarm notify local DB, alarmId=%u, faultNode=%u, cna=%u, session=%llu",
        req.alarm_id, req.alarm_node_id, req.cna, session_id);

    status_t ret = cms_uds_srv_request(&req.head, &res.head, sizeof(res), CMS_XALARM_NOTIFY_DB_TIMEOUT_MS);
    if (ret != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm notify local DB failed or timeout(%u ms), ret=%d, alarmId=%u, continue alarm handle",
            CMS_XALARM_NOTIFY_DB_TIMEOUT_MS, ret, alarm->alarm_id);
        return;
    }
    if (res.result != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm notify local DB ack result=%d, alarmId=%u, continue alarm handle",
            res.result, alarm->alarm_id);
        return;
    }
    CMS_LOG_INF("xalarm notify local DB ack ok, alarmId=%u, faultNode=%u",
        alarm->alarm_id, alarm->alarm_node_id);
}

static const char *cms_xalarm_dispatch_case_name(cms_xalarm_dispatch_case_t dispatch_case)
{
    switch (dispatch_case) {
        case CMS_XALARM_CASE_HEALTHY_MASTER_KICK:
            return "healthy_local_master_kick_fault";
        case CMS_XALARM_CASE_FAULT_MASTER_LOCAL_SKIP:
            return "fault_local_master_skip";
        case CMS_XALARM_CASE_SURVIVOR_ELECT_AND_KICK:
            return "survivor_elect_master_then_kick";
        case CMS_XALARM_CASE_DELEGATE_TO_MASTER:
            return "delegate_to_remote_master";
        default:
            return "unknown";
    }
}

static void cms_xalarm_kick_fault_from_cluster(const cms_xalarm_alarm_report_t *alarm, uint16 fault_id)
{
    CMS_LOG_INF("xalarm: kick fault node %u from cluster, alarmId=%u", fault_id, alarm->alarm_id);
    if (cms_kick_node_best_effort(fault_id) != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm: iofence kick failed, continue offline, faultNode=%u", fault_id);
    }
    cms_xalarm_handle_cluster_alarm(alarm);
}

static void cms_xalarm_dispatch_survivor_elect_and_kick(
    const cms_xalarm_alarm_report_t *alarm, uint16 cur_id, uint16 fault_id)
{
    CMS_LOG_WAR("xalarm case3: fault master node %u, survivor node %u elects CMS master first",
        fault_id, cur_id);

    if (cms_xalarm_is_shared_storage()) {
        if (cms_force_release_master_lock(fault_id) != OG_SUCCESS) {
            CMS_LOG_WAR("xalarm case3: force release master lock failed, fallback to lease wait, "
                "faultNode=%u", fault_id);
        } else {
            CMS_LOG_WAR("xalarm case3: force released master lock of fault node %u, try elect now",
                fault_id);
        }
    }

    cms_xalarm_try_master_election();

    if (!cms_xalarm_wait_master_switch(fault_id, CMS_XALARM_PRIMARY_SWITCH_WAIT_MS)) {
        CMS_LOG_WAR("xalarm case3: wait CMS master switch timeout, faultNode=%u, localNode=%u",
            fault_id, cur_id);
        return;
    }

    uint16 master_id = OG_INVALID_ID16;
    if (cms_get_master_node(&master_id) != OG_SUCCESS) {
        CMS_LOG_ERR("xalarm case3: get master node failed after election, faultNode=%u", fault_id);
        return;
    }
    if (master_id == fault_id) {
        CMS_LOG_WAR("xalarm case3: CMS master still on fault node %u after wait, localNode=%u",
            fault_id, cur_id);
        return;
    }
    if (master_id != cur_id) {
        CMS_LOG_INF("xalarm case3: new CMS master is node %u, local node %u skips kick",
            master_id, cur_id);
        return;
    }

    cms_xalarm_kick_fault_from_cluster(alarm, fault_id);
}

static void cms_xalarm_dispatch(const cms_xalarm_alarm_report_t *alarm)
{
    uint16 cur_id = g_cms_param->node_id;
    uint16 fault_id = (uint16)alarm->alarm_node_id;
    uint16 master_id = OG_INVALID_ID16;

    if (cms_get_master_node(&master_id) != OG_SUCCESS) {
        CMS_LOG_ERR("xalarm dispatch: get master node failed, faultNode=%u", fault_id);
        return;
    }

    cms_xalarm_dispatch_case_t dispatch_case = cms_xalarm_classify_dispatch(cur_id, master_id, fault_id);
    CMS_LOG_INF("xalarm dispatch: cur=%u master=%u fault=%u alarmId=%u case=%s",
        cur_id, master_id, fault_id, alarm->alarm_id, cms_xalarm_dispatch_case_name(dispatch_case));

    switch (dispatch_case) {
        case CMS_XALARM_CASE_HEALTHY_MASTER_KICK:
            cms_xalarm_kick_fault_from_cluster(alarm, fault_id);
            break;

        case CMS_XALARM_CASE_FAULT_MASTER_LOCAL_SKIP:
            CMS_LOG_WAR("xalarm case2: local node %u is fault CMS master, skip alarm handle",
                cur_id);
            break;

        case CMS_XALARM_CASE_SURVIVOR_ELECT_AND_KICK:
            cms_xalarm_dispatch_survivor_elect_and_kick(alarm, cur_id, fault_id);
            break;

        case CMS_XALARM_CASE_DELEGATE_TO_MASTER:
            CMS_LOG_DEBUG_INF("xalarm case4: healthy CMS master is node %u, local node %u skips",
                master_id, cur_id);
            break;

        default:
            CMS_LOG_ERR("xalarm dispatch: unknown case, cur=%u master=%u fault=%u",
                cur_id, master_id, fault_id);
            break;
    }
}

static void cms_xalarm_process_event_report(struct alarm_info *param, int alarm_id)
{
    char *alarm_desc = xalarm_getdesc(param);
    if (alarm_desc == NULL) {
        CMS_LOG_ERR("xalarm desc is null, alarmId=%d", alarm_id);
        return;
    }
    cms_xalarm_report_event_ack(alarm_id, alarm_desc, CMS_XALARM_ACK_RES_SUCCESS);

    uint32 cna = 0;
    if (!cms_xalarm_parse_remote_node_desc(alarm_desc, &cna)) {
        CMS_LOG_ERR("failed to parse xalarm payload, alarmId=%d, payload=%s", alarm_id, alarm_desc);
        return;
    }

    uint32 alarm_node_id = cms_xalarm_find_node_by_cna(cna);
    if (alarm_node_id == CMS_XALARM_INVALID_NODE_ID) {
        CMS_LOG_ERR("cannot find node mapping for xalarm, alarmId=%d, cna=%u", alarm_id, cna);
        return;
    }

    cms_xalarm_alarm_report_t alarm = { 0 };
    alarm.source_node_id = g_cms_param->node_id;
    alarm.alarm_node_id = alarm_node_id;
    alarm.cna = cna;
    alarm.alarm_id = (uint32)alarm_id;
    alarm.alarm_type = (uint32)xalarm_gettype(param);
    alarm.alarm_time = (int64)xalarm_gettime(param);
    errno_t rc = strncpy_s(alarm.alarm_desc, sizeof(alarm.alarm_desc), alarm_desc, sizeof(alarm.alarm_desc) - 1);
    if (rc != EOK) {
        CMS_LOG_ERR("copy xalarm desc failed, rc=%d", rc);
        return;
    }

    cms_xalarm_notify_local_db(&alarm);
    cms_xalarm_dispatch(&alarm);
    CMS_LOG_INF("reported xalarm event done, alarmId=%d, nodeId=%u, cna=%u", alarm_id, alarm_node_id, cna);
}

static void cms_xalarm_fill_local_power_off_alarm(struct alarm_info *param, const char *alarm_desc,
    cms_xalarm_alarm_report_t *alarm)
{
    alarm->source_node_id = g_cms_param->node_id;
    alarm->alarm_node_id = g_cms_param->node_id;
    alarm->cna = 0;
    alarm->alarm_id = CMS_XALARM_REBOOT_EVENT_ID;
    alarm->alarm_type = (uint32)xalarm_gettype(param);
    alarm->alarm_time = (int64)xalarm_gettime(param);
    if (strncpy_s(alarm->alarm_desc, sizeof(alarm->alarm_desc), alarm_desc,
        sizeof(alarm->alarm_desc) - 1) != EOK) {
        alarm->alarm_desc[0] = '\0';
    }
}

static void cms_xalarm_broadcast_stop_ub(const cms_xalarm_alarm_report_t *alarm)
{
    cms_msg_req_xalarm_report_t req;
    errno_t err = memset_s(&req, sizeof(req), 0, sizeof(req));
    if (err != EOK) {
        CMS_LOG_ERR("xalarm 1003: memset ub stop msg failed, rc=%d", err);
        return;
    }

    req.head.msg_type = CMS_MSG_REQ_XALARM_REPORT;
    req.head.msg_size = sizeof(cms_msg_req_xalarm_report_t);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_node = g_cms_param->node_id;
    req.head.dest_node = g_cms_param->node_id;
    req.head.need_ack = OG_FALSE;
    req.alarm = *alarm;
    cms_broadcast_srv_msg_best_effort(&req.head);
    CMS_LOG_INF("xalarm 1003: broadcast stop-ub to other cms nodes, localNode=%u",
        g_cms_param->node_id);
}

static void cms_xalarm_release_master_if_local_master(void)
{
    bool32 is_master = OG_FALSE;
    if (cms_is_master(&is_master) != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm 1003: get cms master status failed, skip release master_lock");
        return;
    }
    if (!is_master) {
        CMS_LOG_INF("xalarm 1003: local node %u is not cms master, skip release master_lock",
            g_cms_param->node_id);
        return;
    }

    CMS_LOG_WAR("xalarm 1003: local node %u is cms master, release master_lock",
        g_cms_param->node_id);
    if (cms_xalarm_is_shared_storage()) {
        if (cms_force_release_master_lock(g_cms_param->node_id) != OG_SUCCESS) {
            CMS_LOG_WAR("xalarm 1003: force release master lock failed, node=%u",
                g_cms_param->node_id);
        }
        return;
    }
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_FILE || g_cms_param->gcc_type == CMS_DEV_TYPE_NFS) {
        if (cms_disk_unlock(&g_cms_inst->master_lock, DISK_LOCK_WRITE) != OG_SUCCESS) {
            CMS_LOG_WAR("xalarm 1003: unlock master_lock failed, node=%u", g_cms_param->node_id);
        }
    }
}

static void cms_xalarm_handle_local_power_off(struct alarm_info *param)
{
    char *alarm_desc = xalarm_getdesc(param);
    CMS_LOG_WAR("receive xalarm power off event, nodeId=%u, alarmType=%d, alarmTime=%lld",
        g_cms_param->node_id, xalarm_gettype(param), (long long)xalarm_gettime(param));
    if (alarm_desc == NULL) {
        CMS_LOG_ERR("xalarm 1003 desc is null");
        cms_xalarm_report_event_ack((int)CMS_XALARM_REBOOT_EVENT_ID, NULL, CMS_XALARM_ACK_RES_FAIL);
        return;
    }

    cms_xalarm_alarm_report_t alarm = { 0 };
    cms_xalarm_fill_local_power_off_alarm(param, alarm_desc, &alarm);

    cms_xalarm_notify_local_db(&alarm);
    cms_xalarm_broadcast_stop_ub(&alarm);

    cms_stat_set_local_powering_off();
    if (cms_stat_force_local_res_offline() != OG_SUCCESS) {
        CMS_LOG_WAR("xalarm 1003: force local res offline failed, continue ack");
    } else {
        cms_res_offline_broadcast(g_cms_param->node_id);
        (void)cms_release_dss_master(g_cms_param->node_id);
    }

    cms_xalarm_release_master_if_local_master();
    cms_xalarm_report_event_ack((int)CMS_XALARM_REBOOT_EVENT_ID, alarm_desc, CMS_XALARM_ACK_RES_SUCCESS);
    CMS_LOG_WAR("xalarm 1003 handle done, nodeId=%u", g_cms_param->node_id);
}

static void cms_xalarm_handle_event(struct alarm_info *param)
{
    int alarm_id = xalarm_getid(param);
    if (alarm_id == (int)CMS_XALARM_REBOOT_EVENT_ID) {
        cms_xalarm_handle_local_power_off(param);
        return;
    }
    if (cms_xalarm_need_process_event(alarm_id)) {
        CMS_LOG_INF("receive xalarm panic/kernel reboot event, alarmId=%d, alarmType=%d, alarmTime=%lld",
            alarm_id, xalarm_gettype(param), (long long)xalarm_gettime(param));
        cms_xalarm_process_event_report(param, alarm_id);
        return;
    }

    switch (alarm_id) {
        case (int)CMS_XALARM_OOM_EVENT_ID:
            CMS_LOG_DEBUG_INF("receive reserved xalarm event, alarmId=%d, alarmType=%d",
                alarm_id, xalarm_gettype(param));
            cms_xalarm_report_event_ack(alarm_id, xalarm_getdesc(param), CMS_XALARM_ACK_RES_SUCCESS);
            break;
        case (int)CMS_XALARM_UBUS_MEM_EVENT_ID:
        case (int)CMS_XALARM_REBOOT_ACK_EVENT_ID:
        case (int)CMS_XALARM_OOM_ACK_EVENT_ID:
        case (int)CMS_XALARM_PANIC_ACK_EVENT_ID:
        case (int)CMS_XALARM_KERNEL_REBOOT_ACK_EVENT_ID:
            CMS_LOG_DEBUG_INF("receive reserved xalarm ack event, alarmId=%d", alarm_id);
            break;
        default:
            CMS_LOG_DEBUG_INF("receive unsupported xalarm event, alarmId=%d", alarm_id);
            break;
    }
}

#endif /* ENABLE_XALARMD */

void cms_xalarm_event_entry(thread_t *thread)
{
#ifdef ENABLE_XALARMD
    int reg_ret = -1;
    struct alarm_register *reg = NULL;
    int index = 0;
    struct alarm_subscription_info id_filter = { 0 };
    id_filter.id_list[index++] = (int)CMS_XALARM_PANIC_EVENT_ID;
    id_filter.id_list[index++] = (int)CMS_XALARM_KERNEL_REBOOT_EVENT_ID;
    id_filter.id_list[index++] = (int)CMS_XALARM_REBOOT_EVENT_ID;
    id_filter.len = (unsigned int)index;
    CMS_LOG_INF("xalarm event check thread start");
    while (!thread->closed) {
        if (reg_ret < 0) {
            reg_ret = xalarm_register_event(&reg, id_filter);
            if (reg_ret < 0) {
                CMS_LOG_ERR("xalarm_register_event failed, ret=%d", reg_ret);
                cm_sleep(CMS_XALARM_REGISTER_RETRY_MS);
                continue;
            }
            CMS_LOG_INF("xalarm event register success");
        }
        g_xalarm_event_register = reg;

        struct alarm_msg msg;
        while (!thread->closed) {
            errno_t rc = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
            if (rc != EOK) {
                CMS_LOG_ERR("memset alarm_msg failed, rc=%d", rc);
                break;
            }
            int get_ret = xalarm_get_event(&msg, reg);
            if (get_ret < 0) {
                CMS_LOG_WAR("xalarm_get_event failed, ret=%d errno=%d", get_ret, errno);
                break;
            }
            struct alarm_info info;
            CmsXalarmMsgToAlarmInfo(&msg, &info);
            cms_xalarm_handle_event(&info);
        }

        if (g_xalarm_event_register == reg && reg != NULL) {
            CmsXalarmUnregisterEvent(&reg);
            g_xalarm_event_register = NULL;
        }
        reg_ret = -1;
        if (thread->closed) {
            break;
        }
        cm_sleep(1);
    }
    CMS_LOG_INF("xalarm event check thread exit");
#else
    (void)thread;
#endif
}

status_t cms_xalarm_start_threads(void)
{
#ifdef ENABLE_XALARMD
    if (g_cms_param->xalarm_node_map[0] == '\0') {
        CMS_LOG_INF("xalarm event check skipped, XALARM_NODE_MAP is empty");
        return OG_SUCCESS;
    }
    if (!cms_xalarm_load_node_map()) {
        CMS_LOG_ERR("XALARM_NODE_MAP is invalid");
        return OG_ERROR;
    }
    if (cm_create_thread(cms_xalarm_event_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->xalarm_event_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("failed to create xalarm event check thread");
        return OG_ERROR;
    }
    CMS_LOG_INF("xalarm event check thread created");
    return OG_SUCCESS;
#else
    return OG_SUCCESS;
#endif
}

void cms_xalarm_shutdown(void)
{
#ifdef ENABLE_XALARMD
    if (g_cms_inst != NULL) {
        g_cms_inst->xalarm_event_thread.closed = OG_TRUE;
    }
    if (g_xalarm_event_register != NULL) {
        struct alarm_register *reg = g_xalarm_event_register;
        CmsXalarmUnregisterEvent(&reg);
        g_xalarm_event_register = NULL;
        CMS_LOG_INF("xalarm panic/reboot event unregister done");
    }
#endif
}

void cms_xalarm_handle_cluster_alarm(const cms_xalarm_alarm_report_t *alarm)
{
#ifdef ENABLE_XALARMD
    if (g_cms_param->xalarm_node_map[0] == '\0' || g_xalarm_node_map_count == 0) {
        CMS_LOG_INF("ignore xalarm cluster alarm, XALARM_NODE_MAP is not configured");
        return;
    }
    if (alarm == NULL || alarm->alarm_node_id >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("invalid xalarm cluster alarm, alarmNodeId=%u",
            alarm != NULL ? alarm->alarm_node_id : CMS_XALARM_INVALID_NODE_ID);
        return;
    }

    CMS_LOG_WAR("handle panic/reboot alarm on master cms, sourceNodeId=%u, alarmNodeId=%u, "
        "alarmId=%u, alarmType=%u, cna=%u",
        alarm->source_node_id, alarm->alarm_node_id, alarm->alarm_id, alarm->alarm_type, alarm->cna);

    bool32 stat_changed = OG_FALSE;
    if (cms_node_all_res_offline(alarm->alarm_node_id, &stat_changed) != OG_SUCCESS) {
        CMS_LOG_ERR("xalarm: update node %u offline failed", alarm->alarm_node_id);
        return;
    }
    if (stat_changed) {
        cms_res_offline_broadcast(alarm->alarm_node_id);
        (void)cms_release_dss_master((uint16)alarm->alarm_node_id);
    }
#else
    (void)alarm;
#endif
}

static void cms_reply_msg_xalarm_report_res(cms_packet_head_t *req_msg, status_t ret)
{
    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_msg_res_xalarm_report_t));
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg cms_msg_res_xalarm_report_t buf failed.");
        return;
    }
    cms_msg_res_xalarm_report_t *res = (cms_msg_res_xalarm_report_t *)cms_que_node_data(node);
    res->head.dest_node = req_msg->src_node;
    res->head.src_node = req_msg->dest_node;
    res->head.msg_size = sizeof(cms_msg_res_xalarm_report_t);
    res->head.msg_type = CMS_MSG_RES_XALARM_REPORT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req_msg->msg_seq;
    if (req_msg->need_ack == OG_TRUE) {
        res->head.is_ack = OG_TRUE;
        res->head.sid = req_msg->sid;
        res->head.rsn = req_msg->rsn;
    } else {
        res->head.is_ack = OG_FALSE;
    }
    res->result = ret;
    cms_enque(&g_cms_inst->send_que, node);
}

void cms_proc_msg_req_xalarm_report(cms_packet_head_t *msg)
{
    if (sizeof(cms_msg_req_xalarm_report_t) > msg->msg_size) {
        CMS_LOG_ERR("xalarm report msg size %u is invalid", msg->msg_size);
        return;
    }

    cms_msg_req_xalarm_report_t *req = (cms_msg_req_xalarm_report_t *)msg;
#ifdef ENABLE_XALARMD
    if (req->alarm.alarm_id == CMS_XALARM_REBOOT_EVENT_ID) {
        CMS_LOG_WAR("receive xalarm 1003 stop-ub notify, srcNode=%u, alarmNode=%u",
            msg->src_node, req->alarm.alarm_node_id);
        cms_xalarm_notify_local_db(&req->alarm);
        cms_reply_msg_xalarm_report_res(msg, OG_SUCCESS);
        return;
    }
#endif
    bool32 is_master = OG_FALSE;
    if (cms_is_master(&is_master) != OG_SUCCESS || !is_master) {
        CMS_LOG_WAR("ignore xalarm report on non-master cms, srcNode=%u, alarmNode=%u",
            msg->src_node, req->alarm.alarm_node_id);
        cms_reply_msg_xalarm_report_res(msg, OG_ERROR);
        return;
    }

    cms_xalarm_handle_cluster_alarm(&req->alarm);
    cms_reply_msg_xalarm_report_res(msg, OG_SUCCESS);
}
