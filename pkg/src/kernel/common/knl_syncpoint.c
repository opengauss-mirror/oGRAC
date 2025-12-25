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
 * knl_syncpoint.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_syncpoint.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_syncpoint.h"
#include "knl_context.h"
#include "mes_func.h"
#include "dtc_drc.h"
#include "cm_malloc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DB_DEBUG_VERSION

static void knl_syncpoint_inject_mem_leak(int32 *user_param, int32 ret)
{
    char *mem = (char *)cm_malloc(OGRAC_MEMORY_LEAK_SIZE);
    if (mem == NULL) {
        OG_LOG_RUN_ERR("[SYNCPOINT] oGRAC inject memory leak failed.");
        return;
    }
    errno_t err = memset_s(mem, OGRAC_MEMORY_LEAK_SIZE, 0, OGRAC_MEMORY_LEAK_SIZE);
    if (EOK != err) {
        OG_LOG_RUN_ERR("[SYNCPOINT] oGRAC inject memory leak failed, Secure C lib has thrown an error %d", (err));
        return;
    }
    OG_LOG_DEBUG_INF("[SYNCPOINT] oGRAC inject memory leak");
}

static void knl_syncpoint_inject_abort(int32 *user_param, int32 ret)
{
    CM_ABORT(0, "[SYNCPOINT] inject abort!");
}

static void knl_syncpoint_inject_errcode(int32 *user_param, int32 ret)
{
    if (user_param == NULL) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT] inject code err param");
        return;
    }
    *user_param = ret;
    OG_LOG_DEBUG_INF("[SYNCPOINT] inject errcode %d", ret);
}

static void knl_syncpoint_inject_null(int32 *user_param, int32 ret)
{
    if (user_param == NULL) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT] inject code err param");
        return;
    }
    void **param = (void **)user_param;
    *param = NULL;
    OG_LOG_DEBUG_INF("[SYNCPOINT] inject null");
}

static void knl_syncpoint_inject_timeout_and_error(int32 *user_param, int32 ret)
{
    if (user_param == NULL) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT] inject code err param");
        return;
    }
    *user_param = ret;
    cm_sleep(10000);  // 10000, smon request timeout
    OG_LOG_DEBUG_INF("[SYNCPOINT] inject errcode %d and timeout", ret);
}

static void knl_syncpoint_inject_delay(int32 *user_param, int32 ret)
{
    cm_sleep(ret);  // 10000, smon request timeout
    OG_LOG_DEBUG_INF("[SYNCPOINT] inject time delay %d ms", ret);
}

#define SYNCPOINT_WAIT_REFORM_TIMEOUT (20)
#define SYNCPOINT_WAIT_REFORM_SLEEP_TIME (1000)
static void knl_syncpoint_inject_other_node_abort(int32 *user_param, int32 ret)
{
    knl_session_t *session = (knl_session_t *)(user_param);
    mes_message_head_t head;
    // node 1 exit and trigger reform
    mes_init_send_head(&head, MES_CMD_SYNCPOINT_ABORT, sizeof(mes_message_head_t), OG_INVALID_ID32, session->kernel->id,
                       1, session->id, OG_INVALID_ID16);

    if (mes_send_data(&head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SYNC]: mes send data failed, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u", head.src_inst,
                       head.src_sid, head.dst_inst, head.dst_sid);
        return;
    }
    // wait reform
    uint64 version = DRC_GET_CURR_REFORM_VERSION;
    uint32 i = 0;
    page_id_t page_id;
    page_id.file = INVALID_FILE_ID;
    while (i < SYNCPOINT_WAIT_REFORM_TIMEOUT) {
        if (DRC_STOP_DCS_IO_FOR_REFORMING(version, session, page_id)) {
            OG_LOG_RUN_INF("syncpoint executed successfully, other node exited, reforming");
            break;
        }
        i++;
        cm_sleep(SYNCPOINT_WAIT_REFORM_SLEEP_TIME);
    }
}

// use sql to active global syncpoint, when the raise count decrease to 0, the syncpoint will be disabled auto.
// SYNCPOINT syncpoint_name SET enable/disable RAISE count;
// example:
// active syncpoint REQUST_PAGE_OWNER_ABORT to inject abort, default raise count is 1
// SYNCPOINT REQUST_PAGE_OWNER_ABORT SET enable;
// active syncpoint REQUST_PAGE_INTERNAL_FAIL to inject errcode, raise count is 5
// SYNCPOINT REQUST_PAGE_INTERNAL_FAIL SET enable RAISE 5;
// active syncpoint CLEAN_PAGE_OWNER_MALLOC_NULL to inject null ptr, raise count is 2
// SYNCPOINT CLEAN_PAGE_OWNER_MALLOC_NULL SET enable RAISE 2;
knl_global_syncpoint_def g_knl_syncpoint[] = {
    { OGRAC_MEMORY_LEAK, OG_FALSE, "OGRAC_MEMORY_LEAK", 0, knl_syncpoint_inject_mem_leak, 0 },
    { OGRAC_DCS_REQUEST_PAGE_OWNER_ABORT, OG_FALSE, "REQUST_PAGE_OWNER_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_REQUEST_PAGE_INTERNAL_FAIL, OG_FALSE, "REQUST_PAGE_INTERNAL_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { SYNCPOINT_ID_CLEAN_PAGE_OWNER_MALLOC_NULL, OG_FALSE, "CLEAN_PAGE_OWNER_MALLOC_NULL", 0, knl_syncpoint_inject_null,
      0 },
    { OGRAC_DCS_ASK_MASTER_SEND_FAIL, OG_FALSE, "ASK_MASTER_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DCS_ASK_MASTER_SUCC_ABORT, OG_FALSE, "ASK_MASTER_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_PROC_ASK_MASTER_ABORT, OG_FALSE, "PROC_ASK_MASTER_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_NOTIFY_OWNER_SEND_FAIL, OG_FALSE, "NOTIFY_OWNER_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DCS_NOTIFY_OWNER_SUCC_ABORT, OG_FALSE, "NOTIFY_OWNER_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_TRANSFER_BEFORE_SEND_ABORT, OG_FALSE, "TRANSFER_BEFORE_SEND_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DCS_TRANSFER_AFTER_SEND_ABORT, OG_FALSE, "TRANSFER_AFTER_SEND_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_ASK_MASTER_ACK_SUCC_ABORT, OG_FALSE, "REQUST_HANDLE_ACK_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_CLAIM_OWNER_SEND_FAIL, OG_FALSE, "OWNER_CLAIM_OWNER_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DCS_MASTER_BEFORE_CLAIM_ABORT, OG_FALSE, "MASTER_BEFORE_CLAIM_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_INVALID_PROC_ABORT, OG_FALSE, "INVALID_READONLY_PAGE_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DCS_SEND_EDP_MESSAGE_FAIL, OG_FALSE, "SEND_EDP_MESSAGE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DCS_INVALID_REQ_OTHER_ABORT, OG_FALSE, "DCS_INVALID_REQ_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },
    { OGRAC_DCS_RECYCLE_ITEM_OTHER_ABORT, OG_FALSE, "DCS_RECYCLE_ITEM_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },
    { OGRAC_DCS_RECYCLE_ITEM_PENDING_OTHER_ABORT, OG_FALSE, "DCS_RECYCLE_ITEM_PENDING_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },
    { OGRAC_DCS_RECYCLE_OWNER_SEND_FAIL, OG_FALSE, "DCS_RECYCLE_OWNER_SEND_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_DCS_RECYCLE_MASTER_OTHER_ABORT, OG_FALSE, "DCS_RECYCLE_MASTER_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },

    { OGRAC_HEAP_EXTEND_PROC_BCAST_ABORT, OG_FALSE, "HEAP_EXTEND_PROC_BCAST_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_HEAP_EXTEND_UNSET_BEFORE_BCAST_ABORT, OG_FALSE, "HEAP_EXTEND_UNSET_BEFORE_BCAST_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_SPLIT_AFTER_BCAST_SPLITTING_ABORT, OG_FALSE, "BTREE_SPLIT_AFTER_BCAST_SPLITTING_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_SPLIT_ALLOC_EXTENT_FAIL, OG_FALSE, "BTREE_SPLIT_ALLOC_EXTENT_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_BTREE_SPLIT_BEFORE_BCAST_ABORT_SPLIT_ABORT, OG_FALSE, "BTREE_SPLIT_BEFORE_BCAST_ABORT_SPLIT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_SPLIT_BEFORE_BCAST_SPLITTED_ABORT, OG_FALSE, "BTREE_SPLIT_BEFORE_BCAST_SPLITTED_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_SYNC_DDL_BEFORE_BCAST_ABORT, OG_FALSE, "SYNC_DDL_BEFORE_BCAST_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_PROC_DDL_BCAST_ABORT, OG_FALSE, "PROC_DDL_BCAST_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_INVALID_DC_BEFORE_BCAST_ABORT, OG_FALSE, "INVALID_DC_BEFORE_BCAST_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DTC_BCAST_ACK_FAIL, OG_FALSE, "DTC_BCAST_ACK_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DROP_USER_LOCK_AFTER_BCAST_ABORT, OG_FALSE, "DROP_USER_LOCK_AFTER_BCAST_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DROP_USER_OBJECT_FAIL, OG_FALSE, "DROP_USER_OBJECT_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DROP_USER_REVERT_NORMAL_BEFORE_BCAST_ABORT, OG_FALSE, "DROP_USER_REVERT_NORMAL_BEFORE_BCAST_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DROP_USER_LOCK_PROC_BCAST_ABORT, OG_FALSE, "DROP_USER_LOCK_PROC_BCAST_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DROP_USER_REVERT_NORMAL_PROC_BCAST_ABORT, OG_FALSE, "DROP_USER_REVERT_NORMAL_PROC_BCAST_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_BEFORE_BCAST_ROOT_PAGE_ABORT, OG_FALSE, "BTREE_BEFORE_BCAST_ROOT_PAGE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_AFTER_BCAST_ROOT_PAGE_ABORT, OG_FALSE, "BTREE_AFTER_BCAST_ROOT_PAGE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BTREE_PROC_BCAST_ROOT_PAGE_FAIL, OG_FALSE, "BTREE_PROC_BCAST_ROOT_PAGE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BTREE_PROC_BCAST_ROOT_PAGE_ABORT, OG_FALSE, "BTREE_PROC_BCAST_ROOT_PAGE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_TXN_INF_REQ_SEND_FAIL, OG_FALSE, "TXN_INF_REQ_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_TXN_INF_ACK_SEND_FAIL, OG_FALSE, "TXN_INF_ACK_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_TXN_SNAPSHOT_REQ_SEND_FAIL, OG_FALSE, "TXN_SNAPSHOT_REQ_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_TXN_SNAPSHOT_ACK_SEND_FAIL, OG_FALSE, "TXN_SNAPSHOT_ACK_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_TXN_WAIT_SEND_FAIL, OG_FALSE, "TXN_WAIT_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DLS_WAIT_TXN_SEND_FAIL, OG_FALSE, "DLS_WAIT_TXN_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DLS_WAIT_TXN_ACK_SEND_FAIL, OG_FALSE, "DLS_WAIT_TXN_ACK_SEND_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PCR_REQ_HEAP_PAGE_SEND_FAIL, OG_FALSE, "OGRAC_PCR_REQ_HEAP_PAGE_SEND_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PCR_REQ_BTREE_PAGE_SEND_FAIL, OG_FALSE, "OGRAC_PCR_REQ_BTREE_PAGE_SEND_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PCR_ACK_FAIL, OG_FALSE, "OGRAC_PCR_ACK_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PCR_REQ_MASTER_SEND_FAIL, OG_FALSE, "OGRAC_PCR_REQ_MASTER_SEND_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_PCR_REQ_OWNER_SEND_FAIL, OG_FALSE, "OGRAC_PCR_REQ_OWNER_SEND_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_HEAP_CHECK_VISIBLE_SEND_FAIL, OG_FALSE, "OGRAC_HEAP_CHECK_VISIBLE_SEND_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_HEAP_CHECK_VISIBLE_ACK_FAIL, OG_FALSE, "OGRAC_HEAP_CHECK_VISIBLE_ACK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REFORM_BUILD_CHANNEL_FAIL, OG_FALSE, "REFORM_BUILD_CHANNEL_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_RECOVERY_INIT_FAIL, OG_FALSE, "RECOVERY_INIT_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PARAL_REPLAY_READ_LOG_FAIL, OG_FALSE, "PARAL_REPLAY_READ_LOG_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_RECOVERY_ANAL_READ_LOG_FAIL, OG_FALSE, "RECOVERY_ANAL_READ_LOG_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_RECOVERY_RCY_SET_ALLOC_ITEMPOOL_FAIL, OG_FALSE, "RECOVERY_RCY_SET_ALLOC_ITEMPOOL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_RECOVERY_SEND_RCY_SET_FAIL, OG_FALSE, "RECOVERY_SEND_RCY_SET_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { CANTAIN_RECOVERY_PROC_RCY_SET_MALLOC_NULL, OG_FALSE, "RECOVERY_PROC_RCY_SET_MALLOC_NULL", 0,
      knl_syncpoint_inject_null, 0 },
    { OGRAC_RECOVERY_SEND_RCY_SET_ACK_FAIL, OG_FALSE, "RECOVERY_SEND_RCY_SET_ACK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_PART_RECOVERY_BEFORE_CKPT_ABORT, OG_FALSE, "PART_RECOVERY_BEFORE_CKPT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_SMON_REQUEST_TXN_DLOCK_TIMEOUT_AND_FAIL, OG_FALSE, "SMON_REQUEST_TXN_DLOCK_TIMEOUT_AND_FAIL", 0,
      knl_syncpoint_inject_timeout_and_error, 0 },
    { OGRAC_SMON_REQUEST_SID_TIMEOUT_AND_FAIL, OG_FALSE, "SMON_REQUEST_SID_TIMEOUT_AND_FAIL", 0,
      knl_syncpoint_inject_timeout_and_error, 0 },
    { OGRAC_SMON_REQUEST_WSID_TIMEOUT_AND_FAIL, OG_FALSE, "SMON_REQUEST_WSID_DLOCK_TIMEOUT_AND_FAIL", 0,
      knl_syncpoint_inject_timeout_and_error, 0 },
    { OGRAC_DLS_LOCK_REMOTE_TABLE_ABORT, OG_FALSE, "DLS_LOCK_REMOTE_TABLE_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_REMASTER_SEND_TASK_FAIL, OG_FALSE, "REMASTER_SEND_TASK_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_SEND_MIGRATE_BUF_RES_FAIL, OG_FALSE, "REMASTER_SEND_MIGRATE_BUF_RES_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_SEND_MIGRATE_LOCK_RES_FAIL, OG_FALSE, "REMASTER_SEND_MIGRATE_LOCK_RES_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_BCAST_TARGET_PART_FAIL, OG_FALSE, "REMASTER_BCAST_TARGET_PART_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_BCAST_REMASTER_DONE_FAIL, OG_FALSE, "REMASTER_BCAST_REMASTER_DONE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_STEP_ASSIGN_TASK_FAIL, OG_FALSE, "REMASTER_STEP_ASSIGN_TASK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_STEP_MIGRATE_FAIL, OG_FALSE, "REMASTER_STEP_MIGRATE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_STEP_RECOVERY_FAIL, OG_FALSE, "REMASTER_STEP_RECOVERY_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_REMASTER_STEP_PUBLISH_FAIL, OG_FALSE, "REMASTER_STEP_PUBLISH_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_CREATE_FREE_MIGRATE_PROC_FAIL, OG_FALSE, "REMASTER_CREATE_FREE_MIGRATE_PROC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_CREATE_CLEAN_OWNER_PROC_FAIL, OG_FALSE, "REMASTER_CREATE_CLEAN_OWNER_PROC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_CREATE_LOCKRES_RCY_PROC_FAIL, OG_FALSE, "REMASTER_CREATE_LOCKRES_RCY_PROC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_CREATE_COLLECT_PAGEINFO_PROC_FAIL, OG_FALSE, "REMASTER_CREATE_COLLECT_PAGEINFO_PROC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REMASTER_CREATE_MIGRATE_RES_PROC_FAIL, OG_FALSE, "REMASTER_CREATE_MIGRATE_RES_PROC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BCAST_RECOVERY_DONE_OTHER_ABORT, OG_FALSE, "OGRAC_BCAST_RECOVERY_DONE_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },
    { OGRAC_BCAST_REFORM_DONE_OTHER_ABORT, OG_FALSE, "OGRAC_BCAST_REFORM_DONE_OTHER_ABORT", 0,
      knl_syncpoint_inject_other_node_abort, 0 },
    { OGRAC_DLS_REQUEST_LOCK_OWNER_FAIL, OG_FALSE, "DLS_REQUEST_LOCK_OWNER_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_DLS_REQUEST_LOCK_OWNER_SUCC_ABORT, OG_FALSE, "DLS_REQUEST_LOCK_OWNER_SUCC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DLS_REQUEST_LOCK_MSG_SEND_FAIL, OG_FALSE, "DLS_REQUEST_LOCK_MSG_SEND_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DLS_REQUEST_LOCK_MSG_SEND_SUCC_ABORT, OG_FALSE, "DLS_REQUEST_LOCK_MSG_SEND_SUCC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DLS_CLAIM_LOCK_OWNER_FAIL, OG_FALSE, "DLS_CLAIM_LOCK_OWNER_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DLS_CLAIM_LOCK_OWNER_SUCC_ABORT, OG_FALSE, "DLS_CLAIM_LOCK_OWNER_SUCC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DLS_CLAIM_LOCK_OWNER_BEFORE_ABORT, OG_FALSE, "DLS_CLAIM_LOCK_OWNER_BEFORE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_TMP_TABLE_BEFORE_CREATE_LTT_ABORT, OG_FALSE, "CREATE_TMP_TABLE_BEFORE_CREATE_LTT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_TMP_TABLE_AFTER_CREATE_LTT_ABORT, OG_FALSE, "CREATE_TMP_TABLE_AFTER_CREATE_LTT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_TMP_TABLE_BEFORE_RELEASE_LTT_ABORT, OG_FALSE, "DROP_TMP_TABLE_BEFORE_RELEASE_LTT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_TMP_TABLE_AFTER_RELEASE_LTT_ABORT, OG_FALSE, "DROP_TMP_TABLE_AFTER_RELEASE_LTT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_TABLE_BEFORE_SYNC_ABORT, OG_FALSE, "CREATE_TABLE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_TABLE_AFTER_SYNC_ABORT, OG_FALSE, "CREATE_TABLE_AFTER_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_TABLE_FAIL, OG_FALSE, "CREATE_TABLE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_CREATE_TABLE_HANDLE_REFS_FAIL, OG_FALSE, "CREATE_TABLE_HANDLE_REFS_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_DROP_TABLE_AFTER_LOG_PUT, OG_FALSE, "DROP_TABLE_AFTER_LOG_PUT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_TABLE_BEFORE_SYNC_ABORT, OG_FALSE, "DROP_TABLE_BEFORE_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_TABLE_AFTER_SYNC_ABORT, OG_FALSE, "DROP_TABLE_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_TABLE_FAIL, OG_FALSE, "DROP_TABLE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_ALTER_TABLE_AFTER_LOG_PUT, OG_FALSE, "ALTER_TABLE_AFTER_LOG_PUT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_ALTER_TABLE_BEFORE_SYNC_ABORT, OG_FALSE, "ALTER_TABLE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_ALTER_TABLE_AFTER_SYNC_ABORT, OG_FALSE, "ALTER_TABLE_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_ALTER_TABLE_RETURN_ERROR, OG_FALSE, "ALTER_TABLE_RETURN_ERROR", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_CREATE_HASH_PART_INDEX_BEFORE_WRITE_UNDO_ABORT, OG_FALSE,
      "CREATE_HASH_PART_INDEX_BEFORE_WRITE_UNDO_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_HASH_PART_INDEX_AFTER_WRITE_UNDO_ABORT, OG_FALSE,
      "CREATE_HASH_PART_INDEX_AFTER_WRITE_UNDO_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_HASH_PART_HEAP_SEG_BEFORE_WRITE_UNDO_ABORT, OG_FALSE,
      "CREATE_HASH_PART_HEAP_SEG_BEFORE_WRITE_UNDO_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_HASH_PART_HEAP_SEG_AFTER_WRITE_UNDO_ABORT, OG_FALSE,
      "CREATE_HASH_PART_HEAP_SEG_AFTER_WRITE_UNDO_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_USER_BEFORE_SYNC_ABORT, OG_FALSE, "CREATE_USER_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_USER_AFTER_SYNC_ABORT, OG_FALSE, "CREATE_USER_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_USER_BEFORE_SYNC_ABORT, OG_FALSE, "DROP_USER_BEFORE_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_USER_AFTER_SYNC_ABORT, OG_FALSE, "DROP_USER_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_ALTER_USER_BEFORE_SYNC_ABORT, OG_FALSE, "ALTER_USER_BEFORE_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_ALTER_USER_AFTER_SYNC_ABORT, OG_FALSE, "ALTER_USER_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_CREATE_INDEX_BEFORE_SYNC_ABORT, OG_FALSE, "CREATE_INDEX_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_INDEX_AFTER_SYNC_ABORT, OG_FALSE, "CREATE_INDEX_AFTER_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_INDEX_BEFORE_SYNC_ABORT, OG_FALSE, "DROP_INDEX_BEFORE_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_INDEX_AFTER_SYNC_ABORT, OG_FALSE, "DROP_INDEX_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_ALTER_INDEX_BEFORE_SYNC_ABORT, OG_FALSE, "ALTER_INDEX_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_ALTER_INDEX_AFTER_SYNC_ABORT, OG_FALSE, "ALTER_INDEX_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_SPACE_BEFORE_SYNC_ABORT, OG_FALSE, "DROP_SPACE_BEFORE_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_CREATE_DATAFILE_BEFORE_CREATE_DF_ABORT, OG_FALSE, "CREATE_DATAFILE_BEFORE_CREATE_DF_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_FAIL, OG_FALSE, "CREATE_DATAFILE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_AFTER_CREATE_DF_ABORT, OG_FALSE, "CREATE_DATAFILE_AFTER_CREATE_DF_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_BEFORE_SAVE_CTRL_ABORT, OG_FALSE, "CREATE_DATAFILE_BEFORE_SAVE_CTRL_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_SAVE_DF_CTRL_FAIL, OG_FALSE, "CREATE_DATAFILE_SAVE_DF_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_SAVE_SPC_CTRL_FAIL, OG_FALSE, "CREATE_DATAFILE_SAVE_SPC_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_BEFORE_SYNC_ABORT, OG_FALSE, "CREATE_DATAFILE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_CREATE_DATAFILE_AFTER_SYNC_DDL_ABORT, OG_FALSE, "CREATE_DATAFILE_AFTER_SYNC_DDL_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_BEFORE_LOG_COMMIT_ABORT, OG_FALSE, "EXTEND_DATAFILE_BEFORE_LOG_COMMIT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_BEFORE_EXTEND_DEVICE_ABORT, OG_FALSE, "EXTEND_DATAFILE_BEFORE_EXTEND_DEVICE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_FAIL, OG_FALSE, "EXTEND_DATAFILE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT, OG_FALSE, "EXTEND_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_SAVE_DF_CTRL_FAIL, OG_FALSE, "EXTEND_DATAFILE_SAVE_DF_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_BEFORE_SYNC_ABORT, OG_FALSE, "EXTEND_DATAFILE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_EXTEND_DATAFILE_AFTER_SYNC_ABORT, OG_FALSE, "EXTEND_DATAFILE_AFTER_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_BEFORE_LOGPUT_ABORT, OG_FALSE, "REMOVE_DATAFILE_BEFORE_LOGPUT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_AFTER_LOGPUT_ABORT, OG_FALSE, "REMOVE_DATAFILE_AFTER_LOGPUT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_SAVE_SPC_CTRL_FAIL, OG_FALSE, "REMOVE_DATAFILE_SAVE_SPC_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_AFTER_WRITE_SPACECTRL_ABORT, OG_FALSE, "REMOVE_DATAFILE_AFTER_WRITE_SPACECTRL_ABORT",
      0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_SAVE_DF_CTRL_FAIL, OG_FALSE, "REMOVE_DATAFILE_SAVE_DF_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_FAIL, OG_FALSE, "REMOVE_DATAFILE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_BEFORE_SYNC_ABORT, OG_FALSE, "REMOVE_DATAFILE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_REMOVE_DATAFILE_AFTER_SYNC_ABORT, OG_FALSE, "REMOVE_DATAFILE_AFTER_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_BEFORE_LOG_COMMIT_ABORT, OG_FALSE, "TRUNCATE_DATAFILE_BEFORE_LOG_COMMIT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_BEFORE_TRUNCATE_DEVICE_ABORT, OG_FALSE,
      "TRUNCATE_DATAFILE_BEFORE_TRUNCATE_DEVICE_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_FAIL, OG_FALSE, "TRUNCATE_DATAFILE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT, OG_FALSE, "TRUNCATE_DATAFILE_BEFORE_SAVE_DF_CTRL_ABORT",
      0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_SAVE_DF_CTRL_FAIL, OG_FALSE, "TRUNCATE_DATAFILE_SAVE_DF_CTRL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_BEFORE_SYNC_ABORT, OG_FALSE, "TRUNCATE_DATAFILE_BEFORE_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_TRUNCATE_DATAFILE_AFTER_SYNC_ABORT, OG_FALSE, "TRUNCATE_DATAFILE_AFTER_SYNC_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_SPACE_BEFORE_LOGPUT_ABORT, OG_FALSE, "DROP_SPACE_BEFORE_LOGPUT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_SPACE_AFTER_LOGPUT_ABORT, OG_FALSE, "DROP_SPACE_AFTER_LOGPUT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_SPACE_FAIL, OG_FALSE, "DROP_SPACE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_DROP_SPACE_SAVE_CTRL_FAIL, OG_FALSE, "DROP_SPACE_SAVE_CTRL_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_DDL_DROP_SPACE_AFTER_SYNC_ABORT, OG_FALSE, "DROP_SPACE_AFTER_SYNC_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_DROP_SPACE_BEFORE_WRITE_CTRL_ABORT, OG_FALSE, "DROP_SPACE_BEFORE_WRITE_CTRL_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_DROP_SPACE_AFTER_WRITE_CTRL_ABORT, OG_FALSE, "DROP_SPACE_AFTER_WRITE_CTRL_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_LOCK_TABLE_X_LOCAL_BEFORE_ABORT, OG_FALSE, "LOCK_TABLE_X_LOCAL_BEFORE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_LOCK_TABLE_X_LOCAL_AFTER_ABORT, OG_FALSE, "LOCK_TABLE_X_LOCAL_AFTER_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_LOCK_TABLE_X_DLS_AFTER_ABORT, OG_FALSE, "LOCK_TABLE_X_DLS_AFTER_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_LOCK_TABLE_S_LOCAL_BEFORE_ABORT, OG_FALSE, "LOCK_TABLE_S_LOCAL_BEFORE_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_LOCK_TABLE_S_LOCAL_AFTER_ABORT, OG_FALSE, "LOCK_TABLE_S_LOCAL_AFTER_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_LOCK_TABLE_S_DLS_AFTER_ABORT, OG_FALSE, "LOCK_TABLE_S_DLS_AFTER_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_BEFORE_SYNC_DDL_ABORT, OG_FALSE, "DDL_BEFORE_SYNC_DDL_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_DDL_AFTER_SYNC_DDL_ABORT, OG_FALSE, "DDL_AFTER_SYNC_DDL_ABORT", 0, knl_syncpoint_inject_abort, 0 },
    { OGRAC_GET_USER_STATS_ACK_TIMEOUT, OG_FALSE, "GET_USER_STAT_ACK_TIME_OUT", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_SET_USER_STATS_ACK_TIMEOUT, OG_FALSE, "SET_USER_STAT_ACK_TIME_OUT", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_BACKUP_REV_PRECHECK_STAT_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_PRECHECK_STAT_REQ_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BACKUP_REV_PRECHECK_ARCH_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_PRECHECK_ARCH_REQ_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BACKUP_TRIGGER_FORCH_ARCH_ABORT, OG_FALSE, "OGRAC_BACKUP_TRIGGER_FORCH_ARCH_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BACKUP_TRIGGER_FORCH_ARCH_WAIT_ABORT, OG_FALSE, "OGRAC_BACKUP_TRIGGER_FORCH_ARCH_WAIT_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_BACKUP_TRIGGER_CKPT_ABORT, OG_FALSE, "OGRAC_BACKUP_TRIGGER_CKPT_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_REV_LSN_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_LSN_REQ_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_REV_RCY_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_RCY_REQ_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_REV_LRP_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_LRP_REQ_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_REV_CTRL_REQ_ABORT, OG_FALSE, "OGRAC_BACKUP_REV_CTRL_REQ_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_REV_CKPT_REQ_FAIL, OG_FALSE, "OGRAC_BACKUP_REV_CKPT_REQ_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_BACKUP_READ_PAGE_FROM_DBSTOR_FAIL, OG_FALSE, "OGRAC_BACKUP_READ_PAGE_FROM_DBSTOR_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_WRITE_CTRL_TO_FILE_FAIL, OG_FALSE, "OGRAC_BACKUP_WRITE_CTRL_TO_FILE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_WRITE_BACKUPSET_TO_FILE_FAIL, OG_FALSE, "OGRAC_BACKUP_WRITE_BACKUPSET_TO_FILE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_WRITE_PAGE_TO_FILE_FAIL, OG_FALSE, "OGRAC_BACKUP_WRITE_PAGE_TO_FILE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_READ_LOG_FROM_ARCH_FAIL, OG_FALSE, "OGRAC_BACKUP_READ_LOG_FROM_ARCH_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_WRITE_LOG_TO_FILE_FAIL, OG_FALSE, "OGRAC_BACKUP_WRITE_LOG_TO_FILE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_ARCH_GET_LOG_CAPACITY_FAIL, OG_FALSE, "OGRAC_ARCH_GET_LOG_CAPACITY_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_ARCH_GET_LOG_FAIL, OG_FALSE, "OGRAC_ARCH_GET_LOG_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_ARCH_WRITE_LOG_TO_FILE_FAIL, OG_FALSE, "OGRAC_ARCH_WRITE_LOG_TO_FILE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_ARCH_RENAME_TMP_FILE_FAIL, OG_FALSE, "OGRAC_ARCH_RENAME_TMP_FILE_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_REFORM_ARCHIVE_INIT_ARCH_CTX_FAIL, OG_FALSE, "OGRAC_REFORM_ARCHIVE_INIT_ARCH_CTX_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_REFORM_ARCHIVE_READ_REDO_LOG_FAIL, OG_FALSE, "OGRAC_REFORM_ARCHIVE_READ_REDO_LOG_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_RST_OPEN_NAMESPACE_FAIL, OG_FALSE, "OGRAC_RST_OPEN_NAMESPACE_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_SPC_OPEN_DATAFILE_FAIL, OG_FALSE, "OGRAC_SPC_OPEN_DATAFILE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_OPEN_DEVICE_FAIL, OG_FALSE, "OGRAC_OPEN_DEVICE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_LOCK_DDL_FAIL, OG_FALSE, "UPGRADE_CTRL_VERSION_LOCK_DDL_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_WRITE_DISK_FAIL, OG_FALSE, "UPGRADE_CTRL_VERSION_WRITE_DISK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_BEFORE_WRITE_DISK_ABORT, OG_FALSE, "UPGRADE_CTRL_VERSION_BEFORE_WRITE_DISK_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_AFTER_WRITE_DISK_ABORT, OG_FALSE, "UPGRADE_CTRL_VERSION_AFTER_WRITE_DISK_ABORT", 0,
      knl_syncpoint_inject_abort, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_SEND_SYNC_FAIL, OG_FALSE, "UPGRADE_CTRL_VERSION_SEND_SYNC_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_UPGRADE_CTRL_VERSION_SEND_ACK_FAIL, OG_FALSE, "UPGRADE_CTRL_VERSION_SEND_ACK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_RD_DROP_TABLE_DELAY, OG_FALSE, "RD_DROP_TABLE_DELAY", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_BEFORE_RD_DROP_TABLE_DELAY, OG_FALSE, "BEFORE_RD_DROP_TABLE_DELAY", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_DDL_ROLLBACK_DROP_GARBAGE_TABLE_FAIL, OG_FALSE, "ROLLBACK_DROP_GARBAGE_TABLE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_DELETE_GARBAGE_TABLE_4COMMIT_FAIL, OG_FALSE, "DELETE_GARBAGE_TABLE_4COMMIT_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_DELETE_GARBAGE_TABLE_4DROP_TABLE_FAIL, OG_FALSE, "DELETE_GARBAGE_TABLE_4DROP_TABLE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_TRUNCATE_TABLE_PRECHECK_FAIL, OG_FALSE, "TRUNCATE_TABLE_PRECHECK_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { OGRAC_DDL_TRUNCATE_TABLE_FAIL, OG_FALSE, "TRUNCATE_TABLE_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_KNL_COMMIT_DELAY, OG_FALSE, "KNL_COMMIT_DELAY", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_KNL_COMMIT_DELAY_ONCE, OG_FALSE, "KNL_COMMIT_DELAY_ONCE", 0, knl_syncpoint_inject_delay, 0 },
    { OGRAC_DDL_TABLE_BEFORE_COMMIT_ABORT, OG_FALSE, "DDL_TABLE_BEFORE_COMMIT_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_DDL_TABLE_AFTER_COMMIT_ABORT, OG_FALSE, "DDL_TABLE_AFTER_COMMIT_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_REFORM_BUILD_CHANNEL_DELAY, OG_FALSE, "OGRAC_REFORM_BUILD_CHANNEL_DELAY", 0, knl_syncpoint_inject_delay,
      0 },
    { OGRAC_REFORM_BUILD_CHANNEL_ABORT, OG_FALSE, "OGRAC_REFORM_BUILD_CHANNEL_ABORT", 0, knl_syncpoint_inject_abort,
      0 },
    { OGRAC_BACKUP_DBS_IOF_FAIL, OG_FALSE, "OGRAC_BACKUP_DBS_IOF_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { OGRAC_BACKUP_CORE_LOG_INFO_FAIL, OG_FALSE, "OGRAC_BACKUP_CORE_LOG_INFO_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { OGRAC_CKPT_CHECKSUM_VERIFY_FAIL, OG_FALSE, "OGRAC_CKPT_CHECKSUM_VERIFY_FAIL", 0, knl_syncpoint_inject_errcode,
      0 },
    { COLLECT_STATISTICS_CREATE_TEMP_TABLE_FAIL, OG_FALSE, "COLLECT_STATISTICS_CREATE_TEMP_TABLE_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { COLLECT_STATISTICS_COLLECT_SAMPLED_DATA_FAIL, OG_FALSE, "COLLECT_STATISTICS_COLLECT_SAMPLED_DATA_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { COLLECT_STATISTICS_ANALYZED_DATA_FAIL, OG_FALSE, "COLLECT_STATISTICS_ANALYZED_DATA_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
    { COLLECT_STATISTICS_INDEX_FAIL, OG_FALSE, "COLLECT_STATISTICS_INDEX_FAIL", 0, knl_syncpoint_inject_errcode, 0 },
    { COLLECT_STATISTICS_PERSISTENCE_THROUGH_RESULT_FAIL, OG_FALSE,
      "COLLECT_STATISTICS_PERSISTENCE_THROUGH_RESULT_FAIL", 0,  //
      knl_syncpoint_inject_errcode, 0 },
    { CTC_SQL_ALLOC_CONTEXT_FAIL, OG_FALSE, "CTC_SQL_ALLOC_CONTEXT_FAIL", 0,
      knl_syncpoint_inject_errcode, 0 },
};

#define KNL_SYNCPOINT_COUNT (sizeof(g_knl_syncpoint) / sizeof(g_knl_syncpoint[0]))

bool32 sp_get_global_syncpoint_flag(uint32 sp_id)
{
    if (sp_id >= KNL_SYNCPOINT_COUNT) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT]exec syncpoint error id:%u", sp_id);
        return OG_FALSE;
    }

    cm_spin_lock(&g_knl_syncpoint[sp_id].lock, NULL);
    bool32 ret = g_knl_syncpoint[sp_id].flag && g_knl_syncpoint[sp_id].count > 0;
    cm_spin_unlock(&g_knl_syncpoint[sp_id].lock);
    return ret;
}

status_t sp_exec_global_syncpoint(uint32 sp_id, int32 *user_param, int32 ret)
{
    if (sp_id >= KNL_SYNCPOINT_COUNT) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT]exec syncpoint error id:%u", sp_id);
        return OG_ERROR;
    }
    cm_spin_lock(&g_knl_syncpoint[sp_id].lock, NULL);
    if (!g_knl_syncpoint[sp_id].flag || g_knl_syncpoint[sp_id].count == 0) {
        cm_spin_unlock(&g_knl_syncpoint[sp_id].lock);
        return OG_SUCCESS;
    }
    OG_LOG_DEBUG_WAR("Execute syncpoint id:%u, name:%s.", sp_id, g_knl_syncpoint[sp_id].name);
    if (g_knl_syncpoint[sp_id].count > 0) {
        g_knl_syncpoint[sp_id].count--;
    }
    if (g_knl_syncpoint[sp_id].count == 0) {
        g_knl_syncpoint[sp_id].flag = OG_FALSE;
    }
    cm_spin_unlock(&g_knl_syncpoint[sp_id].lock);
    g_knl_syncpoint[sp_id].op(user_param, ret);
    return OG_SUCCESS;
}
status_t sp_set_global_syncpoint(syncpoint_def_t *syncpoint_def)
{
    uint32 inx = KNL_SYNCPOINT_COUNT;
    for (inx = 0; inx < KNL_SYNCPOINT_COUNT; inx++) {
        uint32 name_len = strlen(g_knl_syncpoint[inx].name);
        uint32 name_str_len = syncpoint_def->syncpoint_name.len;
        if (name_len == name_str_len &&
            !cm_strcmpni(syncpoint_def->syncpoint_name.str, g_knl_syncpoint[inx].name, name_len)) {
            break;
        }
    }
    if (inx == KNL_SYNCPOINT_COUNT) {
        OG_THROW_ERROR(ERR_OUT_OF_INDEX, "syncpoint not found", KNL_SYNCPOINT_COUNT);
        return OG_ERROR;
    }
    cm_spin_lock(&g_knl_syncpoint[inx].lock, NULL);
    if (!cm_strcmpni(syncpoint_def->enable.str, "enable", strlen("enable"))) {
        g_knl_syncpoint[inx].flag = OG_TRUE;
        g_knl_syncpoint[inx].count = syncpoint_def->raise_count;
    } else if (!cm_strcmpni(syncpoint_def->enable.str, "disable", strlen("disable"))) {
        g_knl_syncpoint[inx].flag = OG_FALSE;
        g_knl_syncpoint[inx].count = 0;
    } else {
        OG_LOG_DEBUG_ERR("[SYNCPOINT]add syncpoint name:%s, error enable str:%s", syncpoint_def->syncpoint_name.str,
                         syncpoint_def->enable.str);
        cm_spin_unlock(&g_knl_syncpoint[inx].lock);
        return OG_ERROR;
    }
    cm_spin_unlock(&g_knl_syncpoint[inx].lock);
    OG_LOG_DEBUG_INF("[SYNCPOINT] set syncpoint name:%s, raise_count:%u, enable:%s", syncpoint_def->syncpoint_name.str,
                     syncpoint_def->raise_count, syncpoint_def->enable.str);
    return OG_SUCCESS;
}

uint32 sp_get_global_syncpoint_count(uint32 sp_id)
{
    if (sp_id >= KNL_SYNCPOINT_COUNT) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT]exec syncpoint error id:%u", sp_id);
        return 0;
    }
    cm_spin_lock(&g_knl_syncpoint[sp_id].lock, NULL);
    uint32 ret = g_knl_syncpoint[sp_id].count;
    cm_spin_unlock(&g_knl_syncpoint[sp_id].lock);
    return ret;
}

const char *sp_get_global_syncpoint_name(uint32 sp_id)
{
    if (sp_id >= KNL_SYNCPOINT_COUNT) {
        OG_LOG_DEBUG_ERR("[SYNCPOINT]exec syncpoint error id:%u", sp_id);
        return "unknown";
    }

    return g_knl_syncpoint[sp_id].name;
}

uint32 sp_get_global_syncpoint_total_count(void)
{
    return KNL_SYNCPOINT_COUNT;
}

static uint32 sp_find_syncpoint(syncpoint_action_t *syncpoint_action, const char *name, bool32 *found)
{
    uint32 i = 0;
    uint32 num_active = syncpoint_action->active_syncpoint;
    syncpoint_def_t *def = NULL;

    for (; i < num_active; i++) {
        def = syncpoint_action->syncpoint_def + i;
        if (def->syncpoint_name.str[0] != '\0' && !strncmp(name, def->syncpoint_name.str, def->syncpoint_name.len)) {
            *found = OG_TRUE;
            return i;
        }
    }

    *found = OG_FALSE;
    return i;
}

static void sp_remove_syncpoint(syncpoint_action_t *syncpoint_action, uint32 index)
{
    errno_t err;
    syncpoint_def_t *tmp_def = syncpoint_action->syncpoint_def;
    char *dest = (char *)(tmp_def + index);
    char *src = (char *)(tmp_def + index + 1);

    /* the max number of syncpoint if 10, and sizeof(syncpoint_def_t) is 56, so it can be overflow */
    uint32 size = (OG_SESSION_MAX_SYNCPOINT - (index + 1)) * sizeof(syncpoint_def_t);
    uint32 dest_max = (OG_SESSION_MAX_SYNCPOINT - index) * sizeof(syncpoint_def_t);

    err = memmove_s(dest, dest_max, src, size);
    knl_securec_check(err);
    syncpoint_action->active_syncpoint--;
}

status_t sp_add_syncpoint(knl_handle_t knl_session, syncpoint_def_t *syncpoint_def)
{
    errno_t err;
    uint32 inx;
    bool32 found = OG_FALSE;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *)knl_session)->syncpoint_action;
    syncpoint_def_t *tmp_def = NULL;

    inx = sp_find_syncpoint(syncpoint_action, syncpoint_def->syncpoint_name.str, &found);
    if (INDEX_IS_INVALID(inx)) {
        OG_THROW_ERROR(ERR_OUT_OF_INDEX, "syncpoint for single session", OG_SESSION_MAX_SYNCPOINT);
        return OG_ERROR;
    }

    tmp_def = &syncpoint_action->syncpoint_def[inx];
    err = memcpy_sp(tmp_def, sizeof(syncpoint_def_t), syncpoint_def, sizeof(syncpoint_def_t));
    knl_securec_check(err);
    if (!found) {
        syncpoint_action->active_syncpoint++;
    }

    return OG_SUCCESS;
}

status_t sp_exec_syncpoint(knl_handle_t knl_session, const char *syncpoint_name)
{
    errno_t err;
    uint32 i;
    uint32 inx;
    uint32 count;
    bool32 found = OG_FALSE;
    bool32 wait_done = OG_FALSE;
    syncpoint_t *syncpoint = &((knl_session_t *)knl_session)->kernel->syncpoint;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *)knl_session)->syncpoint_action;
    syncpoint_def_t *tmp_def = NULL;

    inx = sp_find_syncpoint(syncpoint_action, syncpoint_name, &found);
    if (!found) {
        if (INDEX_IS_INVALID(inx)) {
            OG_THROW_ERROR(ERR_OUT_OF_INDEX, "syncpoint for single session", OG_SESSION_MAX_SYNCPOINT);
            return OG_ERROR;
        } else {
            return OG_SUCCESS;
        }
    }

    tmp_def = syncpoint_action->syncpoint_def + inx;
    if (tmp_def->signal.str != NULL) {
        count = tmp_def->raise_count;

        cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
        for (i = 0; i < count; i++) {
            /* the num_signal is less than OG_CONCURRENT_MAX_SYNCPOINT, so it can not cross array's border */
            err = strncpy_s(&syncpoint->signals[syncpoint->num_signal * OG_NAME_BUFFER_SIZE], OG_NAME_BUFFER_SIZE,
                            tmp_def->signal.str, tmp_def->signal.len);
            knl_securec_check(err);
            syncpoint->num_signal++;
        }
        cm_spin_unlock(&syncpoint->syncpoint_lock);
    }

    if (tmp_def->wait_for.str != NULL) {
        while (!wait_done) {
            cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
            count = syncpoint->num_signal;
            for (i = 0; i < count; i++) {
                if (!cm_strcmpni(tmp_def->wait_for.str, "abort", strlen("abort"))) {
                    CM_ABORT(0, "ABORT INFO: instance exit while doing syncpoint test");
                }

                /*
                 * i < count <= OG_CONCURRENT_MAX_SYNCPOINT,
                 * so it can not access the memory where cross the array's border
                 */
                if (!strncmp(tmp_def->wait_for.str, syncpoint->signals + (i * OG_NAME_BUFFER_SIZE),
                             tmp_def->wait_for.len)) {
                    char *dest = syncpoint->signals + (i * OG_NAME_BUFFER_SIZE);
                    char *src = syncpoint->signals + ((i + 1) * OG_NAME_BUFFER_SIZE);

                    /*
                     * OG_CONCURRENT_MAX_SYNCPOINT equal to 0x80, and OG_NAME_BUFFER_SIZE equal to 68,
                     * so it can be overflow
                     */
                    uint32 size = (OG_CONCURRENT_MAX_SYNCPOINT - (i + 1)) * OG_NAME_BUFFER_SIZE;
                    uint32 dest_max = (OG_CONCURRENT_MAX_SYNCPOINT - i) * OG_NAME_BUFFER_SIZE;

                    err = memmove_s(dest, dest_max, src, size);
                    knl_securec_check(err);
                    syncpoint->num_signal--;
                    wait_done = OG_TRUE;
                }
            }
            cm_spin_unlock(&syncpoint->syncpoint_lock);

            if (!wait_done) {
                cm_sleep(10);
            }
        }
    }

    sp_remove_syncpoint(syncpoint_action, inx);
    return OG_SUCCESS;
}

status_t sp_reset_syncpoint(knl_handle_t knl_session)
{
    errno_t err;
    syncpoint_t *syncpoint = &((knl_session_t *)knl_session)->kernel->syncpoint;

    cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
    err = memset_sp(syncpoint->signals, sizeof(syncpoint->signals), 0, sizeof(syncpoint->signals));
    knl_securec_check(err);
    syncpoint->num_signal = 0;
    cm_spin_unlock(&syncpoint->syncpoint_lock);
    return OG_SUCCESS;
}

void sp_clear_syncpoint_action(knl_handle_t knl_session)
{
    errno_t err;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *)knl_session)->syncpoint_action;
    uint32 syscpoint_size = sizeof(syncpoint_action_t);

    err = memset_sp(syncpoint_action, syscpoint_size, 0, syscpoint_size);
    knl_securec_check(err);
}
#endif /* DB_DEBUG_VERSION */

#ifdef __cplusplus
}
#endif
