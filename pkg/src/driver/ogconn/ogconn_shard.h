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
* ogconn_shard.h
*
*
* IDENTIFICATION
* src/driver/ogconn/ogconn_shard.h
*
* -------------------------------------------------------------------------
*/
#ifndef __CTCONN_SHARD_H__
#define __CTCONN_SHARD_H__

#include "cm_text.h"
#include "ogconn_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32 ogconn_fetch_raw(ogconn_stmt_t pstmt);

int32 ogconn_fetch_data(ogconn_stmt_t pstmt, uint32 *rows);
int32 ogconn_fetch_data_ack(ogconn_stmt_t pstmt, char **data, uint32 *size);
int32 ogconn_fetch_data_attr_ack(ogconn_stmt_t pstmt, uint32 *options, uint32 *return_rows);

int32 ogconn_init_paramset_length(ogconn_stmt_t pstmt);
int32 ogconn_bind_by_pos_batch(ogconn_stmt_t pstmt, uint32 pos, int32 type, const void *data, uint32 size, bool32
    is_null);
int32 ogconn_init_params(ogconn_stmt_t pstmt, uint32 param_count, bool32 is_batch);
void ogconn_paramset_size_inc(ogconn_stmt_t pstmt);

int32 ogconn_pe_prepare(ogconn_stmt_t pstmt, const char *sql, uint64 *scn);
int32 ogconn_pe_async_execute(ogconn_stmt_t pstmt, uint32 *more_param);
int32 ogconn_pe_async_execute_ack(ogconn_stmt_t pstmt, const char *sql, uint64 *ack_scn);
int32 ogconn_async_execute(ogconn_stmt_t pstmt, bool32 *more_param, uint64 *scn);
int32 ogconn_async_execute_ack(ogconn_stmt_t pstmt, uint64 *ack_scn);

int32 ogconn_async_commit(ogconn_conn_t pconn);
int32 ogconn_async_commit_ack(ogconn_conn_t pconn);
int32 ogconn_async_rollback(ogconn_conn_t pconn);
int32 ogconn_async_rollback_ack(ogconn_conn_t pconn);

int32 ogconn_async_xa_rollback(ogconn_conn_t conn, const text_t *xid, uint64 flags);
int32 ogconn_async_xa_prepare(ogconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 ogconn_async_xa_commit(ogconn_conn_t conn, const text_t *xid, uint64 flags, uint64 *scn);
int32 ogconn_async_xa_rollback_ack(ogconn_conn_t conn);
int32 ogconn_async_xa_prepare_ack(ogconn_conn_t conn, uint64 *ack_scn);
int32 ogconn_async_xa_commit_ack(ogconn_conn_t conn, uint64 *ack_scn);

int32 ogconn_statement_rollback(ogconn_conn_t pconn, uint32 dml_id);
int32 ogconn_gts(ogconn_conn_t pconn, uint64 *scn);

int32 ogconn_shard_prepare(ogconn_stmt_t pstmt, const char *sql);
int32 ogconn_shard_execute(ogconn_stmt_t pstmt);

int32 ogconn_fetch_sequence(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, ogconn_sequence_t *ogconn_seq);
int32 ogconn_set_sequence_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 currval);
int32 ogconn_get_sequence_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 *value);
int32 ogconn_get_cn_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, bool32 *empty_cache, int64 *value);
int32 ogconn_notify_cn_update_cache(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name);

/*
    Definition: Single shard transaction commit
    Incoming parameter:
        conn: connection object
        time_stamp: cn delivers the timestamp, the ordinary transaction time_stamp is NULL, and the single shard is the
   CN timestamp. return value: Description: Single shard transaction commit, CN and DN do clock synchronization, common
   transaction commit is equivalent to ogconn_rollback
*/
int32 ogconn_commit_with_ts(ogconn_conn_t pconn, uint64 *scn);

int32 ogconn_set_pipe_timeout(ogconn_conn_t conn, uint32 timeout);
void ogconn_reset_pipe_timeout(ogconn_conn_t conn);
void ogconn_force_close_pipe(ogconn_conn_t conn);
void ogconn_shutdown_pipe(ogconn_conn_t conn);
cli_db_role_t ogconn_get_db_role(ogconn_conn_t conn);

#define OGCONN_INIT_PREP_EXEC_PARAM(_exe_param, _stmt)               \
    do {                                                          \
        (_exe_param)->paramset_size = 0;                          \
        (_exe_param)->prefetch_rows = (_stmt)->prefetch_rows;     \
        (_exe_param)->auto_commit = ((_stmt)->conn->auto_commit); \
        (_exe_param)->reserved[0] = 0;                            \
        (_exe_param)->reserved[1] = 0;                            \
        (_exe_param)->reserved[2] = 0;                            \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
