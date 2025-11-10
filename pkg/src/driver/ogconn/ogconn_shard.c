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
 * ogconn_shard.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogconn/ogconn_shard.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogconn_shard.h"
#include "ogconn_stmt.h"
#include "ogconn_fetch.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OG_RAC_ING
status_t ogconn_fetch_raw(ogconn_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    return clt_remote_fetch(stmt);
}

status_t ogconn_fetch_data(ogconn_stmt_t pstmt, uint32 *rows)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    OGCONN_CHECK_FETCH_STATUS(stmt);

    stmt->status = CLI_STMT_FETCHING;

    if (stmt->row_index < stmt->return_rows) {
        *rows = stmt->return_rows;
        stmt->row_index = stmt->return_rows;
        return OG_SUCCESS;
    }

    if (stmt->more_rows) {
        OG_RETURN_IFERR(clt_remote_fetch(stmt));
    } else {
        *rows = 0;
        return OG_SUCCESS;
    }

    if (stmt->eof) {
        *rows = 0;
        return OG_SUCCESS;
    }

    *rows = stmt->return_rows;
    stmt->row_index = stmt->return_rows;
    return OG_SUCCESS;
}

status_t ogconn_fetch_data_ack(ogconn_stmt_t pstmt, char **data, uint32 *size)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");

    *data = CS_READ_ADDR(&stmt->cache_pack->pack);
    *size = stmt->cache_pack->pack.head->size - stmt->cache_pack->pack.offset;
    return OG_SUCCESS;
}

status_t ogconn_fetch_data_attr_ack(ogconn_stmt_t pstmt, uint32 *options, uint32 *return_rows)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    if (stmt == NULL) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        return OG_ERROR;
    }
    *options = stmt->cache_pack->pack.options;
    *return_rows = stmt->return_rows;
    return OG_SUCCESS;
}

static status_t clt_realloc_batch_buf(clt_stmt_t *clt_stmt, uint32 expect_size)
{
    uint32 buf_used = (uint32)(clt_stmt->batch_curr_ptr - clt_stmt->batch_bnd_ptr);
    errno_t errcode;

    if (buf_used + expect_size > clt_stmt->max_batch_buf_size) {
        uint32 new_buf_size = buf_used + (expect_size / SIZE_K(8) + 1) * SIZE_K(8); // expand buf memory in units of 8K
        if (new_buf_size == 0) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "batch operation");
            return OG_ERROR;
        }

        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "batch operation");
            return OG_ERROR;
        }
        if (buf_used != 0) {
            errcode = memcpy_s(new_buf, new_buf_size, clt_stmt->batch_bnd_ptr, buf_used);
            if (errcode != EOK) {
                CM_FREE_PTR(new_buf);
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return OG_ERROR;
            }
        }

        CM_FREE_PTR(clt_stmt->batch_bnd_ptr);
        clt_stmt->batch_bnd_ptr = new_buf;
        clt_stmt->batch_curr_ptr = clt_stmt->batch_bnd_ptr + buf_used;
        clt_stmt->max_batch_buf_size = new_buf_size;
    }

    return OG_SUCCESS;
}

status_t ogconn_init_paramset_length(ogconn_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");

    OG_RETURN_IFERR(clt_realloc_batch_buf(stmt, sizeof(uint32)));

    // a row format: total_len(4bytes) + [cs_param_head_t + value] + ... + [cs_param_head_t + value]
    stmt->paramset_len_offset = (uint32)(stmt->batch_curr_ptr - stmt->batch_bnd_ptr);
    *((uint32 *)stmt->batch_curr_ptr) = sizeof(uint32); // total length when put_param
    stmt->batch_curr_ptr += sizeof(uint32);

    return OG_SUCCESS;
}

#define PARAMSET_LENGTH_ADD(stmt, value) *(uint32 *)((stmt)->batch_bnd_ptr + (stmt)->paramset_len_offset) += (value)

status_t ogconn_bind_by_pos_batch(ogconn_stmt_t pstmt, uint32 pos, int32 type, const void *data, uint32 size, bool32
    is_null)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");

    if (stmt->status != CLI_STMT_PRE_PARAMS) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_API_SEQUENCE, "sql is not in preprocess params for batch");
        return OG_ERROR;
    }

    if (pos >= stmt->param_count) {
        CLT_THROW_ERROR(stmt->conn, ERR_CLT_OUT_OF_INDEX, "parameter");
        return OG_ERROR;
    }

    PARAMSET_LENGTH_ADD(stmt, sizeof(cs_param_head_t));
    PARAMSET_LENGTH_ADD(stmt, CM_ALIGN4(size));

    OG_RETURN_IFERR(clt_realloc_batch_buf(stmt, sizeof(cs_packet_head_t) + size));

    cs_param_head_t *head = (cs_param_head_t *)stmt->batch_curr_ptr;
    stmt->batch_curr_ptr += sizeof(cs_param_head_t);

    // Hint : this head->len is different with clt_put_param
    head->len = size;
    head->type = type;
    head->flag = 0;
    clt_set_param_direction(OGCONN_INPUT, &head->flag);

    if (is_null == OG_TRUE) {
        head->flag |= 0x01;
    } else {
        // copy the data...
        if (size != 0) {
            MEMS_RETURN_IFERR(memcpy_s(stmt->batch_curr_ptr, size, data, size));
        }
        // add a terminator '\0' for string
        if (type == OGCONN_TYPE_STRING || type == OGCONN_TYPE_VARCHAR || type == OGCONN_TYPE_CHAR) {
            stmt->batch_curr_ptr[size - 1] = '\0';
        }
        stmt->batch_curr_ptr += size;
    }

    return OG_SUCCESS;
}

// DML for CN bind params to DN
status_t ogconn_init_params(ogconn_stmt_t pstmt, uint32 param_count, bool32 is_batch)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");

    stmt->paramset_size = 0;
    stmt->param_count = param_count;

    if (is_batch == OG_TRUE) {
        // if not point to an available buffer (default buffer or dynamicly extended buffer) already.
        // use the default buffer.
        if (stmt->batch_bnd_ptr == NULL) {
            stmt->batch_bnd_ptr = (char *)malloc(OG_MAX_PACKET_SIZE);
            if (stmt->batch_bnd_ptr == NULL) {
                OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)OG_MAX_PACKET_SIZE, "batch bind parameters");
                return OG_ERROR;
            }
            stmt->max_batch_buf_size = OG_MAX_PACKET_SIZE;
        }
    } else {
        // free the dynamicly extended buffer
        CM_FREE_PTR(stmt->batch_bnd_ptr);
        stmt->max_batch_buf_size = 0;
    }

    stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
    stmt->paramset_len_offset = 0;

    // in case of (SQL + parameters) large than OG_MAX_PACKET_SIZE
    stmt->offset = 0;
    stmt->can_read_ack = OG_FALSE;

    cm_destroy_list(&stmt->batch_errs.err_list);
    stmt->batch_errs.actual_count = 0;
    stmt->batch_errs.allowed_count = 0;

    if (stmt->param_count == 0) {
        return OG_SUCCESS;
    }

    // beacuse of stmt reuse. maybe stmt->params has no enough space.
    if (stmt->params.count < stmt->param_count) {
        OG_RETURN_IFERR(clt_extend_param_list(stmt, stmt->param_count));
    }

    // for batch operation, this initialize of clt_param is useless.
    clt_param_t *param = NULL;
    for (uint32 i = 0; i < stmt->param_count; i++) {
        param = (clt_param_t *)cm_list_get(&stmt->params, i);
        param->bnd_ptr = NULL;
        param->ind_ptr = NULL;
        param->bnd_type = OGCONN_TYPE_INTEGER;
        param->bnd_size = 0;
        CM_FREE_PTR(param->lob_ptr);
        param->lob_ptr_size = 0;
    }

    stmt->status = CLI_STMT_PRE_PARAMS;

    return OG_SUCCESS;
}

void ogconn_paramset_size_inc(ogconn_stmt_t pstmt)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    stmt->paramset_size++;
}

status_t ogconn_pe_prepare(ogconn_stmt_t pstmt, const char *sql, uint64 *scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    uint32 req_offset;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, sql, "sql");

    req_pack = &stmt->conn->pack;

    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_PREP_AND_EXEC;

    OG_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_prepare_req_t), &req_offset));
    stmt->req = (cs_prepare_req_t *)CS_RESERVE_ADDR(req_pack, req_offset);
    stmt->req->flags = 0;
    stmt->req->stmt_id = stmt->stmt_id;
    cs_putted_prepare_req(req_pack, req_offset);
    if (stmt->conn->call_version >= CS_VERSION_11) {
        OG_RETURN_IFERR(cs_put_alter_set(req_pack, stmt));
    }

    /* strong consistency */
    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        OG_RETURN_IFERR(cs_put_scn(req_pack, scn));
    }

    if (stmt->conn->call_version >= CS_VERSION_17) {
        stmt->req->flags |= CS_CN_DML_ID;
        OG_RETURN_IFERR(cs_put_int32(req_pack, stmt->shard_dml_id));
    }

    text_t text;
    text.str = (char *)sql;
    text.len = (uint32)strlen(sql);
    OG_RETURN_IFERR(cs_put_text(req_pack, &text));

    if (stmt->status != CLI_STMT_PRE_PARAMS) {
        stmt->param_count = 0;
    }

    stmt->status = CLI_STMT_PREPARED;
    return OG_SUCCESS;
}

status_t ogconn_pe_async_execute(ogconn_stmt_t pstmt, uint32 *more_param)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_prep_exec_param *exe_param = NULL;
    uint32 exe_param_offset;
    bool32 add_types = OG_TRUE;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    OG_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    if (clt_has_large_string(stmt)) {
        /* string to lob bind type column data will be writed to server here */
        OG_RETURN_IFERR(clt_write_large_string(stmt));
        if (stmt->req != NULL && stmt->stmt_id != OG_INVALID_ID16) {
            stmt->req->stmt_id = stmt->stmt_id;
        }
    }

    req_pack = &stmt->conn->pack;

    *more_param = OG_FALSE;

    OG_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_prep_exec_param), &exe_param_offset));
    exe_param = (cs_prep_exec_param *)CS_RESERVE_ADDR(req_pack, exe_param_offset);
    OGCONN_INIT_PREP_EXEC_PARAM(exe_param, stmt);

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= OG_FLAG_ALLOWED_BATCH_ERRS;
        OG_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    while (stmt->offset < stmt->paramset_size) {
        // Hint: at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 1. the package cat store at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 2. for batch operation, if it satisfy 1, split the batch parameter set;
        // only for batch operation;
        if (stmt->batch_bnd_ptr != NULL) {
            if (stmt->offset == 0) {
                stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
            }

            // the maximal binding size of a row
            uint32 max_row_bndsz =
                *((uint32 *)stmt->batch_curr_ptr) + (sizeof(cs_param_head_t) + sizeof(int32)) * stmt->param_count;
            // at least one row;
            if (CM_REALLOC_SEND_PACK_SIZE(req_pack, max_row_bndsz) > req_pack->max_buf_size && stmt->offset != 0) {
                *more_param = OG_TRUE;
                break;
            }
            stmt->batch_curr_ptr += sizeof(uint32);
        }

        if (clt_put_params(stmt, stmt->offset, add_types) != OG_SUCCESS) {
            clt_copy_local_error(stmt->conn);
            return OG_ERROR;
        }
        add_types = OG_FALSE;
        /* after "clt_put_params" exe_param should be refresh by "CS_RESERVE_ADDR" */
        exe_param = (cs_prep_exec_param *)CS_RESERVE_ADDR(req_pack, exe_param_offset);
        exe_param->paramset_size++;
        stmt->offset++;
    }

    CS_SERIAL_NUMBER_INC(stmt->conn, req_pack);
    if (cs_write(&stmt->conn->pipe, req_pack) != OG_SUCCESS) {
        clt_copy_local_error(stmt->conn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogconn_pe_async_execute_ack(ogconn_stmt_t pstmt, const char *sql, uint64 *ack_scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *ack_pack = NULL;
    text_t sql_text;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    OGCONN_CHECK_OBJECT_NULL_CLT(stmt->conn, sql, "sql");

    sql_text.str = (char *)sql;
    sql_text.len = (uint32)strlen(sql);

    OG_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    ack_pack = &stmt->cache_pack->pack;
    OG_RETURN_IFERR(clt_async_get_ack(stmt->conn, ack_pack));

    cs_init_get(ack_pack);
    OG_RETURN_IFERR(clt_get_prepare_ack(stmt, ack_pack, &sql_text));
    OG_RETURN_IFERR(clt_get_execute_ack(stmt));

    if (CS_XACT_WITH_TS(ack_pack->head->flags)) {
        if (ack_scn == NULL) {
            return OG_ERROR;
        }
        *ack_scn = stmt->scn;
    }

    stmt->status = CLI_STMT_EXECUTED;
    return OG_SUCCESS;
}

status_t ogconn_async_execute(ogconn_stmt_t pstmt, bool32 *more_param, uint64 *scn)
{
    cs_packet_t *req_pack = NULL;
    cs_execute_req_t *exec_req = NULL;
    uint32 exec_req_offset;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    bool32 add_types = OG_TRUE;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;

    *more_param = OG_FALSE;

    // 1. no param -- request
    // 2. no more param -- no request
    // for the splitting package from CN to DN
    if (stmt->offset == stmt->paramset_size && stmt->offset != 0) {
        // done , all paramsets' request has handled
        stmt->can_read_ack = OG_FALSE;
        return OG_SUCCESS;
    }

    cs_init_set(req_pack, stmt->conn->call_version);
    CS_SERIAL_NUMBER_INC(stmt->conn, req_pack);
    req_pack->head->cmd = CS_CMD_EXECUTE;
    req_pack->head->result = 0;
    req_pack->head->flags = 0;

    /* strong consistency */
    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        OG_RETURN_IFERR(cs_put_scn(req_pack, scn));
    }

    OG_RETURN_IFERR(cs_reserve_space(req_pack, sizeof(cs_execute_req_t), &exec_req_offset));
    exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
    exec_req->stmt_id = stmt->stmt_id;
    exec_req->paramset_size = 0;
    exec_req->prefetch_rows = clt_prefetch_rows(stmt);
    exec_req->auto_commit = stmt->conn->auto_commit;
    exec_req->reserved = 0;

    if (stmt->batch_errs.allowed_count > 0) {
        req_pack->head->flags |= OG_FLAG_ALLOWED_BATCH_ERRS;
        OG_RETURN_IFERR(cs_put_int32(req_pack, stmt->batch_errs.allowed_count));
    }

    uint32 send_count = 0;
    while (stmt->offset < stmt->paramset_size) {
        // Hint: at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 1. the package cat store at least one parameter-set with a SQ statementL; SQL + 1 parameter
        // / 2. for batch operation, if it satisfy 1, split the batch parameter set;
        // only for batch operation;
        if (stmt->batch_bnd_ptr != NULL) {
            /* format
            paramset :  | paramset_length (uint32) | param_info_1 | param_info_2 | ... | param_info_n |
            param_info: | cs_param_head_t | param_value (string contains terminator '\0') |
            */
            if (stmt->offset == 0) {
                stmt->batch_curr_ptr = stmt->batch_bnd_ptr;
            }

            // the maximal binding size of a row
            uint32 max_row_bndsz =
                *((uint32 *)stmt->batch_curr_ptr) + (sizeof(cs_param_head_t) + sizeof(int32)) * stmt->param_count;
            // at least one row
            if (send_count != 0 && CM_REALLOC_SEND_PACK_SIZE(req_pack, max_row_bndsz) > req_pack->max_buf_size) {
                *more_param = OG_TRUE;
                break;
            }
            stmt->batch_curr_ptr += sizeof(uint32);
        }

        OG_RETURN_IFERR(clt_put_params(stmt, stmt->offset, add_types));
        add_types = OG_FALSE;

        /* after "clt_put_params" exec_req should be refresh by "CS_RESERVE_ADDR" */
        exec_req = (cs_execute_req_t *)CS_RESERVE_ADDR(req_pack, exec_req_offset);
        exec_req->paramset_size++;
        stmt->offset++;
        send_count++;
    }

    cs_putted_execute_req(req_pack, exec_req_offset);

    if (cs_write(&stmt->conn->pipe, req_pack) != OG_SUCCESS) {
        clt_copy_local_error(stmt->conn);
        return OG_ERROR;
    }

    stmt->can_read_ack = OG_TRUE;

    return OG_SUCCESS;
}

status_t ogconn_async_execute_ack(ogconn_stmt_t pstmt, uint64 *ack_scn)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    OG_RETURN_IFERR(clt_prepare_stmt_pack(stmt));
    ack_pack = &stmt->cache_pack->pack;

    if (!stmt->can_read_ack) {
        stmt->affected_rows = 0;
        return OG_SUCCESS;
    }
    // reset the flag before read ack;
    stmt->can_read_ack = OG_FALSE;

    OG_RETURN_IFERR(clt_async_get_ack(stmt->conn, ack_pack));

    cs_init_get(ack_pack);
    OG_RETURN_IFERR(clt_get_execute_ack(stmt));

    if (CS_XACT_WITH_TS(ack_pack->head->flags)) {
        if (ack_scn == NULL) {
            return OG_ERROR;
        }
        *ack_scn = stmt->scn;
    }

    stmt->status = CLI_STMT_EXECUTED;
    return OG_SUCCESS;
}

static status_t send_cmd(ogconn_conn_t pconn, uint8 cmd)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = cmd;
    CS_SERIAL_NUMBER_INC(conn, req_pack);

    if (cs_write(&conn->pipe, req_pack) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogconn_async_commit(ogconn_conn_t pconn)
{
    return send_cmd(pconn, CS_CMD_COMMIT);
}

status_t ogconn_async_commit_ack(ogconn_conn_t pconn)
{
    return clt_async_get_ack((clt_conn_t *)pconn, &((clt_conn_t *)pconn)->pack);
}

status_t ogconn_async_rollback(ogconn_conn_t pconn)
{
    return send_cmd(pconn, CS_CMD_ROLLBACK);
}

status_t ogconn_async_rollback_ack(ogconn_conn_t pconn)
{
    return clt_async_get_ack((clt_conn_t *)pconn, &((clt_conn_t *)pconn)->pack);
}

status_t ogconn_statement_rollback(ogconn_conn_t pconn, uint32 dml_id)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    ack_pack = &conn->pack;
    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_STMT_ROLLBACK;

    OG_RETURN_IFERR(cs_put_int32(req_pack, dml_id));

    return clt_remote_call(conn, req_pack, ack_pack);
}

status_t ogconn_gts(ogconn_conn_t pconn, uint64 *scn)
{
    clt_conn_t *conn = (clt_conn_t *)pconn;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_GTS;
    OG_RETURN_IFERR(clt_remote_call(conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    return cs_get_scn(ack_pack, scn);
}

status_t ogconn_shard_prepare(ogconn_stmt_t pstmt, const char *sql)
{
    return ogconn_prepare(pstmt, sql);
}

status_t ogconn_shard_execute(ogconn_stmt_t pstmt)
{
    return ogconn_execute(pstmt);
}

status_t ogconn_fetch_sequence(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, ogconn_sequence_t *ogconn_seq)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    OG_RETURN_IFERR(cs_put_int32(req_pack, SEQ_FETCH_CACHE));
    OG_RETURN_IFERR(cs_put_text(req_pack, user));
    OG_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    OG_RETURN_IFERR(cs_put_int32(req_pack, ogconn_seq->group_order));
    OG_RETURN_IFERR(cs_put_int32(req_pack, ogconn_seq->group_cnt));
    OG_RETURN_IFERR(cs_put_int32(req_pack, ogconn_seq->size));

    OG_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    OG_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&ogconn_seq->start_val));
    OG_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&ogconn_seq->step));
    OG_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)&ogconn_seq->end_val));

    return OG_SUCCESS;
}

status_t ogconn_set_sequence_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 currval)
{
    status_t status = OG_SUCCESS;
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");
    OG_RETURN_IFERR(clt_lock_conn(stmt->conn));

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    do {
        status = cs_put_int32(req_pack, SEQ_SET_NEXTVAL);
        OG_BREAK_IF_ERROR(status);

        status = cs_put_text(req_pack, user);
        OG_BREAK_IF_ERROR(status);

        status = cs_put_text(req_pack, seq_name);
        OG_BREAK_IF_ERROR(status);

        status = cs_put_int64(req_pack, currval);
        OG_BREAK_IF_ERROR(status);
    } while (0);

    if (status != OG_SUCCESS) {
        clt_unlock_conn(stmt->conn);
        return OG_ERROR;
    }

    status = clt_remote_call(stmt->conn, req_pack, ack_pack);
    clt_unlock_conn(stmt->conn);
    return status;
}

status_t ogconn_get_sequence_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, int64 *value)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    OG_RETURN_IFERR(cs_put_int32(req_pack, SEQ_GET_NEXTVAL));
    OG_RETURN_IFERR(cs_put_text(req_pack, user));
    OG_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    OG_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    OG_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)value));

    return OG_SUCCESS;
}

status_t ogconn_get_cn_nextval(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name, bool32 *empty_cache, int64 *value)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    OG_RETURN_IFERR(cs_put_int32(req_pack, SEQ_GET_CN_NEXTVAL));
    OG_RETURN_IFERR(cs_put_text(req_pack, user));
    OG_RETURN_IFERR(cs_put_text(req_pack, seq_name));
    OG_RETURN_IFERR(clt_remote_call(stmt->conn, req_pack, ack_pack));

    cs_init_get(ack_pack);
    OG_RETURN_IFERR(cs_get_int32(ack_pack, (int32 *)empty_cache));
    OG_RETURN_IFERR(cs_get_int64(ack_pack, (int64 *)value));
    return OG_SUCCESS;
}

status_t ogconn_notify_cn_update_cache(ogconn_stmt_t pstmt, text_t *user, text_t *seq_name)
{
    clt_stmt_t *stmt = (clt_stmt_t *)pstmt;
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;

    OGCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    OGCONN_CHECK_OBJECT_NULL_GS(stmt->conn, "connection");

    req_pack = &stmt->conn->pack;
    ack_pack = &stmt->conn->pack;
    cs_init_set(req_pack, stmt->conn->call_version);
    req_pack->head->cmd = CS_CMD_SEQUENCE;

    OG_RETURN_IFERR(cs_put_int32(req_pack, SEQ_ALTER_NOTIFY));
    OG_RETURN_IFERR(cs_put_text(req_pack, user));
    OG_RETURN_IFERR(cs_put_text(req_pack, seq_name));

    return clt_remote_call(stmt->conn, req_pack, ack_pack);
}

static status_t ogconn_decode_scn(clt_conn_t *conn, cs_packet_t *ack_pack, uint64 *scn)
{
    if (!CS_XACT_WITH_TS(ack_pack->head->flags)) {
        return OG_SUCCESS;
    }

    if (scn == NULL) {
        return OG_ERROR;
    }

    cs_init_get(ack_pack);
    return cs_get_scn(ack_pack, scn);
}

static status_t ogconn_commit_with_ts_core(clt_conn_t *conn, uint64 *scn)
{
    cs_packet_t *req_pack = NULL;
    cs_packet_t *ack_pack = NULL;
    req_pack = &conn->pack;
    ack_pack = &conn->pack;

    cs_init_set(req_pack, conn->call_version);
    req_pack->head->cmd = CS_CMD_COMMIT;

    if (scn != NULL) {
        req_pack->head->flags |= CS_FLAG_WITH_TS;
        OG_RETURN_IFERR(cs_put_scn(req_pack, scn));
    } else {
        OG_BIT_RESET(req_pack->head->flags, CS_FLAG_WITH_TS);
    }

    if (clt_remote_call(conn, req_pack, ack_pack) != OG_SUCCESS) {
        clt_copy_local_error(conn);
        return OG_ERROR;
    }

    return ogconn_decode_scn(conn, ack_pack, scn);
}

status_t ogconn_commit_with_ts(ogconn_conn_t pconn, uint64 *scn)
{
    status_t status;
    clt_conn_t *conn = (clt_conn_t *)pconn;

    OGCONN_CHECK_OBJECT_NULL_GS(conn, "connection");

    OG_RETURN_IFERR(clt_lock_conn(conn));
    status = ogconn_commit_with_ts_core(conn, scn);
    clt_unlock_conn(conn);
    return status;
}

int32 ogconn_set_pipe_timeout(ogconn_conn_t conn, uint32 timeout)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    uint32 timeout_ms;
    if (opr_uint32mul_overflow(timeout, OG_TIME_THOUSAND_UN, &timeout_ms) || timeout_ms > OG_MAX_INT32) {
        CLT_THROW_ERROR(clt_conn, ERR_CLT_INVALID_VALUE, "socket timeout value", timeout);
        return OG_ERROR;
    }

    clt_conn->pipe.socket_timeout = (timeout_ms == 0) ? (-1) : ((int32)timeout_ms);
    return OG_SUCCESS;
}

void ogconn_reset_pipe_timeout(ogconn_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    int32 origin = clt_conn->options.socket_timeout;
    clt_conn->pipe.socket_timeout = (origin == -1) ? origin : origin * OG_TIME_THOUSAND;
}

void ogconn_force_close_pipe(ogconn_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    cs_disconnect(&clt_conn->pipe);
}

void ogconn_shutdown_pipe(ogconn_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    cs_shutdown(&clt_conn->pipe);
}

cli_db_role_t ogconn_get_db_role(ogconn_conn_t conn)
{
    clt_conn_t *clt_conn = (clt_conn_t *)conn;
    return clt_conn->server_info.db_role;
}

#endif

#ifdef __cplusplus
}
#endif
