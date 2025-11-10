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
 * ogsql_service.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/ogsql_service.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_list.h"
#include "cs_protocol.h"
#include "srv_session.h"
#include "srv_instance.h"
#include "dml_executor.h"
#include "ogsql_parser.h"
#include "cm_array.h"
#include "cm_nls.h"
#include "cm_file.h"
#include "cs_protocol.h"
#include "ogsql_privilege.h"
#ifndef WIN32
#include "sys/wait.h"
#define LOAD_RET_FD_SIZE 2
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CHECK_SRC_LEN_VALID(buf, result)                                                         \
    do {                                                                                         \
        if ((strlen(result) + strlen(buf) + 1) > OG_MAX_STRING_LEN) {                            \
            OG_LOG_DEBUG_ERR("[load data local] the lenght of dest is less than length of src"); \
            break;                                                                               \
        }                                                                                        \
    } while (0)

status_t sql_get_stmt(session_t *session, uint32 stmt_id)
{
    if (stmt_id >= session->stmts.count) {
        OG_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return OG_ERROR;
    }

    session->current_stmt = (sql_stmt_t *)cm_list_get(&session->stmts, stmt_id);
    if (session->current_stmt == NULL || session->current_stmt->status == STMT_STATUS_FREE) {
        OG_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_alloc_for_longsql_stat(session->current_stmt));

    array_set_handle((void *)&session->knl_session, session->knl_session.temp_mtrl->pool,
        (void *)session->knl_session.stack);
    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_free_stmt(session_t *session)
{
    uint16 stmt_id = 0;
    session->sql_audit.action = SQL_AUDIT_ACTION_FREE_STMT;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    OG_RETURN_IFERR(cs_get_int16(session->recv_pack, (int16 *)&stmt_id));

    if (stmt_id == OG_INVALID_ID16 || sql_get_stmt(session, stmt_id) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_STATEMENT_ID, stmt_id);
        return OG_ERROR;
    }

    sql_free_stmt(session->current_stmt);
    return OG_SUCCESS;
}

static inline status_t sql_try_send_pl_warning(sql_stmt_t *stmt)
{
    const char *err_msg = NULL;
    int32 err_code;

    if (!stmt->pl_failed) {
        return OG_SUCCESS;
    }

    cm_get_error(&err_code, &err_msg, NULL);

    if (err_msg[0] == '\0') {
        return OG_SUCCESS;
    }

    return cs_put_err_msg(stmt->session->send_pack, stmt->session->call_version, err_msg);
}

static status_t sql_process_direct_route_info(sql_stmt_t *stmt)
{
    cs_packet_t *recv_pack = stmt->session->recv_pack;
    if (recv_pack->head->flags & OG_FLAG_CN_USE_ROUTE) {
        if (!(IS_COORDINATOR && IS_APP_CONN(stmt->session))) {
            OG_THROW_ERROR(ERR_INVALID_PROTOCOL_INVOKE, "useRoute can only be used in cn direct route scenarios");
            return OG_ERROR;
        }

        text_t route_sql;
        source_location_t loc = { .line = 1, .column = 1 };
        OG_RETURN_IFERR(cs_get_text(recv_pack, &route_sql));
        if (route_sql.len == 0) {
            return OG_SUCCESS;
        }

        sql_release_resource(stmt, OG_TRUE);
        sql_release_context(stmt);
        // sql_release_sql_map(stmt);

        uint16 save_status = stmt->status;
        stmt->status = STMT_STATUS_IDLE;
        stmt->session->sql_audit.packet_sql = route_sql;
        OG_RETURN_IFERR(sql_parse(stmt, &route_sql, &loc));
        stmt->status = STMT_STATUS_PREPARED;
        OG_RETURN_IFERR(sql_execute(stmt));
        stmt->status = save_status;
    }

    return OG_SUCCESS;
}

static status_t sql_process_alter_set_nls_param(session_t *session, nlsparams_t *nls_params, nlsparam_id_t param_id)
{
    if (nls_params->nlsvalues[param_id].len > 0 &&
        strcmp(nls_params->nlsvalues[param_id].str, session->nls_params.nlsvalues[param_id].str) != 0) {
        MEMS_RETURN_IFERR(strcpy_s(session->nls_params.nlsvalues[param_id].str, MAX_NLS_PARAM_LENGTH,
                                   nls_params->nlsvalues[param_id].str));
        session->nls_params.nlsvalues[param_id].len = nls_params->nlsvalues[param_id].len;
    }
    return OG_SUCCESS;
}

static status_t sql_process_alter_set_nls_params(session_t *session, nlsparams_t *nls_params)
{
    OG_RETURN_IFERR(sql_process_alter_set_nls_param(session, nls_params, NLS_DATE_FORMAT));
    OG_RETURN_IFERR(sql_process_alter_set_nls_param(session, nls_params, NLS_TIMESTAMP_FORMAT));
    OG_RETURN_IFERR(sql_process_alter_set_nls_param(session, nls_params, NLS_TIMESTAMP_TZ_FORMAT));
    OG_RETURN_IFERR(sql_process_alter_set_nls_param(session, nls_params, NLS_TIME_FORMAT));
    OG_RETURN_IFERR(sql_process_alter_set_nls_param(session, nls_params, NLS_TIME_TZ_FORMAT));

    if (nls_params->client_timezone != TIMEZONE_OFFSET_INVALIDVALUE &&
        nls_params->client_timezone != session->nls_params.client_timezone) {
        session->nls_params.client_timezone = nls_params->client_timezone;
    }
    return OG_SUCCESS;
}

static status_t sql_process_alter_set_core(session_t *session, alter_set_info_t *alter_info, nlsparams_t *nls_params)
{
    text_t curr_schema;
    text_t curr_user;
    if ((uint16)alter_info->commit_batch != OG_INVALID_ID16 &&
        alter_info->commit_batch != session->knl_session.commit_batch) {
        session->knl_session.commit_batch = (bool8)alter_info->commit_batch;
    }

    if ((uint16)alter_info->commit_nowait != OG_INVALID_ID16 &&
        alter_info->commit_nowait != session->knl_session.commit_nowait) {
        session->knl_session.commit_nowait = (bool8)alter_info->commit_nowait;
    }

    if (alter_info->lock_wait_timeout != OG_INVALID_ID32) {
        if (alter_info->lock_wait_timeout != session->knl_session.lock_wait_timeout) {
            session->knl_session.lock_wait_timeout = alter_info->lock_wait_timeout;
        }
    }

    cm_str2text(alter_info->curr_schema, &curr_schema);
    if (curr_schema.len > 0) {
        if (strcmp(alter_info->curr_schema, session->curr_schema) != 0) {
            if (!knl_get_user_id(&session->knl_session, &curr_schema, &session->curr_schema_id)) {
                OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&curr_schema));
                return OG_ERROR;
            }

            MEMS_RETURN_IFERR(strncpy_s(session->curr_schema, OG_NAME_BUFFER_SIZE, curr_schema.str, curr_schema.len));
        }
    }

    cm_str2text(alter_info->curr_user2, &curr_user);
    if (curr_user.len > 0 && strcmp(alter_info->curr_user2, session->curr_user2) != 0) {
        if (!knl_get_user_id(&session->knl_session, &curr_user, &session->curr_user2_id)) {
            OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&curr_user));
            return OG_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(session->curr_user2, OG_NAME_BUFFER_SIZE, curr_user.str, curr_user.len));
    }

    if (alter_info->nologging_enable != OG_INVALID_ID8 && alter_info->nologging_enable != session->nologging_enable) {
        session->nologging_enable = alter_info->nologging_enable;
    }

    return sql_process_alter_set_nls_params(session, nls_params);
}

static status_t sql_init_alter_set(alter_set_info_t *alter_info, nlsparams_t *nls_params)
{
    MEMS_RETURN_IFERR(memset_s(alter_info, sizeof(alter_set_info_t), 0x00, sizeof(alter_set_info_t)));
    alter_info->commit_batch = OG_INVALID_ID16;
    alter_info->commit_nowait = OG_INVALID_ID16;
    alter_info->lock_wait_timeout = OG_INVALID_ID32;
    alter_info->nologging_enable = OG_INVALID_ID8;

    MEMS_RETURN_IFERR(memset_s(nls_params, sizeof(nlsparams_t), 0x00, sizeof(nlsparams_t)));
    nls_params->client_timezone = TIMEZONE_OFFSET_INVALIDVALUE;
    return OG_SUCCESS;
}

static status_t sql_process_get_alter_set(session_t *session, alter_set_info_t *alter_info, nlsparams_t *nls_params)
{
    text_t tmp_schema;
    text_t tmp_user;
    alter_set_info_t *tmp = NULL;
    text_t text;
    int32 tmp_lenth;
    int32 alter_se_lenth;
    OG_RETURN_IFERR(cs_get_int32(session->recv_pack, &alter_se_lenth));
    if (alter_se_lenth == 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_init_alter_set(alter_info, nls_params));

    tmp_lenth = OFFSET_OF(alter_set_info_t, curr_schema);
    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_data(session->recv_pack, OFFSET_OF(alter_set_info_t, curr_schema), (void **)&tmp));
        alter_info->commit_batch = tmp->commit_batch;
        alter_info->commit_nowait = tmp->commit_nowait;
        alter_info->lock_wait_timeout = tmp->lock_wait_timeout;
        alter_info->nologging_enable = tmp->nologging_enable;
        alter_info->isolevel = tmp->isolevel;
        alter_se_lenth = alter_se_lenth - tmp_lenth;
    }

    tmp_lenth = sizeof(uint32);
    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &tmp_schema));
        cm_text2str(&tmp_schema, alter_info->curr_schema, OG_NAME_BUFFER_SIZE);
        alter_se_lenth = alter_se_lenth - tmp_lenth - tmp_schema.len;
    }

    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2nlsvalue(&text, &nls_params->nlsvalues[NLS_DATE_FORMAT]));
        alter_se_lenth = alter_se_lenth - tmp_lenth - text.len;
    }

    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2nlsvalue(&text, &nls_params->nlsvalues[NLS_TIMESTAMP_FORMAT]));

        alter_se_lenth = alter_se_lenth - tmp_lenth - text.len;
    }

    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2nlsvalue(&text, &nls_params->nlsvalues[NLS_TIMESTAMP_TZ_FORMAT]));
        alter_se_lenth = alter_se_lenth - tmp_lenth - text.len;
    }

    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2nlsvalue(&text, &nls_params->nlsvalues[NLS_TIME_FORMAT]));
        alter_se_lenth = alter_se_lenth - tmp_lenth - text.len;
    }

    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &text));
        OG_RETURN_IFERR(cm_text2nlsvalue(&text, &nls_params->nlsvalues[NLS_TIME_TZ_FORMAT]));
        alter_se_lenth = alter_se_lenth - tmp_lenth - text.len;
    }

    tmp_lenth = sizeof(int16);
    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_int16(session->recv_pack, &nls_params->client_timezone));
        alter_se_lenth = alter_se_lenth - tmp_lenth;
    }

    tmp_lenth = sizeof(uint32);
    if (alter_se_lenth >= tmp_lenth) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &tmp_user));
        cm_text2str(&tmp_user, alter_info->curr_user2, OG_NAME_BUFFER_SIZE);
        alter_se_lenth = alter_se_lenth - tmp_lenth - tmp_user.len;
    }

    if (alter_se_lenth > 0) {
        OG_RETURN_IFERR(cs_get_data(session->recv_pack, alter_se_lenth, (void **)&text));
    }
    OG_RETURN_IFERR(sql_process_alter_set_core(session, alter_info, nls_params));

    return OG_SUCCESS;
}

status_t sql_process_alter_set(session_t *session)
{
    alter_set_info_t alter_info;
    nlsparams_t nls_params;
    if (session->call_version >= CS_VERSION_11) {
        OG_RETURN_IFERR(sql_process_get_alter_set(session, &alter_info, &nls_params));
    }
    return OG_SUCCESS;
}

static inline void sql_set_autotrace(session_t *session, cs_prepare_req_t *req)
{
    if ((session->client_kind == CLIENT_KIND_OGSQL) && (req->flags & CS_PREP_AUTOTRACE) &&
        (session->call_version >= CS_VERSION_16)) {
        session->knl_session.autotrace = OG_TRUE;
    } else {
        session->knl_session.autotrace = OG_FALSE;
    }
}

static inline status_t sql_process_altpwd(session_t *session, cs_prepare_req_t *req)
{
    if (session->knl_session.interactive_altpwd) {
        if (session->client_kind != CLIENT_KIND_OGSQL || !(req->flags & CS_OGSQL_IN_ALTPWD)) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "illegal sql text.");
            session->knl_session.interactive_altpwd = OG_FALSE;
            session->is_log_out = OG_TRUE;
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_get_cn_dml_id(session_t *session, cs_prepare_req_t *req)
{
    return OG_SUCCESS;
}

static inline status_t sql_get_stmt_id(session_t *session, uint16 stmt_id)
{
    if (stmt_id == OG_INVALID_ID16) {
        OG_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
        session->current_stmt->is_temp_alloc = OG_TRUE;
    } else {
        OG_RETURN_IFERR(sql_get_stmt(session, stmt_id));
    }

    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_prepare(session_t *session)
{
    cs_prepare_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;
    session->sql_audit.action = SQL_AUDIT_ACTION_PREPARE;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_prepare_req_t), (void **)&req));
    OG_RETURN_IFERR(sql_process_alter_set(session));
    OG_RETURN_IFERR(sql_process_altpwd(session, req));
    /* get stmt to prepare sql */
    OG_RETURN_IFERR(sql_get_stmt_id(session, req->stmt_id));
    stmt = session->current_stmt;

    /* set autotrace flag */
    sql_set_autotrace(session, req);

    /* get cn dml id */
    OG_RETURN_IFERR(sql_get_cn_dml_id(session, req));
    sql_release_lob_info(stmt);
    OG_RETURN_IFERR(sql_process_direct_route_info(stmt));

    if (sql_prepare(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_process_altpwd(session, req));
    /* try send PL warning in prepare ack */
    return sql_try_send_pl_warning(stmt);
}

static void sql_clean_returned_rs(sql_stmt_t *stmt)
{
    sql_stmt_t *item = NULL;
    for (uint32 i = 0; i < stmt->session->stmts.count; i++) {
        item = (sql_stmt_t *)cm_list_get(&stmt->session->stmts, i);
        if (item->status == STMT_STATUS_FREE) {
            continue;
        }

        if (item->cursor_info.is_returned && item->cursor_info.rrs_sn == item->session->rrs_sn) {
            sql_free_stmt(item);
        }
    }
}

void sql_check_user_def_exception(void)
{
    int32 error_code;
    const char *error_message = NULL;

    cm_get_error(&error_code, &error_message, NULL);

    if (error_code == ERR_USER_DEFINED_EXCEPTION) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_UNHANDLED_USER_EXCEPTION);
    }
}

static inline status_t ack_larger_scn(sql_stmt_t *stmt)
{
    // compare local_scn with gts_scn, assign the max to stmt->gts_scn
    // NOTE: should be after sql_execute
    session_t *session = stmt->session;
    if (CS_XACT_WITH_TS(session->recv_pack->head->flags)) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void sql_init_stmt_before_exec(session_t *session, sql_stmt_t *stmt, cs_execute_req_t *execute_req)
{
    stmt->param_info.paramset_size = execute_req->paramset_size;
    stmt->prefetch_rows = (execute_req->prefetch_rows == 0 ? g_instance->sql.prefetch_rows
                                                           : execute_req->prefetch_rows);
    stmt->auto_commit = execute_req->auto_commit;
    session->auto_commit = stmt->auto_commit;

    if (stmt->auto_commit) {
        session->sql_audit.action = SQL_AUDIT_ACTION_AUTOCOMMIT_EXECUTE;
    }

    stmt->is_srvoutput_on = ((session->recv_pack->head->flags & CS_FLAG_SERVEROUPUT) != 0);
    stmt->return_generated_key = (session->recv_pack->head->flags & CS_FLAG_RETURN_GENERATED_KEY) ? OG_TRUE : OG_FALSE;

    return;
}

status_t sql_try_send_backup_warning(sql_stmt_t *stmt)
{
    const char *err_msg = NULL;
    int32 err_code;

    cm_get_error(&err_code, &err_msg, NULL);

    if (err_msg[0] == '\0') {
        return OG_SUCCESS;
    }

    return cs_put_err_msg(stmt->session->send_pack, stmt->session->call_version, err_msg);
}

EXTER_ATTACK status_t sql_process_execute(session_t *session)
{
    cs_execute_req_t *execute_req = NULL;
    sql_stmt_t *stmt = NULL;
    status_t ret;
    errno_t errcode = 0;
    knl_scn_t local_scn = OG_INVALID_ID64;

    session->sql_audit.action = SQL_AUDIT_ACTION_EXECUTE;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_execute_req_t), (void **)&execute_req));

    OG_RETURN_IFERR(sql_get_stmt(session, execute_req->stmt_id));
    stmt = session->current_stmt;

    stmt->sync_scn = local_scn;
    stmt->gts_offset = 0;

    sql_mark_lob_info(stmt);

    sql_init_stmt_before_exec(session, stmt, execute_req);

    if ((session->recv_pack->head->flags & OG_FLAG_ALLOWED_BATCH_ERRS) != 0) {
        OG_RETURN_IFERR(cs_get_int32(session->recv_pack, (int32 *)&stmt->allowed_batch_errs));
    } else {
        stmt->allowed_batch_errs = 0;
    }

    do {
        ret = sql_process_direct_route_info(stmt);
        OG_BREAK_IF_ERROR(ret);

        ret = sql_execute(stmt);
        if (ret == OG_SUCCESS) {
            OG_RETURN_IFERR(ack_larger_scn(stmt));
        }

        OG_BREAK_IF_ERROR(ret);
    } while (OG_FALSE);

    if (ret != OG_SUCCESS) {
        sql_clean_returned_rs(stmt);
    }

    if (stmt->pl_set_schema[0] != '\0') {
        errcode = strncpy_s(session->curr_schema, OG_NAME_BUFFER_SIZE, stmt->pl_set_schema,
                            sizeof(stmt->pl_set_schema));
        if (errcode != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return OG_ERROR;
        }
        stmt->pl_set_schema[0] = '\0';
    }

    return ret;
}

EXTER_ATTACK status_t sql_process_fetch(session_t *session)
{
    cs_fetch_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;
    status_t status;

    session->sql_audit.action = SQL_AUDIT_ACTION_FETCH;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_fetch_req_t), (void **)&req));

    if (sql_get_stmt(session, req->stmt_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    stmt = session->current_stmt;

    stmt->status = STMT_STATUS_FETCHING;
    sql_begin_ctx_stat(stmt);

    do {
        if (req->fetch_mode == CS_FETCH_NORMAL) {
            status = sql_execute_fetch(stmt);
        } else if (req->fetch_mode == CS_FETCH_WITH_PREP_EXEC) {
            status = sql_execute_fetch_medatata(stmt);
            OG_BREAK_IF_ERROR(status);
            status = sql_read_params(stmt);
            OG_BREAK_IF_ERROR(status);
            status = sql_execute(stmt);
        } else if (req->fetch_mode == CS_FETCH_WITH_PREP) {
            status = sql_execute_fetch_cursor_medatata(stmt);
            OG_BREAK_IF_ERROR(status);
            status = sql_execute_fetch(stmt);
        } else {
            OG_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "fetch.");
            status = OG_ERROR;
        }
    } while (OG_FALSE);

    stmt->param_info.paramset_size = 0;
    stmt->status = STMT_STATUS_FETCHED;
    sql_end_ctx_stat(stmt);

    return status;
}

EXTER_ATTACK status_t sql_process_commit(session_t *session)
{
    cs_packet_t *send_pack = NULL;

    CM_POINTER(session);

    session->sql_audit.action = SQL_AUDIT_ACTION_COMMIT;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    send_pack = &session->agent->send_pack;

    {
        OG_RETURN_IFERR(do_commit(session));
        /* if commit from JDBC, conn should from client also. */
        OG_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
        return OG_SUCCESS;
    }
}

EXTER_ATTACK status_t sql_process_rollback(session_t *session)
{
    CM_POINTER(session);

    session->sql_audit.action = SQL_AUDIT_ACTION_ROLLBACK;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    do_rollback(session, NULL);
    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_query(session_t *session)
{
    /* sql_process_query contains prepare and execute:
    request content is "cs_execute_req_t + sql"
    response content is "cs_prepare_ack_t + cs_execute_ack_t"
    */
    cs_execute_req_t *execute_req = NULL;
    sql_stmt_t *stmt = NULL;

    session->sql_audit.action = SQL_AUDIT_ACTION_QUERY;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_execute_req_t), (void **)&execute_req));

    /* get stmt to prepare sql */
    OG_RETURN_IFERR(sql_get_stmt_id(session, execute_req->stmt_id));

    stmt = session->current_stmt;

    stmt->param_info.paramset_size = execute_req->paramset_size;
    stmt->prefetch_rows = (execute_req->prefetch_rows == 0 ? g_instance->sql.prefetch_rows
                                                           : execute_req->prefetch_rows);
    stmt->auto_commit = execute_req->auto_commit;
    session->auto_commit = stmt->auto_commit;
    if (stmt->auto_commit) {
        session->sql_audit.action = SQL_AUDIT_ACTION_AUTOCOMMIT_QUERY;
    }
    stmt->is_srvoutput_on = ((session->recv_pack->head->flags & CS_FLAG_SERVEROUPUT) != 0);

    OG_RETURN_IFERR(sql_prepare(stmt));
    return sql_execute(stmt);
}

EXTER_ATTACK status_t sql_process_prep_and_exec(session_t *session)
{
    cs_prepare_req_t *prepare_req = NULL;
    sql_stmt_t *stmt = NULL;
    cs_prep_exec_param *param = NULL;
    status_t ret;
    knl_scn_t local_scn = OG_INVALID_ID64;

    session->sql_audit.action = SQL_AUDIT_ACTION_PREP_EXEC;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_prepare_req_t), (void **)&prepare_req));
    OG_RETURN_IFERR(sql_process_alter_set(session));

    /* get cn dml id */
    OG_RETURN_IFERR(sql_get_cn_dml_id(session, prepare_req));

    /* get stmt to prepare sql */
    OG_RETURN_IFERR(sql_get_stmt_id(session, prepare_req->stmt_id));

    stmt = session->current_stmt;
    stmt->gts_offset = 0;
    stmt->gts_scn = 0;
    stmt->sync_scn = local_scn;

    sql_mark_lob_info(stmt);

    do {
        ret = sql_process_direct_route_info(stmt);
        OG_BREAK_IF_ERROR(ret);

        /* prepare */
        ret = sql_prepare(stmt);
        OG_BREAK_IF_ERROR(ret);

        cm_reset_error();

        ret = cs_get_data(session->recv_pack, sizeof(cs_prep_exec_param), (void **)&param);
        OG_BREAK_IF_ERROR(ret);
        stmt->param_info.paramset_size = param->paramset_size;
        stmt->prefetch_rows = (param->prefetch_rows == 0 ? g_instance->sql.prefetch_rows : param->prefetch_rows);
        stmt->auto_commit = param->auto_commit;
        session->auto_commit = stmt->auto_commit;
        if (stmt->auto_commit) {
            session->sql_audit.action = SQL_AUDIT_ACTION_PREP_AUTOCOMMIT_EXEC;
        }

        stmt->is_srvoutput_on = ((session->recv_pack->head->flags & CS_FLAG_SERVEROUPUT) != 0);
        stmt->return_generated_key = (session->recv_pack->head->flags & CS_FLAG_RETURN_GENERATED_KEY) ? OG_TRUE
                                                                                                      : OG_FALSE;

        if ((session->recv_pack->head->flags & OG_FLAG_ALLOWED_BATCH_ERRS) != 0) {
            ret = cs_get_int32(session->recv_pack, (int32 *)&stmt->allowed_batch_errs);
            OG_BREAK_IF_ERROR(ret);
        } else {
            stmt->allowed_batch_errs = 0;
        }

        ret = sql_execute(stmt);
        if (ret == OG_SUCCESS) {
            OG_RETURN_IFERR(ack_larger_scn(stmt));
        }

        if (ret != OG_SUCCESS) {
            sql_clean_returned_rs(stmt);
        }
    } while (OG_FALSE);
    return ret;
}

EXTER_ATTACK status_t sql_process_lob_write(session_t *session)
{
    lob_write_req_t *req = NULL;
    session->sql_audit.action = SQL_AUDIT_ACTION_LOB_WRITE;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(lob_write_req_t), (void **)&req));

    OG_RETURN_IFERR(sql_get_stmt_id(session, req->stmt_id));

    sql_prewrite_lob_info(session->current_stmt);
    OG_RETURN_IFERR(sql_write_lob(session->current_stmt, req));
    return OG_SUCCESS;
}

status_t sql_process_lob_read_local(session_t *session, lob_read_req_t *read_req, lob_read_ack_t *ack)
{
    uint32 read_size;
    uint32 lob_size;
    uint32 lob_type;
    sql_stmt_t *stmt = session->current_stmt;
    lob_size = *(uint32 *)read_req->locator;
    lob_type = *(uint32 *)(read_req->locator + sizeof(uint32));

    // get the page to read lob data with offset
    if (read_req->offset >= lob_size) {
        ack->size = 0;
        ack->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    switch (lob_type) {
        case OG_LOB_FROM_KERNEL:
            if (session->call_version >= CS_VERSION_3 && !((lob_locator_t *)read_req->locator)->head.is_outline) {
                OG_THROW_ERROR(ERR_ILEGAL_LOB_TYPE, "inline lob");
                return OG_ERROR;
            }

            OG_RETURN_IFERR(knl_read_lob(session, (knl_handle_t)read_req->locator, read_req->offset,
                                         CS_WRITE_ADDR(session->send_pack), read_req->size, &read_size, NULL));
            ack->eof = (read_req->offset + read_size >= knl_lob_size((knl_handle_t)read_req->locator));
            break;

        case OG_LOB_FROM_VMPOOL:
            sql_preread_lob_info(stmt);
            OG_RETURN_IFERR(sql_read_lob(stmt, (vm_lob_t *)read_req->locator, read_req->offset,
                                         CS_WRITE_ADDR(session->send_pack), read_req->size, &read_size));
            ack->eof = (read_req->offset + read_size >= ((vm_lob_t *)read_req->locator)->size);
            break;

        default:
            OG_THROW_ERROR(ERR_ILEGAL_LOB_TYPE, get_lob_type_name((int32)lob_type));
            return OG_ERROR;
    }

    if (read_size == 0) {
        ack->size = 0;
        ack->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    ack->size = read_size;
    session->send_pack->head->size += read_size;
    return OG_SUCCESS;
}

/* lob_locator: size + type + lob_locator */
EXTER_ATTACK status_t sql_process_lob_read(session_t *session)
{
    uint32 req_pack_len;
    lob_read_req_t *read_req = NULL;
    lob_read_ack_t *ack = NULL;
    uint32 ack_offset;
    sql_stmt_t *stmt = NULL;

    session->sql_audit.action = SQL_AUDIT_ACTION_LOB_READ;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(lob_read_req_t), (void **)&read_req));
    CM_CHECK_RECV_PACK_FREE(session->recv_pack, g_instance->sql.sql_lob_locator_size);

    OG_RETURN_IFERR(cs_reserve_space(session->send_pack, sizeof(lob_read_ack_t), &ack_offset));
    ack = (lob_read_ack_t *)CS_RESERVE_ADDR(session->send_pack, ack_offset);

    OG_RETURN_IFERR(sql_get_stmt(session, read_req->stmt_id));
    stmt = session->current_stmt;

    if (stmt->status < STMT_STATUS_EXECUTED || stmt->context == NULL) {
        OG_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "executed.");
        return OG_ERROR;
    }

    /* invalid len of lob read request packet */
    req_pack_len = CM_ALIGN4(sizeof(cs_packet_head_t)) + CM_ALIGN4(sizeof(lob_read_req_t)) +
                   CM_ALIGN4(g_instance->sql.sql_lob_locator_size);
    if (session->recv_pack->head->size > req_pack_len) {
        OG_THROW_ERROR(ERR_INVALID_TCP_PACKET, "lob read", req_pack_len, session->recv_pack->head->size);
        return OG_ERROR;
    }

    if (read_req->size > OG_MAX_PACKET_SIZE - session->send_pack->head->size) {
        OG_THROW_ERROR(ERR_INVALID_TCP_PACKET, "lob read", (OG_MAX_PACKET_SIZE - session->send_pack->head->size),
                       read_req->size);
        return OG_ERROR;
    }

    return sql_process_lob_read_local(session, read_req, ack);
}

static inline status_t sql_get_xid(cs_packet_t *pack, xa_xid_t **xid)
{
    text_t text;
    OG_RETURN_IFERR(cs_get_text(pack, &text));
    if (text.str == NULL) {
        OG_THROW_ERROR(ERR_XA_INVALID_XID, "Invalid XID");
        return OG_ERROR;
    }

    *xid = (xa_xid_t *)text.str;
    if (text.len != KNL_XA_XID_LEN(*xid)) {
        OG_THROW_ERROR_EX(ERR_XA_INVALID_XID, "Invalid XID : %s", T2S(&text));
        return OG_ERROR;
    }

    if (text.len > KNL_MAX_XA_XID_LEN) {
        OG_THROW_ERROR_EX(ERR_XA_INVALID_XID, "Invalid XID : %s", T2S(&text));
        return OG_ERROR;
    }

    text.str = (*xid)->data;
    text.len = (uint32)((*xid)->gtrid_len);
    text.len += (uint32)((*xid)->bqual_len);
    if (cm_chk_and_upper_base16(&text) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_XA_INVALID_XID, "Invalid XID : %s", T2S(&text));
        return OG_ERROR;
    }

    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*xid)->fmt_id = cs_reverse_int64((*xid)->fmt_id);
    }
    if ((*xid)->fmt_id > OG_MAX_INT64) {
        OG_THROW_ERROR_EX(ERR_XA_INVALID_XID, "Invalid format ID : %llu", (*xid)->fmt_id);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_xa_start(session_t *session)
{
    cs_packet_t *recv_pack = &session->agent->recv_pack;
    uint64 timeout;
    uint64 flags;
    xa_xid_t *xid = NULL;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_XA_START;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    if (IS_COORDINATOR && IS_APP_CONN(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "XA interface on coordinator");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_get_xid(recv_pack, &xid));
    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&timeout));
    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&flags));
    if ((flags & KNL_XA_RESUME) && (sql_check_xa_priv(&session->knl_session, xid) != OG_SUCCESS)) {
        return OG_ERROR;
    }
    return knl_xa_start(session, xid, timeout, flags);
}

EXTER_ATTACK status_t sql_process_xa_end(session_t *session)
{
    cs_packet_t *recv_pack = &session->agent->recv_pack;
    uint64 flags;

    CM_POINTER(session);

    if (IS_COORDINATOR && IS_APP_CONN(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "XA interface on coordinator");
        return OG_ERROR;
    }

    session->sql_audit.action = SQL_AUDIT_ACTION_XA_END;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&flags));
    return knl_xa_end(session);
}

EXTER_ATTACK status_t sql_process_xa_status(session_t *session)
{
    cs_packet_t *send_pack = &session->agent->send_pack;
    cs_packet_t *recv_pack = &session->agent->recv_pack;
    xact_status_t status;
    xa_xid_t *xid = NULL;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_XA_STATUS;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    if (IS_COORDINATOR && IS_APP_CONN(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "XA interface on coordinator");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_get_xid(recv_pack, &xid));

    if (knl_xa_status(session, xid, &status) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cs_put_int32(send_pack, status));

    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_xa_prepare(session_t *session)
{
    status_t status;
    uint64 flags;
    bool32 rdonly = OG_FALSE;
    xa_xid_t *xid = NULL;
    knl_scn_t local_scn = OG_INVALID_ID64;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_XA_PREPARE;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    if (IS_COORDINATOR && IS_APP_CONN(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "XA interface on coordinator");
        return OG_ERROR;
    }
    cs_packet_t *send_pack = &session->agent->send_pack;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    OG_RETURN_IFERR(sql_get_xid(recv_pack, &xid));
    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&flags));
    if (sql_check_xa_priv(&session->knl_session, xid) != OG_SUCCESS) {
        return OG_ERROR;
    }

    {
        status = knl_xa_prepare(session, xid, flags, local_scn, &rdonly);
        ((knl_session_t *)session)->xa_scn = OG_INVALID_ID64;
        OG_RETURN_IFERR(status);

        OG_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
        OG_RETURN_IFERR(cs_put_int32(send_pack, rdonly ? ERR_XA_RDONLY : 0));
        return OG_SUCCESS;
    }
}

EXTER_ATTACK status_t sql_process_xa_commit(session_t *session)
{
    xa_xid_t *xid = NULL;
    uint64 flags;
    knl_scn_t local_scn = OG_INVALID_ID64;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_XA_COMMIT;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    cs_packet_t *send_pack = &session->agent->send_pack;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    // gtid | timestamp | is_2pc_clean
    OG_RETURN_IFERR(sql_get_xid(recv_pack, &xid));
    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&flags));
    if (sql_check_xa_priv(&session->knl_session, xid) != OG_SUCCESS) {
        return OG_ERROR;
    }

    {
        ((knl_session_t *)session)->xa_scn = OG_INVALID_ID64;
        OG_RETURN_IFERR(knl_xa_commit(&session->knl_session, xid, flags, local_scn));

        OG_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
        return OG_SUCCESS;
    }
}

EXTER_ATTACK status_t sql_process_xa_rollback(session_t *session)
{
    xa_xid_t *xid = NULL;
    uint64 flags;

    CM_POINTER(session);
    session->sql_audit.action = SQL_AUDIT_ACTION_XA_ROLLBACK;
    session->sql_audit.audit_type = SQL_AUDIT_DML;

    if (IS_COORDINATOR && IS_APP_CONN(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "XA interface on coordinator");
        return OG_ERROR;
    }

    cs_packet_t *send_pack = &session->agent->send_pack;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    OG_RETURN_IFERR(sql_get_xid(recv_pack, &xid));
    OG_RETURN_IFERR(cs_get_int64(recv_pack, (int64 *)&flags));
    if (sql_check_xa_priv(&session->knl_session, xid) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(knl_xa_rollback(session, xid, flags));

    OG_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
    return OG_SUCCESS;
}

status_t sql_get_uuid(char *buf, uint32 in_len)
{
    uint32 sequence_id;
    date_t now;

    // sequence id + nodeid + now + random
    sequence_id = ((uint32)cm_atomic32_inc(&g_instance->seq_xid)) % 0xFFFF;
    now = cm_now();
    // sequence_id % 100 means get last two digits of sequence_id
    // sequence_id / 100 means get other than last two digits of sequence_id
    PRTS_RETURN_IFERR(
        snprintf_s(buf, in_len, in_len - 1, "%u_%u_%u_%lld", sequence_id % 100, sequence_id / 100, 0, now));

    return OG_SUCCESS;
}

static status_t sql_load_send_ack_msg(sql_stmt_t *stmt, text_t *text_body)
{
    cs_packet_t *send_pack = stmt->session->send_pack;

    cs_init_set(send_pack, stmt->session->call_version);
    send_pack->head->cmd = CS_CMD_LOAD;

    if (text_body != NULL) {
        if (cs_put_text(send_pack, text_body) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t fetch_load_sql_table_name(lex_t *lex, char *table_name)
{
    word_t word;
    text_buf_t tbl_name_buf;

    tbl_name_buf.max_size = OG_FILE_NAME_BUFFER_SIZE;
    tbl_name_buf.str = table_name;
    tbl_name_buf.len = 0;

    if (lex_expected_fetch_word2(lex, "INTO", "TABLE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_tblname(lex, &word, &tbl_name_buf) != OG_SUCCESS) {
        return OG_ERROR;
    }
    CM_NULL_TERM(&tbl_name_buf);

    return OG_SUCCESS;
}

static status_t check_load_sql_syntax(lex_t *lex)
{
    if (lex_expected_fetch_word(lex, "LOAD") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word3(lex, "DATA", "LOCAL", "INFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_load_and_send(sql_stmt_t *stmt, text_t *sql, load_data_info_t *info)
{
    if (sql_alloc_context(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }
    text_t load_file;
    lex_t lex;
    sql_text_t sql_text;
    word_t word;
    sql_text.value = *sql;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);

    // will add more check of sql syntax
    if (check_load_sql_syntax(&lex) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_enclosed_string(&lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_trim_text(&word.text.value);
    load_file = word.text.value;

    if (fetch_load_sql_table_name(&lex, info->table_name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(info->sql_load_seq_suffix, LOAD_MAX_SQL_SUFFIX_LEN, 0, LOAD_MAX_SQL_SUFFIX_LEN));
    if (lex.curr_text->len <= 0) {
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(
        strncat_s(info->sql_load_seq_suffix, LOAD_MAX_SQL_SUFFIX_LEN, lex.curr_text->str, lex.curr_text->len));

    cs_packet_t *send_pack = stmt->session->send_pack;
    cs_init_set(send_pack, stmt->session->call_version);
    send_pack->head->cmd = CS_CMD_LOAD;
    send_pack->head->flags = 1;
    // need return statement id
    OG_RETURN_IFERR(cs_put_int16(send_pack, (uint16)stmt->id));

    if (cs_put_text(send_pack, &load_file) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql_free_context(stmt->context);
    SET_STMT_CONTEXT(stmt, NULL);
    return OG_SUCCESS;
}

static status_t sql_load_write_tmp_file(load_data_info_t *info, text_t *content)
{
    if (info->load_data_tmp_file_fp == INVALID_FILE_HANDLE) {
        // if exist file delete it
        if (cm_file_exist(info->full_file_name)) {
            remove(info->full_file_name);
        }
        status_t status = cm_open_file(info->full_file_name, O_CREAT | O_RDWR | O_APPEND, &info->load_data_tmp_file_fp);
        OG_LOG_DEBUG_INF("[load data local]:open file fd %d file %s", info->load_data_tmp_file_fp,
                         info->full_file_name);
        if (status != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_OPEN_FILE);
            return OG_ERROR;
        }
    }

    status_t status = cm_write_file(info->load_data_tmp_file_fp, content->str, content->len);
    if (status != OG_SUCCESS) {
        cm_close_file(info->load_data_tmp_file_fp);
        info->load_data_tmp_file_fp = INVALID_FILE_HANDLE;
        sql_load_try_remove_file(info->full_file_name);
        OG_THROW_ERROR(ERR_WRITE_FILE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t get_load_upload_dir_ex(char *upload_dir)
{
    MEMS_RETURN_IFERR(strncpy_s(upload_dir, OG_MAX_PATH_BUFFER_SIZE, g_instance->home, strlen(g_instance->home)));
    char *load_sub_dir_name;
#ifdef WIN32
    load_sub_dir_name = "\\upload\\";
#else
    load_sub_dir_name = "/upload/";
#endif /* WIN32 */

    MEMS_RETURN_IFERR(strncat_s(upload_dir, OG_MAX_PATH_BUFFER_SIZE, load_sub_dir_name, strlen(load_sub_dir_name)));

    if (cm_dir_exist(upload_dir)) {
        return OG_SUCCESS;
    }

    if (cm_create_dir(upload_dir) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_load_generate_tmp_file_name(session_t *session, char *file_name)
{
    int len_of_txt = 4;
    char thread_name_arr[OG_MAX_INT32_STRLEN] = { 0 };
    text_t thread_id_text = { .str = thread_name_arr, .len = 0 };
    cm_uint32_to_text(session->knl_session.spid, &thread_id_text);
    char session_id_arr[OG_MAX_INT32_STRLEN] = { 0 };
    text_t session_id_text = { .str = session_id_arr, .len = 0 };
    cm_uint32_to_text(session->knl_session.serial_id, &session_id_text);

    MEMS_RETURN_IFERR(strncat_s(file_name, OG_MAX_FILE_NAME_LEN, thread_name_arr, thread_id_text.len));
    MEMS_RETURN_IFERR(strncat_s(file_name, OG_MAX_FILE_NAME_LEN, "_", 1));
    MEMS_RETURN_IFERR(strncat_s(file_name, OG_MAX_FILE_NAME_LEN, session_id_arr, session_id_text.len));
    MEMS_RETURN_IFERR(strncat_s(file_name, OG_MAX_FILE_NAME_LEN, ".txt", len_of_txt));
    OG_LOG_DEBUG_INF("[load data local]:tmp file name %s ", file_name);
    return OG_SUCCESS;
}

status_t generate_load_full_file_name(session_t *session, char *full_file_name)
{
    char upload_dir[OG_MAX_PATH_BUFFER_SIZE] = { 0 };
    OG_RETURN_IFERR(get_load_upload_dir_ex(upload_dir));
    char file_name[OG_MAX_FILE_NAME_LEN] = { 0 };
    OG_RETURN_IFERR(sql_load_generate_tmp_file_name(session, file_name));
    // construct full file name
    MEMS_RETURN_IFERR(memset_s(full_file_name, LOAD_MAX_FULL_FILE_NAME_LEN, 0, LOAD_MAX_FULL_FILE_NAME_LEN));
    MEMS_RETURN_IFERR(strncat_s(full_file_name, LOAD_MAX_FULL_FILE_NAME_LEN, upload_dir, strlen(upload_dir)));
    MEMS_RETURN_IFERR(strncat_s(full_file_name, LOAD_MAX_FULL_FILE_NAME_LEN, file_name, strlen(file_name)));
    return OG_SUCCESS;
}

status_t sql_load_try_remove_file(char *file_name)
{
    if (cm_file_exist(file_name)) {
        int try_times = MAX_DEL_RETRY_TIMES;
        int retry_sleep_100ms = 100;
        int status = OG_ERROR;
        while (try_times--) {
            status = cm_remove_file(file_name);
            if (status == OG_SUCCESS) {
                break;
            }
            cm_sleep(retry_sleep_100ms);
        }

        if (status != OG_SUCCESS) {
            OG_THROW_ERROR(
                ERR_REMOVE_FILE,
                "[load data local]:rm file %s failed,may be file loaded, pls delete file by hand and check os.",
                file_name);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t sql_load_reset_fp_and_del_file(load_data_info_t *info)
{
    if (info->load_data_tmp_file_fp != INVALID_FILE_HANDLE) {
        OG_LOG_DEBUG_INF("[load data local]:rm file after do cmd %s,fp %d", info->full_file_name,
                         info->load_data_tmp_file_fp);
        cm_close_file(info->load_data_tmp_file_fp);
        info->load_data_tmp_file_fp = INVALID_FILE_HANDLE;
        return sql_load_try_remove_file(info->full_file_name);
    }
    return OG_SUCCESS;
}

status_t check_version_and_local_infile(void)
{
    if (!IS_COORDINATOR) {
        OG_LOG_DEBUG_ERR("[load data local] only support load on CN node");
        OG_THROW_ERROR(ERR_INVALID_PROTOCOL, "only support load data while connect to CN node");
        return OG_ERROR;
    }

    if (g_instance->attr.enable_local_infile != OG_TRUE) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "ENABLE_LOCAL_INFILE", g_instance->attr.enable_local_infile);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t append_ogsql_cmd_head(char *sql_load_seq, char *dba_user, char *pwd)
{
#ifdef WIN32
    int len_of_ogsql = 5;
    // put :ogsql
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, "ogsql ", len_of_ogsql));
#endif
    // put user
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, dba_user, strlen(dba_user)));
    // put /
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, "/", 1));
    // put passwd
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, pwd, strlen(pwd)));
    // put url
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, "@", 1));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS)));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, ":", 1));
    // put port
    uint16 port = g_instance->lsnr.tcp_service.port;
    char port_array[OG_MAX_INT32_STRLEN];
    text_t port_text = { .str = port_array, .len = 0 };
    cm_uint32_to_text((uint32)port, &port_text);
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, OG_MAX_FILE_NAME_LEN, port_text.str, port_text.len));
    return OG_SUCCESS;
}

static status_t load_file_by_ogsql2(char *cmd_head, char *load_sql_content, char *result)
{
#ifndef WIN32
    pid_t pid;
    int fd[LOAD_RET_FD_SIZE];
    char buf[POPEN_GET_BUF_MAX_LEN] = { 0 };
    char *const args[] = { "", cmd_head, "-q", "-c", load_sql_content, NULL };

    if (pipe(fd) == -1) {
        OG_THROW_ERROR_EX(ERR_CREATE_THREAD, "error code %d", errno);
        return OG_ERROR;
    }
    pid = fork();
    if (pid == -1) {
        OG_THROW_ERROR_EX(ERR_CREATE_THREAD, "error code %d", errno);
        return OG_ERROR;
    } else if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        close(fd[1]);

        if (execvp("ogsql", args) == -1) {
            return OG_ERROR;
        }
        exit(errno);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED((unsigned int)status)) {
            OG_LOG_DEBUG_INF("[load data local]:ogsql load process exit code %d\n", WEXITSTATUS((unsigned int)status));
            close(fd[1]);
            int num_bytes = 0;
            do {
                num_bytes = read(fd[0], buf, sizeof(buf));
                if (num_bytes == 0) {
                    break;
                }
                buf[num_bytes] = '\0';
                CHECK_SRC_LEN_VALID(buf, result);
                if (strncat_s(result, OG_MAX_STRING_LEN, buf, strlen(buf)) == OG_ERROR) {
                    OG_LOG_DEBUG_ERR("[load data local]:result if full %s ", result);
                    break;
                }
            } while (num_bytes);
            return OG_SUCCESS;
        } else {
            OG_THROW_ERROR_EX(ERR_CREATE_THREAD, "error code %d", errno);
            return OG_ERROR;
        }
    }
#endif
    return OG_SUCCESS;
}

status_t load_file_by_ogsql(char *ogsql_command, char *result)
{
    return OG_SUCCESS;
}

static status_t sql_load_execute_ogsql(sql_stmt_t *stmt, text_t *recv_data, load_data_info_t *info)
{
    char execute_result[OG_MAX_STRING_LEN] = { 0 };
    char sql_load_seq[LOAD_BY_OGSQL_MAX_STR_LEN] = { 0 };
    char dba_user[OG_MAX_STRING_LEN] = { 0 };
    char pwd[OG_PASSWORD_BUFFER_SIZE + 1] = { 0 };
    OG_RETURN_IFERR(append_ogsql_cmd_head(sql_load_seq, dba_user, pwd));
    MEMS_RETURN_IFERR(memset_s(pwd, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
#ifdef WIN32
    char *sql_load_seq_prefix = " -q -c \" LOAD DATA INFILE '";
#else
    char sql_load_seq_head[OG_MAX_STRING_LEN] = { 0 };
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq_head, OG_MAX_STRING_LEN, sql_load_seq, strlen(sql_load_seq)));
    MEMS_RETURN_IFERR(memset_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, 0, LOAD_BY_OGSQL_MAX_STR_LEN));
    char *sql_load_seq_prefix = "LOAD DATA INFILE '";
#endif
    MEMS_RETURN_IFERR(
        strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, sql_load_seq_prefix, strlen(sql_load_seq_prefix)));
    MEMS_RETURN_IFERR(
        strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, info->full_file_name, strlen(info->full_file_name)));
    char sql_load_into_table[] = "' INTO TABLE ";
    MEMS_RETURN_IFERR(
        strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, sql_load_into_table, strlen(sql_load_into_table)));
    MEMS_RETURN_IFERR(
        strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, stmt->session->curr_user.str, stmt->session->curr_user.len));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, ".", 1));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, info->table_name, strlen(info->table_name)));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, " ", 1));
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, info->sql_load_seq_suffix,
                                strlen(info->sql_load_seq_suffix)));
#ifdef WIN32
    MEMS_RETURN_IFERR(strncat_s(sql_load_seq, LOAD_BY_OGSQL_MAX_STR_LEN, "\"", 1));
    OG_RETURN_IFERR(load_file_by_ogsql(sql_load_seq, execute_result));
#else
    OG_RETURN_IFERR(load_file_by_ogsql2(sql_load_seq_head, sql_load_seq, execute_result));
#endif
    // send load result
    text_t load_file_res;
    load_file_res.str = execute_result;
    load_file_res.len = (uint32)strlen(execute_result);
    return sql_load_send_ack_msg(stmt, &load_file_res);
}

static status_t sql_load_malloc_data_info(session_t *sess)
{
    sess->load_data_info.full_file_name = (char *)malloc(LOAD_MAX_FULL_FILE_NAME_LEN + 1);
    if (sess->load_data_info.full_file_name == NULL) {
        return OG_ERROR;
    }
    sess->load_data_info.sql_load_seq_suffix = (char *)malloc(LOAD_MAX_SQL_SUFFIX_LEN + 1);
    if (sess->load_data_info.sql_load_seq_suffix == NULL) {
        return OG_ERROR;
    }
    sess->load_data_info.table_name = (char *)malloc(OG_MAX_FILE_NAME_LEN + 1);
    if (sess->load_data_info.table_name == NULL) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void sql_load_free_data_info(session_t *sess)
{
    if (sess->load_data_info.sql_load_seq_suffix != NULL) {
        free(sess->load_data_info.sql_load_seq_suffix);
        sess->load_data_info.sql_load_seq_suffix = NULL;
    }
    if (sess->load_data_info.table_name != NULL) {
        free(sess->load_data_info.table_name);
        sess->load_data_info.table_name = NULL;
    }
    if (sess->load_data_info.full_file_name != NULL) {
        free(sess->load_data_info.full_file_name);
        sess->load_data_info.full_file_name = NULL;
    }
}

EXTER_ATTACK status_t sql_process_load(session_t *session)
{
    cs_prepare_req_t *req = NULL;
    sql_stmt_t *stmt = NULL;
    status_t ret = OG_ERROR;
    text_t recv_data;

    session->sql_audit.action = SQL_AUDIT_ACTION_LOAD_DATA;
    OG_RETURN_IFERR(check_version_and_local_infile());
    OG_RETURN_IFERR(cs_get_data(session->recv_pack, sizeof(cs_prepare_req_t), (void **)&req));

    if (req->stmt_id == OG_INVALID_ID16) {
        OG_RETURN_IFERR(sql_alloc_stmt(session, &session->current_stmt));
        session->load_data_info.load_data_tmp_file_fp = INVALID_FILE_HANDLE;
    } else {
        OG_RETURN_IFERR(sql_get_stmt(session, req->stmt_id));
    }
    stmt = session->current_stmt;

    OG_RETURN_IFERR(cs_get_text(session->recv_pack, &recv_data));

    do {
        if (req->flags & CS_LOAD_GET_SQL) {
            if (recv_data.len > LOAD_MAX_RAW_SQL_LEN) {
                OG_THROW_ERROR(ERR_SQL_TOO_LONG, recv_data.len);
                return OG_ERROR;
            }
            OG_BREAK_IF_ERROR(sql_load_malloc_data_info(session));
            OG_BREAK_IF_ERROR(generate_load_full_file_name(stmt->session, session->load_data_info.full_file_name));
            ret = sql_parse_load_and_send(stmt, &recv_data, &session->load_data_info);
            OG_LOG_DEBUG_INF("[load data local]:LOAD_DATA_LOCAL_GET_SQL end");
        } else if (req->flags & CS_LOAD_GET_DATA) {
            OG_BREAK_IF_ERROR(sql_load_write_tmp_file(&session->load_data_info, &recv_data));
            text_t write_file_result = { .str = "", .len = 1 };
            ret = sql_load_send_ack_msg(stmt, &write_file_result);
        } else if (req->flags & CS_LOAD_EXE_CMD) {
            OG_LOG_DEBUG_INF("[load data local]:LOAD_DATA_LOCAL_GET_DATA end ");
            ret = sql_load_execute_ogsql(stmt, &recv_data, &session->load_data_info);
        }
    } while (0);

    if (ret != OG_SUCCESS || (req->flags & CS_LOAD_EXE_CMD)) {
        OG_LOG_DEBUG_INF("[load data local]:try rm file %s, ret:%d ", session->load_data_info.full_file_name, ret);
        sql_load_reset_fp_and_del_file(&session->load_data_info);
        sql_load_free_data_info(session);
    }

    return ret;
}

static status_t sql_gen_multi_ack(session_t *session, sql_stmt_t *stmt, uint64 *affected_array, uint32 sql_num)
{
    cs_prep_exec_multi_ack_t *multi_sql_ack = NULL;
    OG_RETURN_IFERR(cs_reserve_space(session->send_pack, sizeof(cs_prep_exec_multi_ack_t), &stmt->exec_ack_offset));
    multi_sql_ack = (cs_prep_exec_multi_ack_t *)CS_RESERVE_ADDR(session->send_pack, stmt->exec_ack_offset);
    MEMS_RETURN_IFERR(memset_s(multi_sql_ack, sizeof(cs_prep_exec_multi_ack_t), 0, sizeof(cs_prep_exec_multi_ack_t)));
    multi_sql_ack->stmt_id = stmt->id;
    multi_sql_ack->sql_num = sql_num;
    OG_RETURN_IFERR(cs_put_data(session->send_pack, affected_array, sizeof(uint64) * sql_num));
    return OG_SUCCESS;
}

static status_t sql_execute_for_multi_sql(session_t *session, sql_stmt_t *stmt, uint64 *affected_array, uint32 sql_num,
                                          uint32 index)
{
    cs_multi_param_info_t *param_info = NULL;

    cs_get_data(session->recv_pack, sizeof(cs_multi_param_info_t), (void **)&param_info);
    stmt->param_info.paramset_size = param_info->paramset_size;
    if (param_info->paramset_size == 0 && stmt->context->params->count > 0) {
        affected_array[index] = 0;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_execute(stmt));
    affected_array[index] = stmt->total_rows;
    return OG_SUCCESS;
}

static status_t sql_do_pre_exec_multi_sql(session_t *session, sql_stmt_t *stmt, uint64 *affected_array, uint32 sql_num)
{
    text_t sql;

    for (uint32 ind = 0; ind < sql_num; ind++) {
        OG_RETURN_IFERR(cs_get_text(session->recv_pack, &sql));

        if (sql.len != 0) {
            OG_RETURN_IFERR(sql_prepare_for_multi_sql(stmt, &sql));
        } else if (stmt->context == NULL) {
            OG_THROW_ERROR(ERR_INVALID_CURSOR);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_execute_for_multi_sql(session, stmt, affected_array, sql_num, ind));
    }

    return OG_SUCCESS;
}

EXTER_ATTACK status_t sql_process_pre_exec_multi_sql(session_t *session)
{
    cs_prep_exec_multi_sql_t *multi_sql_head = NULL;
    uint64 *affected_array = NULL;
    sql_stmt_t *stmt = NULL;

    session->sql_audit.action = SQL_AUDIT_ACTION_PREP_EXEC;
    cs_get_data(session->recv_pack, sizeof(cs_prep_exec_multi_sql_t), (void **)&multi_sql_head);
    OG_RETVALUE_IFTRUE(CM_IS_NULL(multi_sql_head), OG_ERROR);
    /* get stmt to prepare sql */
    OG_RETURN_IFERR(sql_get_stmt_id(session, multi_sql_head->stmt_id));

    stmt = session->current_stmt;
    stmt->gts_offset = 0;
    stmt->gts_scn = 0;
    sql_mark_lob_info(stmt);

    stmt->auto_commit = multi_sql_head->auto_commit;
    if (stmt->auto_commit) {
        session->sql_audit.action = SQL_AUDIT_ACTION_PREP_AUTOCOMMIT_EXEC;
    }
    session->auto_commit = stmt->auto_commit;
    stmt->is_srvoutput_on = OG_FALSE;
    stmt->return_generated_key = OG_FALSE;
    stmt->allowed_batch_errs = 0;

    OG_RETURN_IFERR(sql_push(stmt, sizeof(uint64) * multi_sql_head->sql_num, (void **)&affected_array));
    OG_RETURN_IFERR(sql_do_pre_exec_multi_sql(session, stmt, affected_array, multi_sql_head->sql_num));
    OG_RETURN_IFERR(sql_gen_multi_ack(session, stmt, affected_array, multi_sql_head->sql_num));

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
