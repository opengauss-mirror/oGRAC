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
 * ogsql_stmt.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/ogsql_stmt.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_protocol.h"
#include "cm_file.h"
#include "ogsql_parser.h"
#include "ddl_executor.h"
#include "dcl_executor.h"
#include "cm_utils.h"
#include "ogsql_mtrl.h"
#include "ogsql_scan.h"
#include "ogsql_proj.h"
#include "ogsql_privilege.h"
#include "pl_lock.h"
#include "ogsql_select.h"
#include "ddl_column_parser.h"
#include "pl_executor.h"
#include "expl_executor.h"
#ifdef TIME_STATISTIC
#include "cm_statistic.h"
#endif
#include "cond_parser.h"
#include "func_parser.h"
#include "ogsql_serial.h"
#include "cm_array.h"
#include "pl_memory.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MQ_MAX_PRECISION 6

#define IS_PL_SQL(stmt) ((stmt)->pl_context != NULL || (stmt)->pl_exec != NULL)

#define STATIC_SAVE_STMT(stmt)                                          \
    ogx_prev_stat_t __ctx_prev_stat__ = (stmt)->session->ogx_prev_stat; \
    text_t __current_sql__ = (stmt)->session->current_sql;              \
    uint32 __sql_id__ = (stmt)->session->sql_id;

#define STATIC_RESTORE_STMT(stmt)                           \
    do {                                                    \
        (stmt)->session->ogx_prev_stat = __ctx_prev_stat__; \
        (stmt)->session->current_sql = __current_sql__;     \
        (stmt)->session->sql_id = __sql_id__;               \
    } while (0)

#define EXPLAIN_HEAD "EXPLAIN PLAN OUTPUT"

void sql_init_stmt(session_t *session, sql_stmt_t *stmt, uint32 stmt_id)
{
    sql_context_t *context = (session->disable_soft_parse) ? stmt->context : NULL;

    MEMS_RETVOID_IFERR(memset_s(stmt, sizeof(sql_stmt_t), 0, sizeof(sql_stmt_t)));

    vmc_init(&session->vmp, &stmt->vmc);
    cm_galist_init(&stmt->vmc_list, &stmt->vmc, vmc_alloc_mem);

    stmt->id = stmt_id;
    stmt->session = session;
    SET_STMT_CONTEXT(stmt, context);
    sql_init_mtrl(&stmt->mtrl, session);
    stmt->vm_ctx = &stmt->vm_ctx_data;
    vm_init_ctx(GET_VM_CTX(stmt), (handle_t)session, &session->stack, session->knl_session.temp_pool);
    stmt->status = STMT_STATUS_IDLE;
    stmt->prefetch_rows = g_instance->sql.prefetch_rows;
    stmt->chk_priv = OG_TRUE;
    stmt->is_verifying = OG_FALSE;
    stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
    stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
    stmt->eof = OG_TRUE;
    stmt->into = NULL;
    stmt->vm_lob_ids = NULL;
    stmt->outlines = NULL;
    stmt->is_temp_alloc = OG_FALSE;
    stmt->trace_disabled = OG_FALSE;
    stmt->context_refered = OG_FALSE;
    stmt->hash_mtrl_ctx_list = NULL;
    array_set_handle((void *)&session->knl_session, session->knl_session.temp_mtrl->pool,
        (void *)session->knl_session.stack);

    (void)sql_alloc_for_longsql_stat(stmt);
}

status_t sql_alloc_stmt(session_t *session, sql_stmt_t **statement)
{
    uint32 i;
    sql_stmt_t *stmt = NULL;

    cm_spin_lock(&session->sess_lock, NULL);

    for (i = 0; i < session->stmts.count; i++) {
        stmt = (sql_stmt_t *)cm_list_get(&session->stmts, i);
        if (stmt->status == STMT_STATUS_FREE) {
            sql_init_stmt(session, stmt, i);
            *statement = stmt;
            session->stmts_cnt++;
            cm_spin_unlock(&session->sess_lock);
            return OG_SUCCESS;
        }
    }
    if (session->stmts.count >= g_instance->attr.open_cursors) {
        cm_spin_unlock(&session->sess_lock);
        OG_THROW_ERROR(ERR_EXCEED_MAX_STMTS, g_instance->attr.open_cursors);
        return OG_ERROR;
    }

    if (cm_list_new(&session->stmts, (void **)&stmt) != OG_SUCCESS) {
        cm_spin_unlock(&session->sess_lock);
        OG_THROW_ERROR(ERR_NO_FREE_VMEM, "alloc space for statement failed");
        return OG_ERROR;
    }
    sql_init_stmt(session, stmt, session->stmts.count - 1);
    *statement = stmt;
    session->stmts_cnt++;
    cm_spin_unlock(&session->sess_lock);
    return OG_SUCCESS;
}

/**
 * Set current statement query scn
 * @attention once we set the query_scn all the cursors in current
 * statement would share the same query_scn.
 * @param sql statement
 */
void sql_set_scn(sql_stmt_t *stmt)
{
    if (stmt->session->pipe != NULL && CS_XACT_WITH_TS(stmt->session->recv_pack->head->flags) &&
        stmt->session->proto_type == PROTO_TYPE_CT) {
        knl_set_session_scn(&stmt->session->knl_session, stmt->sync_scn);
    } else {
        /* *
         * return error, hint: select 1;
         * if no valid scn in the request pack and connection from CN,
         * the consistency model must be GTS-free
         */
        knl_set_session_scn(&stmt->session->knl_session, OG_INVALID_ID64);
    }

    stmt->query_scn = stmt->session->knl_session.query_scn;
}

void sql_set_ssn(sql_stmt_t *stmt)
{
    knl_inc_session_ssn(&stmt->session->knl_session);
    stmt->ssn = stmt->session->knl_session.ssn;
    stmt->xact_ssn = stmt->session->knl_session.rm->ssn;
}

void ogsql_assign_transaction_id(sql_stmt_t *stmt, uint64 *xid)
{
    stmt->xid = stmt->session->knl_session.rm->xid.value;
    if (xid != NULL) {
        *xid = stmt->xid;
    }
}

static void do_release_context(sql_stmt_t *stmt, sql_context_t *sql_ctx)
{
    CM_ASSERT(stmt->pl_context == NULL);
    if (sql_ctx->type < OGSQL_TYPE_DML_CEIL) {
        if (sql_ctx->in_sql_pool) {
            ogx_dec_ref(sql_pool, &sql_ctx->ctrl);
        } else if (sql_ctx->ctrl.ref_count > 0) {
            ogx_dec_ref2(&sql_ctx->ctrl);
        } else {
            sql_free_context(sql_ctx);
        }
    } else {
        sql_free_context(sql_ctx);
    }
}

void sql_release_context(sql_stmt_t *stmt)
{
    sql_unlock_lnk_tabs(stmt);
    sql_context_t *sql_ctx = NULL;

    if (stmt->context == NULL) {
        CM_ASSERT(stmt->pl_context == NULL);
        return;
    }

    sql_ctx = stmt->context;
    cm_spin_lock(&sql_ctx->ctrl.lock, NULL);
    sql_ctx->stat.vm_stat.open_pages += stmt->vm_stat.open_pages;
    sql_ctx->stat.vm_stat.close_pages += stmt->vm_stat.close_pages;
    sql_ctx->stat.vm_stat.max_open_pages += stmt->vm_stat.max_open_pages;
    sql_ctx->stat.vm_stat.alloc_pages += stmt->vm_stat.alloc_pages;
    sql_ctx->stat.vm_stat.free_pages += stmt->vm_stat.free_pages;
    sql_ctx->stat.vm_stat.swap_in_pages += stmt->vm_stat.swap_in_pages;
    sql_ctx->stat.vm_stat.swap_out_pages += stmt->vm_stat.swap_out_pages;
    sql_ctx->stat.vm_stat.time_elapsed += stmt->vm_stat.time_elapsed;
    cm_spin_unlock(&sql_ctx->ctrl.lock);

    stmt->vm_stat.open_pages = 0;
    stmt->vm_stat.close_pages = 0;
    stmt->vm_stat.max_open_pages = 0;
    stmt->vm_stat.alloc_pages = 0;
    stmt->vm_stat.free_pages = 0;
    stmt->vm_stat.swap_in_pages = 0;
    stmt->vm_stat.swap_out_pages = 0;
    stmt->vm_stat.time_elapsed = 0;

    if (stmt->pl_context != NULL) {
        pl_release_context(stmt);
        SET_STMT_CONTEXT(stmt, NULL);
        return;
    }
    SET_STMT_CONTEXT(stmt, NULL);

    sql_context_t *parent = sql_ctx->parent;
    if (parent == NULL) {
        do_release_context(stmt, sql_ctx);
        return;
    }
    ogx_dec_ref(parent->ctrl.subpool, &sql_ctx->ctrl);
    do_release_context(stmt, parent);
}

static inline void sql_release_pool_objects(sql_stmt_t *stmt)
{
    object_pool_t *obj_pool = NULL;

    if (stmt->sql_curs.count > 0) {
        sql_free_cursors(stmt);
    }

    if (stmt->knl_curs.count > 0) {
        obj_pool = &stmt->session->knl_cur_pool;
        opool_free_list(obj_pool, &stmt->knl_curs);
        olist_init(&stmt->knl_curs);
    }
}

static void sql_release_hash_optm_data(sql_stmt_t *stmt)
{
    hash_view_ctx_t *hash_view_ctx = (hash_view_ctx_t *)stmt->hash_views;
    if (hash_view_ctx == NULL) {
        return;
    }

    for (uint32 i = 0; i < stmt->context->hash_optm_count; ++i) {
        if (hash_view_ctx[i].initialized) {
            vm_hash_segment_deinit(&hash_view_ctx[i].hash_seg);
        }
    }
    stmt->hash_views = NULL;
}

static void sql_release_withas_mtrl(sql_stmt_t *stmt)
{
    withas_mtrl_ctx_t *withas_mtrl_ctx = (withas_mtrl_ctx_t *)stmt->withass;
    if (withas_mtrl_ctx == NULL) {
        return;
    }
    sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;
    for (uint32 i = 0; i < withas->withas_factors->count; ++i) {
        if (withas_mtrl_ctx[i].is_ready && withas_mtrl_ctx[i].rs.sid != OG_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, withas_mtrl_ctx[i].rs.sid);
            mtrl_release_segment(&stmt->mtrl, withas_mtrl_ctx[i].rs.sid);
        }
    }
    stmt->withass = NULL;
}

static void sql_release_vm_view_ctx_list(sql_stmt_t *stmt)
{
    vm_view_mtrl_ctx_t **view_mtrl_ctx = (vm_view_mtrl_ctx_t **)stmt->vm_view_ctx_array;
    if (view_mtrl_ctx == NULL) {
        return;
    }

    vm_view_mtrl_ctx_t *ogx = NULL;
    for (uint32 i = 0; i < stmt->context->vm_view_count; i++) {
        ogx = view_mtrl_ctx[i];
        if (ogx != NULL && ogx->is_ready && ogx->rs.sid != OG_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, ogx->rs.sid);
            mtrl_release_segment(&stmt->mtrl, ogx->rs.sid);
        }
    }
    stmt->vm_view_ctx_array = NULL;
}

static void sql_release_varea(sql_stmt_t *stmt)
{
    stmt->cursor_info.param_buf = NULL;
    stmt->cursor_info.param_types = NULL;
    stmt->fexec_info.first_exec_buf = NULL;
    stmt->plan_cnt = 0;
    stmt->plan_time = NULL;
    sql_release_hash_optm_data(stmt);
    sql_release_withas_mtrl(stmt);
    sql_free_hash_mtrl(stmt);
    sql_release_vm_view_ctx_list(stmt);
    stmt->in_param_buf = NULL;
    sql_free_vmemory(stmt);
    vmc_free(&stmt->vmc);
}

void sql_prewrite_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        /* free lob list used last time, include pre_list and exec_list */
        if (stmt->lob_info_ex.pre_expired) {
            vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.pre_list);
            stmt->lob_info_ex.pre_expired = OG_FALSE;
        }
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.exec_list);
    }
}

void sql_preread_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        /* move pre_list to exec_list for lob read */
        if (stmt->lob_info_ex.pre_list.count > 0) {
            vm_append_list(stmt->mtrl.pool, &stmt->lob_info_ex.exec_list, &stmt->lob_info_ex.pre_list);
            vm_reset_list(&stmt->lob_info_ex.pre_list);
        }
    }
}

void sql_mark_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.exec_list);
        stmt->lob_info_ex.pre_expired = OG_TRUE;
    }
}

id_list_t *sql_get_pre_lob_list(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        return &(stmt->lob_info_ex.pre_list);
    } else {
        return &(stmt->lob_info.list);
    }
}

id_list_t *sql_get_exec_lob_list(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        return &(stmt->lob_info_ex.exec_list);
    } else {
        return &(stmt->lob_info.list);
    }
}

void sql_release_lob_info(sql_stmt_t *stmt)
{
    if (stmt->session->call_version >= CS_VERSION_10) {
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.pre_list);
        vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info_ex.exec_list);
        stmt->lob_info_ex.pre_expired = OG_FALSE;
    }
}

/* alloc memory for longsql stat info */
status_t sql_alloc_for_longsql_stat(sql_stmt_t *stmt)
{
    if (!cm_log_param_instance()->longsql_print_enable || stmt->stat != NULL) {
        return OG_SUCCESS;
    }

    stmt->stat = (ogx_stat_t *)malloc(sizeof(ogx_stat_t));
    if (stmt->stat == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(ogx_stat_t), "stmt statistics information");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(stmt->stat, sizeof(ogx_stat_t), 0, sizeof(ogx_stat_t)));
    return OG_SUCCESS;
}

static void sql_reset_vmctx(sql_stmt_t *stmt)
{
    if (GET_VM_CTX(stmt) != &stmt->vm_ctx_data) {
        return;
    }
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (stmt->is_success) {
        (void)vmctx_check_memory(stmt->vm_ctx);
    }
#endif // DEBUG
    vmctx_reset(GET_VM_CTX(stmt));
}

static void sql_free_pl_ref_dc(sql_stmt_t *stmt)
{
    pl_entry_t *entry = NULL;
    galist_t *dc_list = stmt->pl_ref_entry;

    if (!stmt->has_pl_ref_dc || dc_list == NULL) {
        return;
    }

    for (uint32 i = 0; i < dc_list->count; i++) {
        entry = (pl_entry_t *)cm_galist_get(dc_list, i);
        pl_unlock_shared(KNL_SESSION(stmt), entry);
    }
    stmt->has_pl_ref_dc = OG_FALSE;
    stmt->pl_ref_entry = NULL;
}

static void sql_free_trigger_list(sql_stmt_t *stmt)
{
    stmt->trigger_list = NULL;
}

void sql_release_resource(sql_stmt_t *stmt, bool32 is_force)
{
    sql_dec_ctx_ref(stmt, stmt->context);
    sql_free_trigger_list(stmt);
    sql_free_pl_ref_dc(stmt);

    if (!stmt->resource_inuse) {
        // we have used vmc memory in sql prepare phase, need to free it.
        sql_free_vmemory(stmt);
        vmc_free(&stmt->vmc);
        sql_reset_vmctx(stmt);
        return;
    }
    if (stmt->cursor_stack.depth > 0) {
        sql_free_cursor(stmt, OGSQL_ROOT_CURSOR(stmt));
    }
    sql_release_varea(stmt);

    sql_release_pool_objects(stmt);
    mtrl_release_context(&stmt->mtrl);
    OBJ_STACK_RESET(&stmt->cursor_stack);
    OBJ_STACK_RESET(&stmt->ssa_stack);
    OBJ_STACK_RESET(&stmt->node_stack);

    if (stmt->session->call_version < CS_VERSION_10) {
        // version under 11 , need to free lob_info here.
        if (!stmt->dc_invalid && (is_force || stmt->lob_info.inuse_count == 0)) {
            vm_free_list(stmt->session, stmt->mtrl.pool, &stmt->lob_info.list);
            stmt->lob_info.inuse_count = 0;
            stmt->resource_inuse = OG_FALSE;
        }
    } else {
        // lob info free at 'sql_release_lob_info'
        stmt->resource_inuse = OG_FALSE;
    }
    sql_reset_vmctx(stmt);

    stmt->is_check = OG_FALSE;
    stmt->vm_lob_ids = NULL;
}

void sql_free_stmt(sql_stmt_t *stmt)
{
    if (stmt == NULL) {
        return;
    }

    if (stmt->status == STMT_STATUS_FREE) {
        return;
    }

    sql_release_lob_info(stmt);
    sql_release_resource(stmt, OG_TRUE);
    sql_release_context(stmt);
    stmt->status = STMT_STATUS_FREE;
    stmt->is_temp_alloc = OG_FALSE;
    stmt->parent_stmt = NULL;
    if (!stmt->eof) {
        stmt->eof = OG_TRUE;
        sql_dec_active_stmts(stmt);
    }
    stmt->session->stmts_cnt--;

    if (stmt->stat != NULL) {
        free(stmt->stat);
        stmt->stat = NULL;
    }
    stmt->into = NULL;
    stmt->outlines = NULL;
}

status_t sql_init_sequence(sql_stmt_t *stmt)
{
    uint32 count;
    sql_seq_t *item = NULL;

    if (stmt->context == NULL) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    if (stmt->context->sequences == NULL) {
        stmt->v_sequences = NULL;
        return OG_SUCCESS;
    }

    count = stmt->context->sequences->count;
    OG_RETURN_IFERR(sql_push(stmt, sizeof(sql_seq_t) * count, (void **)&stmt->v_sequences));

    for (uint32 i = 0; i < count; ++i) {
        item = (sql_seq_t *)cm_galist_get(stmt->context->sequences, i);
        stmt->v_sequences[i].seq = item->seq;
        stmt->v_sequences[i].flags = item->flags;
        stmt->v_sequences[i].processed = OG_FALSE;
        stmt->v_sequences[i].value = 0;
    }
    return OG_SUCCESS;
}

void sql_free_vmemory(sql_stmt_t *stmt)
{
    for (uint32 i = 0; i < stmt->vmc_list.count; ++i) {
        vmc_t *vmc = (vmc_t *)cm_galist_get(&stmt->vmc_list, i);
        vmc_free(vmc);
    }
    cm_galist_init(&stmt->vmc_list, &stmt->vmc, vmc_alloc_mem);
}

static status_t sql_recv_long_text(sql_stmt_t *stmt, cs_packet_t *cs_pack, text_t *sql)
{
    uint32 size;
    text_t text;
    uint32 buf_size;
    cm_stack_t *stack = stmt->session->stack;
    char *buf = (char *)stack->buf + stack->heap_offset;
    buf_size = sql_stack_remain_size(stmt);
    OG_RETURN_IFERR(srv_return_success(stmt->session));
    OG_RETURN_IFERR(cs_get_text(cs_pack, &text));
    if (text.len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, buf_size, text.str, text.len));
    }
    size = text.len;

    do {
        if (srv_wait_for_more_data(stmt->session) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cs_read(stmt->session->pipe, cs_pack, OG_FALSE) != OG_SUCCESS) {
            return OG_ERROR;
        }

        cs_init_get(cs_pack);
        OG_RETURN_IFERR(cs_get_text(cs_pack, &text));

        if (size + text.len > buf_size) {
            OG_THROW_ERROR(ERR_SQL_TOO_LONG, size + text.len);
            return OG_ERROR;
        }
        if (text.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(buf + size, buf_size - size, text.str, text.len));
        }
        size += text.len;

        if (!(cs_pack->head->flags & CS_FLAG_MORE_DATA)) {
            break;
        }
        OG_RETURN_IFERR(srv_return_success(stmt->session));
    } while (OG_TRUE);

    sql->str = buf;
    sql->len = size;

    stmt->session->stack->heap_offset += CM_ALIGN8(size);
    return OG_SUCCESS;
}

status_t sql_parse_job(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    sql_release_lob_info(stmt);
    sql_release_resource(stmt, OG_TRUE);
    sql_release_context(stmt);

    stmt->is_explain = OG_FALSE;

    if (sql_parse(stmt, sql, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }
    reset_tls_plc_error();
    if (stmt->context->params->count > 0) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Current position cannot use params");
        return OG_ERROR;
    }
    stmt->status = STMT_STATUS_PREPARED;
    return OG_SUCCESS;
}

void sql_reset_plsql_resource(sql_stmt_t *stmt)
{
    stmt->plsql_mode = PLSQL_NONE;
    stmt->pl_compiler = NULL;
    stmt->pl_exec = NULL;
    stmt->pl_failed = OG_FALSE;
    stmt->is_sub_stmt = OG_FALSE;
    stmt->parent_stmt = NULL;
}

static void sql_reset_stmt_resource(sql_stmt_t *stmt)
{
    stmt->query_scn = OG_INVALID_ID64;
    stmt->gts_scn = OG_INVALID_ID64;
    stmt->is_explain = OG_FALSE;
    stmt->is_reform_call = OG_FALSE;
    stmt->params_ready = OG_FALSE;
    stmt->text_shift = 0;
}

status_t sql_prepare_for_multi_sql(sql_stmt_t *stmt, text_t *sql)
{
    source_location_t loc;

    sql_release_resource(stmt, OG_TRUE);
    sql_release_context(stmt);

    if (sql->len > AGENT_STACK_SIZE) {
        OG_THROW_ERROR(ERR_SQL_TOO_LONG, sql->len);
        return OG_ERROR;
    }

    stmt->session->sql_audit.packet_sql = *sql;
    sql_reset_stmt_resource(stmt);
    loc.line = 1;
    loc.column = 1;

    if (sql_parse(stmt, sql, &loc) != OG_SUCCESS) {
        /* check whether is multiple sql when parsed failed */
        if (cm_is_multiple_sql(sql)) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_CLT_MULTIPLE_SQL);
        }
        return OG_ERROR;
    }

    if (sql_check_privilege(stmt, OG_TRUE) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }

    if (stmt->context->type == OGSQL_TYPE_SELECT) {
        OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "select can not be supported.");
        return OG_ERROR;
    }

    stmt->status = STMT_STATUS_PREPARED;
    return OG_SUCCESS;
}

void sql_log_param_change(sql_stmt_t *stmt, text_t sql)
{
    session_t *session = stmt->session;
    sql_type_t type = stmt->context->type;
    knl_alter_sys_def_t *alsys_def = (knl_alter_sys_def_t *)stmt->context->entry;
    knl_user_def_t *alusr_def = (knl_user_def_t *)stmt->context->entry;

    if (type == OGSQL_TYPE_ALTER_PROFILE || (type == OGSQL_TYPE_ALTER_SYSTEM && alsys_def->action ==
        ALTER_SYS_SET_PARAM) ||
        (type == OGSQL_TYPE_ALTER_USER && OG_BIT_TEST(alusr_def->mask, OG_GET_MASK(ALTER_USER_FIELD_PASSWORD)))) {
        sql_ignore_passwd_log(session, &sql);
        if (sql.str) {
            CM_NULL_TERM(&sql);
        }
        OG_LOG_RUN_WAR("prepare to change parameter, password or profile, user: %s, host: %s, sql: %s",
            session->db_user, session->os_host, sql.str);
    }
    return;
}

status_t sql_prepare(sql_stmt_t *stmt)
{
    text_t sql;
    cs_packet_t *cs_pack = NULL;
    source_location_t loc;

    sql_release_resource(stmt, OG_TRUE);
    sql_release_context(stmt);
    sql_reset_plsql_resource(stmt);

    cs_pack = stmt->session->recv_pack;
    if (cs_pack->head->flags & CS_FLAG_MORE_DATA) {
        if (sql_recv_long_text(stmt, cs_pack, &sql) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        OG_RETURN_IFERR(cs_get_text(cs_pack, &sql));
        if (sql.len > AGENT_STACK_SIZE) {
            OG_THROW_ERROR(ERR_SQL_TOO_LONG, sql.len);
            return OG_ERROR;
        }
    }
    stmt->session->sql_audit.packet_sql = sql;
    sql_reset_stmt_resource(stmt);
    loc.line = 1;
    loc.column = 1;

    stmt->status = STMT_STATUS_IDLE;
    if (sql_parse(stmt, &sql, &loc) != OG_SUCCESS) {
        /* check whether is multiple sql when parsed failed */
        if (cm_is_multiple_sql(&sql)) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_CLT_MULTIPLE_SQL);
        }
        return OG_ERROR;
    }

    if (sql_check_privilege(stmt, OG_TRUE) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }
    sql_log_param_change(stmt, sql);
    OG_RETURN_IFERR(my_sender(stmt)->send_parsed_stmt(stmt));

    stmt->status = STMT_STATUS_PREPARED;
    return OG_SUCCESS;
}

static status_t sql_reparse_in_sub_stmt(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    sql_stmt_t *sub_stmt = NULL;
    status_t status = OG_ERROR;

    OGSQL_SAVE_STACK(stmt);
    do {
        OG_BREAK_IF_ERROR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));
        sql_init_stmt(stmt->session, sub_stmt, stmt->id);
        SET_STMT_CONTEXT(sub_stmt, NULL);
        stmt->session->current_stmt = sub_stmt;
        // must decrease execute_count here, because context will be changed in sql_reparse
        sql_dec_ctx_ref(stmt, stmt->context);
        sub_stmt->is_sub_stmt = OG_TRUE;
        sub_stmt->parent_stmt = stmt;
        if (sql_parse(sub_stmt, sql, loc) == OG_SUCCESS) {
            if (sql_check_privilege(sub_stmt, OG_TRUE) == OG_SUCCESS) {
                status = OG_SUCCESS;
            } else {
                OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            }
        }
        stmt->session->current_stmt = stmt;
        stmt->context = sub_stmt->context;
        // increase execute_count for new context(OG_SUCCESS) or NULL(OG_ERROR)
        sql_inc_ctx_ref(stmt, stmt->context);
    } while (OG_FALSE);

    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, OG_TRUE);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_reparse(sql_stmt_t *stmt)
{
    text_t sql;
    vmc_t vmc;
    status_t status;
    source_location_t location;
    cm_reset_error();

    OG_LOG_DEBUG_INF("Begin reparse SQL");
    vmc_init(&stmt->session->vmp, &vmc);
    OG_RETURN_IFERR(vmc_alloc(&vmc, stmt->context->ctrl.text_size + 1, (void **)&sql.str));
    sql.len = stmt->context->ctrl.text_size + 1;
    if (ogx_read_text(sql_pool, &stmt->context->ctrl, &sql, OG_FALSE) != OG_SUCCESS) {
        vmc_free(&vmc);
        return OG_ERROR;
    }

    stmt->context->ctrl.valid = OG_FALSE;
    stmt->session->current_sql = CM_NULL_TEXT;
    sql_release_context(stmt);

    if (stmt->pl_exec) {
        pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;
        location = pl_exec->sql_loc;
    } else {
        location.line = 1;
        location.column = 1;
    }
    status = sql_reparse_in_sub_stmt(stmt, &sql, &location);
    vmc_free(&vmc);
    return status;
}

static inline void sql_write_debug_err_dml(sql_stmt_t *stmt)
{
    if (!LOG_DEBUG_ERR_ON || stmt->context == NULL) {
        return;
    }

    text_t sql_text;
    vmc_t vmc;
    vmc_init(&stmt->session->vmp, &vmc);
    if (vmc_alloc(&vmc, stmt->context->ctrl.text_size + 1, (void **)&sql_text.str) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Read dml context failed.");
        return;
    }
    sql_text.len = stmt->context->ctrl.text_size + 1;
    if (ogx_read_text(sql_pool, &stmt->context->ctrl, &sql_text, OG_FALSE) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Execute DML failed");
        vmc_free(&vmc);
        return;
    }
    OG_LOG_DEBUG_ERR("Execute DML failed, DML = %s", sql_text.str);
    vmc_free(&vmc);
}

static void sql_get_mutating_tables(sql_context_t *context, mutate_table_assist_t *table_ass)
{
    table_ass->type = 0;
    table_ass->table_count = 0;
    table_ass->table = NULL;

    switch (context->type) {
        case OGSQL_TYPE_SELECT:
            table_ass->type = ALL_TABLES;
            table_ass->tables = context->tables;
            table_ass->table_count = table_ass->tables->count;
            break;

        case OGSQL_TYPE_UPDATE: {
            sql_update_t *update_ctx = (sql_update_t *)context->entry;
            table_ass->type = UPD_TABLES;
            table_ass->tables = update_ctx->objects;
            table_ass->table_count = table_ass->tables->count;
            break;
        }

        case OGSQL_TYPE_INSERT: {
            sql_insert_t *insert_ctx = (sql_insert_t *)context->entry;
            table_ass->type = SINGLE_TABLE;
            table_ass->table = insert_ctx->table;
            table_ass->table_count = 1;
            break;
        }

        case OGSQL_TYPE_DELETE: {
            sql_delete_t *delete_ctx = (sql_delete_t *)context->entry;
            table_ass->type = DEL_TABLES;
            table_ass->tables = delete_ctx->objects;
            table_ass->table_count = table_ass->tables->count;
            break;
        }

        case OGSQL_TYPE_MERGE: {
            sql_merge_t *merge_ctx = (sql_merge_t *)context->entry;
            table_ass->type = SINGLE_TABLE;
            table_ass->table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
            table_ass->table_count = 1;
            break;
        }

        case OGSQL_TYPE_REPLACE: {
            sql_replace_t *replace_ctx = (sql_replace_t *)context->entry;
            table_ass->type = SINGLE_TABLE;
            table_ass->table = replace_ctx->insert_ctx.table;
            table_ass->table_count = 1;
            break;
        }

        default:
            break;
    }
}

static sql_table_entry_t *sql_get_parent_table(mutate_table_assist_t *table_ass, uint32 index)
{
    sql_table_entry_t *table = NULL;

    switch (table_ass->type) {
        case SINGLE_TABLE: {
            table = table_ass->table->entry;
            break;
        }

        case ALL_TABLES: {
            table = (sql_table_entry_t *)cm_galist_get(table_ass->tables, index);
            break;
        }

        case UPD_TABLES: {
            upd_object_t *upd_object = (upd_object_t *)cm_galist_get(table_ass->tables, index);
            table = upd_object->table->entry;
            break;
        }

        case DEL_TABLES: {
            del_object_t *del_object = (del_object_t *)cm_galist_get(table_ass->tables, index);
            table = del_object->table->entry;
            break;
        }

        default:
            break;
    }

    CM_ASSERT(table != NULL);
    return table;
}

static status_t sql_check_mutating_table(sql_stmt_t *stmt, sql_context_t *parent_ctx)
{
    sql_context_t *ogx = stmt->context;
    sql_table_entry_t *table = NULL;
    sql_table_entry_t *parent_table = NULL;
    mutate_table_assist_t table_ass;

    sql_get_mutating_tables(parent_ctx, &table_ass);
    for (uint32 i = 0; i < ogx->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(ogx->tables, i);
        for (uint32 j = 0; j < table_ass.table_count; j++) {
            parent_table = sql_get_parent_table(&table_ass, j);
            if (cm_text_equal_ins(&parent_table->user, &table->user) &&
                cm_text_equal_ins(&parent_table->name, &table->name)) {
                OG_THROW_ERROR(ERR_TAB_MUTATING, T2S(&table->user), T2S_EX(&table->name));
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

status_t sql_check_tables(sql_stmt_t *stmt, sql_context_t *ogx)
{
    sql_table_entry_t *table = NULL;

    if (ogx->tables != NULL) {
        for (uint32 i = 0; i < ogx->tables->count; i++) {
            table = (sql_table_entry_t *)cm_galist_get(ogx->tables, i);
            if (table == NULL) {
                continue;
            }

            if (knl_check_dc(KNL_SESSION(stmt), &table->dc) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t sql_check_pl_table(sql_stmt_t *stmt)
{
    sql_context_t *sql_ctx = stmt->context;
    sql_stmt_t *parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    sql_context_t *parent_ctx = NULL;
    pl_executor_t *pl_exec = NULL;
    pl_entity_t *pl_entity = NULL;
    uint32 trig_event;
    bool32 check_insert = OG_FALSE;

    // parent_ctx is not accurate when executing proc/trigger, pl_entity is preferred
    while (parent_stmt != NULL) {
        pl_entity = (pl_entity_t *)parent_stmt->pl_context;
        if (pl_entity != NULL) {
            switch (pl_entity->pl_type) {
                case PL_TRIGGER:
                    pl_exec = (pl_executor_t *)parent_stmt->pl_exec;
                    pl_entity = pl_exec->entity;
                    if (pl_entity->is_auton_trans) {
                        return OG_SUCCESS;
                    }
                    trig_event = pl_entity->trigger->desc.events;
                    if (pl_entity->trigger->desc.type == TRIG_INSTEAD_OF) {
                        return OG_SUCCESS;
                    }
                    if (pl_entity->trigger->desc.type == TRIG_AFTER_STATEMENT ||
                        pl_entity->trigger->desc.type == TRIG_BEFORE_STATEMENT) {
                        parent_stmt = (sql_stmt_t *)parent_stmt->parent_stmt;
                    } else if (trig_event == TRIG_EVENT_INSERT &&
                        pl_entity->trigger->desc.type == TRIG_AFTER_EACH_ROW) {
                        check_insert = OG_TRUE;
                    }
                    break;
                default:
                    pl_exec = (pl_executor_t *)parent_stmt->pl_exec;
                    pl_entity = pl_exec->entity;
                    if (pl_entity->is_auton_trans) {
                        return OG_SUCCESS;
                    }
                    break;
            }
        } else {
            parent_ctx = parent_stmt->context;
            switch (parent_ctx->type) {
                case OGSQL_TYPE_INSERT:
                    if (check_insert) {
                        OG_RETURN_IFERR(sql_check_mutating_table(stmt, parent_ctx));
                        check_insert = OG_FALSE;
                    }
                    break;
                case OGSQL_TYPE_UPDATE:
                case OGSQL_TYPE_DELETE:
                    OG_RETURN_IFERR(sql_check_mutating_table(stmt, parent_ctx));
                    break;
                case OGSQL_TYPE_REPLACE:
                case OGSQL_TYPE_MERGE:
                case OGSQL_TYPE_SELECT:
                    if (sql_ctx->type != OGSQL_TYPE_SELECT) {
                        OG_RETURN_IFERR(sql_check_mutating_table(stmt, parent_ctx));
                    }
                    break;
                default:
                    break;
            }
        }
        parent_stmt = (sql_stmt_t *)parent_stmt->parent_stmt;
    }
    return OG_SUCCESS;
}

status_t sql_check_ltt_dc(sql_stmt_t *stmt)
{
    if (!stmt->context->has_ltt) {
        return OG_SUCCESS;
    }

    sql_table_entry_t *table = NULL;
    for (uint32 i = 0; i < stmt->context->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, i);
        if (IS_LTT_BY_NAME(table->name.str)) {
            knl_session_t *curr = (knl_session_t *)knl_get_curr_sess();
            dc_entity_t *entity = DC_ENTITY(&table->dc);
            uint32 tab_id = entity->table.desc.id;
            dc_entry_t *entry = entity->entry;
            if (entry == NULL || tab_id < OG_LTT_ID_OFFSET ||
                tab_id >= (OG_LTT_ID_OFFSET + curr->temp_table_capacity)) {
                OG_THROW_ERROR(ERR_DC_INVALIDATED);
                return OG_ERROR;
            }

            dc_entry_t *sess_entry = (dc_entry_t *)curr->temp_dc->entries[tab_id - OG_LTT_ID_OFFSET];
            if (entry != sess_entry || table->dc.org_scn != sess_entry->org_scn) {
                OG_THROW_ERROR(ERR_DC_INVALIDATED);
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static inline status_t sql_execute_dml(sql_stmt_t *stmt)
{
    int32 code;
    const char *message = NULL;
    cs_packet_t *cs_pack = stmt->session->recv_pack;
    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    if (!stmt->is_sub_stmt) {
        OG_RETURN_IFERR(sql_prepare_params(stmt));
    }

    OG_RETURN_IFERR(sql_check_pl_table(stmt));
    OGSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_try_execute_dml(stmt) == OG_SUCCESS) {
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(knl_check_session_status(KNL_SESSION(stmt)));

        /* execute dml again if came to ERR_DC_INVALIDATED */
        cm_get_error(&code, &message, NULL);
        if (code != ERR_DC_INVALIDATED) {
            if (stmt->auto_commit) {
                do_rollback(stmt->session, NULL);
            }

            sql_write_debug_err_dml(stmt);
            return OG_ERROR;
        }

        if (sql_reparse(stmt) != OG_SUCCESS) {
            if (stmt->auto_commit) {
                do_rollback(stmt->session, NULL);
            }

            OG_LOG_DEBUG_ERR("reparse SQL failed");
            return OG_ERROR;
        }
        cm_reset_error();
        cm_spin_lock(&stmt->session->sess_lock, NULL);
        ogx_read_first_page_text(sql_pool, &stmt->context->ctrl, &stmt->session->current_sql);
        cm_spin_unlock(&stmt->session->sess_lock);

        /* reset params address in request packet for continue execute */
        if (!stmt->is_sub_stmt && stmt->context->params->count > 0 && cs_pack != NULL) {
            cs_pack->offset = stmt->param_info.param_offset;
        }
        OGSQL_RESTORE_STACK(stmt);
    }
}

static inline status_t sql_execute_dml_and_send(sql_stmt_t *stmt)
{
    if (my_sender(stmt)->send_exec_begin(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_execute_dml(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    my_sender(stmt)->send_exec_end(stmt);

    return OG_SUCCESS;
}

static inline status_t sql_execute_expl_and_send(sql_stmt_t *stmt)
{
    sql_reset_first_exec_vars(stmt);

    if (my_sender(stmt)->send_exec_begin(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (expl_execute(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    my_sender(stmt)->send_exec_end(stmt);

    return OG_SUCCESS;
}

static status_t sql_init_trigger_list_core(sql_stmt_t *stmt)
{
    if (vmc_alloc(&stmt->vmc, sizeof(galist_t), (void **)&stmt->trigger_list) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cm_galist_init(stmt->trigger_list, &stmt->vmc, vmc_alloc);
    stmt->resource_inuse = OG_TRUE;
    return OG_SUCCESS;
}

status_t sql_init_trigger_list(sql_stmt_t *stmt)
{
    if (stmt->trigger_list != NULL) {
        return OG_SUCCESS;
    }
    return sql_init_trigger_list_core(stmt);
}

static status_t sql_init_ref_dc_list(sql_stmt_t *stmt)
{
    if (vmc_alloc(&stmt->vmc, sizeof(galist_t), (void **)&stmt->pl_ref_entry) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cm_galist_init(stmt->pl_ref_entry, &stmt->vmc, vmc_alloc);
    stmt->resource_inuse = OG_TRUE;
    stmt->has_pl_ref_dc = OG_TRUE;
    return OG_SUCCESS;
}

status_t sql_init_pl_ref_dc(sql_stmt_t *stmt)
{
    if (stmt->pl_ref_entry != NULL) {
        return OG_SUCCESS;
    }
    return sql_init_ref_dc_list(stmt);
}

static inline void init_stmt(sql_stmt_t *stmt)
{
    stmt->total_rows = 0;
    stmt->batch_rows = 0;
    stmt->actual_batch_errs = 0;
    stmt->pairs_pos = 0;
    stmt->mark_pending_done = OG_FALSE;
    stmt->param_info.paramset_offset = 0;
    stmt->dc_invalid = OG_FALSE;
    stmt->default_info.default_on = OG_FALSE;
    stmt->is_success = OG_FALSE;
    stmt->trace_disabled = OG_FALSE;
    if (stmt->plsql_mode == PLSQL_NONE) {
        stmt->param_info.param_buf = NULL;
        stmt->param_info.param_types = NULL;
        stmt->param_info.params = NULL;
        stmt->params_ready = OG_FALSE;
        stmt->param_info.param_offset = 0;
        stmt->param_info.param_strsize = 0;
    }
}

void sql_unlock_lnk_tabs(sql_stmt_t *stmt)
{
    if (stmt->context == NULL || stmt->context->has_dblink == OG_FALSE) {
        return;
    }
}

static inline status_t sql_check_pre_exec(sql_stmt_t *stmt)
{
    if (stmt->is_verifying != OG_TRUE && (stmt->status < STMT_STATUS_PREPARED || stmt->context == NULL)) {
        OG_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "prepared.");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void sql_release_exec_resource(sql_stmt_t *stmt)
{
    if (stmt->context == NULL) {
        return;
    }
    if (stmt->eof) {
        sql_unlock_lnk_tabs(stmt);
        sql_release_resource(stmt, OG_FALSE);
        sql_dec_active_stmts(stmt);
    }
    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        sql_release_context(stmt);
    }
    stmt->fexec_info.first_exec_vars = NULL;
}

static status_t sql_init_exec_data(sql_stmt_t *stmt)
{
    init_stmt(stmt);
    sql_release_resource(stmt, OG_FALSE);
    reset_tls_plc_error();

    /* reset reserved values */
    stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
    stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
    OG_RETURN_IFERR(sql_init_sequence(stmt));
    OG_RETURN_IFERR(sql_init_first_exec_info(stmt));
    OG_RETURN_IFERR(sql_init_trigger_list(stmt));
    return sql_init_pl_ref_dc(stmt);
}

status_t sql_execute(sql_stmt_t *stmt)
{
    status_t status = OG_SUCCESS;
    timeval_t tv_begin;

    /* execute DDL/DCL multi-times after prepare will cause null pointer access for context */
    if (sql_check_pre_exec(stmt) != OG_SUCCESS) {
        sql_release_exec_resource(stmt);
        return OG_ERROR;
    }
    (void)cm_gettimeofday(&tv_begin);
    STATIC_SAVE_STMT(stmt);
    stmt->status = STMT_STATUS_EXECUTING;
    sql_begin_ctx_stat(stmt);
    if (sql_init_exec_data(stmt) != OG_SUCCESS) {
        sql_end_ctx_stat(stmt);
        STATIC_RESTORE_STMT(stmt);
        sql_release_exec_resource(stmt);
        return OG_ERROR;
    }

    bool32 stmt_eof = stmt->eof;
    /* must do it at last!!! */
    if (stmt_eof) {
        stmt->eof = OG_FALSE;
        sql_inc_active_stmts(stmt);
    }
    sql_inc_ctx_ref(stmt, stmt->context);

    if (sql_check_privilege(stmt, OG_FALSE) != OG_SUCCESS) {
        sql_dec_ctx_ref(stmt, stmt->context);
        if (stmt_eof) {
            sql_dec_active_stmts(stmt);
        }
        sql_end_ctx_stat(stmt);
        STATIC_RESTORE_STMT(stmt);
        sql_release_exec_resource(stmt);
        cm_reset_error();
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }

    /* do execute */
    if (stmt->is_explain) {
        status = sql_execute_expl_and_send(stmt);
    } else if (SQL_TYPE(stmt) < OGSQL_TYPE_DML_CEIL) {
        status = sql_execute_dml_and_send(stmt);
    } else if (SQL_TYPE(stmt) == OGSQL_TYPE_ANONYMOUS_BLOCK) {
        status = ple_exec_anonymous_block(stmt);
        stmt->eof = OG_TRUE;
    } else if (SQL_TYPE(stmt) < OGSQL_TYPE_DCL_CEIL) {
        status = sql_execute_dcl(stmt);
        stmt->eof = OG_TRUE;
    } else if (SQL_TYPE(stmt) < OGSQL_TYPE_DDL_CEIL) {
        status = sql_execute_ddl(stmt);
        stmt->eof = OG_TRUE;
    }

    sql_end_ctx_stat(stmt);
    STATIC_RESTORE_STMT(stmt);
    stmt->status = STMT_STATUS_EXECUTED;

    if (status == OG_SUCCESS) {
        stmt->is_success = OG_TRUE;
        OG_LOG_DEBUG_INF("Execute SQL successfully");
    }

    sql_release_exec_resource(stmt);
    return status;
}

static sql_table_t g_init_table = {
    .id = 0,
    .type = NORMAL_TABLE,
    .remote_type = REMOTE_TYPE_LOCAL
};

status_t sql_init_first_exec_info(sql_stmt_t *stmt)
{
    /* init first execute vars */
    uint32 count = stmt->context->fexec_vars_cnt;
    if (count != 0) {
        // the memory of first executable variants comes from stack, as well as
        // the memory of var-length variants, such as VARCHAR, BINARY, RAW
        // see @sql_copy_first_exec_var
        OG_RETURN_IFERR(cm_stack_alloc(stmt->session->stack,
            sizeof(variant_t) * count + stmt->context->fexec_vars_bytes, (void **)&stmt->fexec_info.first_exec_vars));
        sql_reset_first_exec_vars(stmt);
    } else {
        stmt->fexec_info.first_exec_vars = NULL;
    }

    /* init first execute subs */
    stmt->fexec_info.first_exec_subs = NULL;

    return OG_SUCCESS;
}

status_t sql_get_table_value(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value)
{
    sql_table_cursor_t *tab_cur = NULL;
    sql_cursor_t *cursor = OGSQL_CURR_CURSOR(stmt);

    if (SECUREC_UNLIKELY(stmt->is_explain)) {
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    /* get value from par cursor */
    cursor = sql_get_proj_cursor(cursor);
    /* hit scenario: multi table update, check cond column expr var_column_t->tab always 0 */
    if (SECUREC_UNLIKELY(stmt->is_check && cursor->table_count > 1)) {
        return sql_get_ddm_kernel_value(stmt, &g_init_table, stmt->direct_knl_cursor, v_col, value);
    }

    OG_RETURN_IFERR(sql_get_ancestor_cursor(cursor, v_col->ancestor, &cursor));
    tab_cur = &cursor->tables[v_col->tab];
    if (tab_cur->table == NULL) {
        OG_THROW_ERROR(ERR_ASSERT_ERROR, "table cannot be NULL");
        return OG_ERROR;
    }

    if (SECUREC_UNLIKELY(cursor->table_count != 1 && tab_cur->table->plan_id > cursor->last_table)) {
        value->type = OG_TYPE_COLUMN;
        value->is_null = OG_FALSE;
        return OG_SUCCESS;
    }

    if (!OG_IS_SUBSELECT_TABLE(tab_cur->table->type)) {
        return sql_get_ddm_kernel_value(stmt, tab_cur->table, tab_cur->knl_cur, v_col, value);
    }

    return sql_get_col_rs_value(stmt, tab_cur->sql_cur, v_col->col, v_col, value);
}

status_t sql_convert_data2variant(sql_stmt_t *stmt, char *ptr, uint32 len, uint32 is_null, variant_t *value)
{
    if (len == OG_NULL_VALUE_LEN || is_null) {
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    value->is_null = OG_FALSE;
    switch (value->type) {
        case OG_TYPE_UINT32:
            VALUE(uint32, value) = *(uint32 *)ptr;
            break;
        case OG_TYPE_INTEGER:
            VALUE(int32, value) = *(int32 *)ptr;
            break;
        case OG_TYPE_BOOLEAN:
            VALUE(bool32, value) = *(bool32 *)ptr;
            break;
        case OG_TYPE_BIGINT:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            VALUE(int64, value) = *(int64 *)ptr;
            break;
        case OG_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)ptr;
            break;
        case OG_TYPE_REAL:
            VALUE(double, value) = *(double *)ptr;
            break;
        case OG_TYPE_NUMBER:
#ifdef USE_NUMBER_DATA_TYPE
            SEC_MEM_RETURN_IFERR(memcpy_s(VALUE_PTR(number_t, value), sizeof(number_t), ptr, sizeof(number_t)));
            break;
#endif
        case OG_TYPE_DECIMAL:
            OG_RETURN_IFERR(cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ptr, len));
            break;
        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ptr, len));
            break;
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
            VALUE_PTR(text_t, value)->str = ptr;
            VALUE_PTR(text_t, value)->len = len;
            break;

        case OG_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)ptr;
            break;

        case OG_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)ptr;
            break;
        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE: {
            uint32 lob_type;
            lob_type = *(uint32 *)(ptr + sizeof(uint32));
            VALUE_PTR(var_lob_t, value)->type = lob_type;

            if (lob_type == OG_LOB_FROM_KERNEL) {
                VALUE_PTR(var_lob_t, value)->knl_lob.bytes = (uint8 *)ptr;
                VALUE_PTR(var_lob_t, value)->knl_lob.size = len;
            } else {
                VALUE_PTR(var_lob_t, value)->vm_lob = *(vm_lob_t *)ptr;
            }
            break;
        }

        default:
            VALUE_PTR(binary_t, value)->bytes = (uint8 *)ptr;
            VALUE_PTR(binary_t, value)->size = len;
            break;
    }

    return OG_SUCCESS;
}

static status_t sql_keep_in_params(sql_stmt_t *stmt)
{
    if (stmt->context->in_params == NULL || stmt->context->in_params->count == 0) {
        return OG_SUCCESS;
    }

    uint32 i;
    uint32 buffer_size;
    uint32 used_size;
    char *param_buffer = NULL;
    sql_param_t *param = NULL;
    sql_param_mark_t *param_mark = NULL;
    variant_t *p_vars = NULL;
    uint32 param_count = stmt->context->in_params->count;

    used_size = 0;
    buffer_size = sizeof(uint32) + param_count * sizeof(variant_t);

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, buffer_size, (void **)&param_buffer));

    *(uint32 *)param_buffer = param_count;
    used_size += sizeof(uint32);
    p_vars = (variant_t *)(param_buffer + used_size);

    for (i = 0; i < param_count; ++i) {
        param_mark = (sql_param_mark_t *)cm_galist_get(stmt->context->in_params, i);
        param = &stmt->param_info.params[param_mark->pnid];

        if (param->value.is_null) {
            break;
        }

        p_vars[i] = param->value;
        used_size += sizeof(variant_t);
    }

    *(uint32 *)param_buffer = i;

    if (vmc_alloc(&stmt->vmc, used_size, (void **)&stmt->in_param_buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    errno_t ret = memcpy_sp(stmt->in_param_buf, used_size, param_buffer, used_size);
    if (ret != EOK) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_read_kept_in_params(sql_stmt_t *stmt)
{
    if (stmt->in_param_buf == NULL) {
        return OG_SUCCESS;
    }

    uint32 i;
    uint32 var_cnt;
    char *param_buffer = NULL;
    variant_t *p_var = NULL;
    sql_param_t *param = NULL;
    sql_param_mark_t *param_mark = NULL;
    uint32 count = stmt->context->in_params->count;

    param_buffer = stmt->in_param_buf;
    var_cnt = *(uint32 *)param_buffer;
    p_var = (variant_t *)(param_buffer + sizeof(uint32));

    for (i = 0; i < count; ++i) {
        param_mark = (sql_param_mark_t *)cm_galist_get(stmt->context->in_params, i);
        param = &stmt->param_info.params[param_mark->pnid];

        if (i < var_cnt) {
            param->value = p_var[i];
        } else {
            param->value.is_null = OG_TRUE;
        }
    }

    return OG_SUCCESS;
}

status_t sql_get_rowid(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value)
{
    rowid_t row_id;
    sql_table_cursor_t *tab_cur = NULL;

    CM_POINTER2(stmt, value);
    sql_cursor_t *cursor = OGSQL_CURR_CURSOR(stmt);

    OG_RETURN_IFERR(sql_get_ancestor_cursor(cursor, rowid->ancestor, &cursor));
    tab_cur = &cursor->tables[rowid->tab_id];

    if (cursor->table_count > 1 && tab_cur->table->plan_id > cursor->last_table) {
        value->type = OG_TYPE_COLUMN;
        value->is_null = OG_FALSE;
        return OG_SUCCESS;
    }

    if (tab_cur->knl_cur->eof) {
        value->type = OG_TYPE_STRING;
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    value->type = OG_TYPE_STRING;
    value->is_null = OG_FALSE;
    row_id = tab_cur->knl_cur->rowid;

    // hit hash join fill null record
    if (sql_is_invalid_rowid(&row_id, tab_cur->table->entry->dc.type)) {
        value->type = OG_TYPE_STRING;
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    if (sql_push(stmt, OG_MAX_ROWID_BUFLEN, (void **)&value->v_text.str) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql_rowid2str(&row_id, value, tab_cur->table->entry->dc.type);

    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

status_t sql_get_rowscn(sql_stmt_t *stmt, var_rowid_t *rowid, variant_t *value)
{
    CM_POINTER2(stmt, value);
    sql_cursor_t *cursor = OGSQL_CURR_CURSOR(stmt);
    sql_table_cursor_t *tab_cur = NULL;
    OG_RETURN_IFERR(sql_get_ancestor_cursor(cursor, rowid->ancestor, &cursor));
    tab_cur = &cursor->tables[rowid->tab_id];

    if (cursor->table_count > 1 && tab_cur->table->plan_id > cursor->last_table) {
        value->type = OG_TYPE_COLUMN;
        value->is_null = OG_FALSE;
        return OG_SUCCESS;
    }

    if (tab_cur->knl_cur->eof) {
        value->type = OG_TYPE_STRING;
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    // revers?
    value->type = OG_TYPE_BIGINT;
    value->is_null = OG_FALSE;
    value->v_bigint = (int64)tab_cur->knl_cur->scn;

    return OG_SUCCESS;
}

status_t sql_get_rownum(sql_stmt_t *stmt, variant_t *value)
{
    sql_cursor_t *cursor = NULL;
    CM_POINTER2(stmt, value);

    cursor = OGSQL_CURR_CURSOR(stmt);
    // rownum is judged only on the last join table
    if (cursor->table_count > 1 && cursor->last_table < cursor->table_count - 1) {
        value->type = OG_TYPE_COLUMN;
        value->is_null = OG_FALSE;
        return OG_SUCCESS;
    }

    value->type = OG_TYPE_INTEGER;
    value->is_null = OG_FALSE;
    value->v_int = (int32)cursor->rownum;

    return OG_SUCCESS;
}
void *sql_get_plan(sql_stmt_t *stmt)
{
    switch (stmt->context->type) {
        case OGSQL_TYPE_DELETE:
            return ((sql_delete_t *)stmt->context->entry)->plan;

        case OGSQL_TYPE_INSERT:
            return ((sql_insert_t *)stmt->context->entry)->plan;

        case OGSQL_TYPE_UPDATE:
            return ((sql_update_t *)stmt->context->entry)->plan;

        case OGSQL_TYPE_SELECT:
            return ((sql_select_t *)stmt->context->entry)->plan;

        case OGSQL_TYPE_MERGE:
            return ((sql_merge_t *)stmt->context->entry)->plan;

        case OGSQL_TYPE_REPLACE:
            return ((sql_replace_t *)stmt->context->entry)->insert_ctx.plan;

        default:
            return NULL;
    }
}

status_t sql_execute_directly2(session_t *session, text_t *sql)
{
    return sql_execute_directly(session, sql, NULL, OG_TRUE);
}

status_t sql_execute_directly(session_t *session, text_t *sql, sql_type_t *type, bool32 check_priv)
{
    sql_stmt_t *stmt = NULL;
    status_t status;
    sql_audit_t sql_audit;
    source_location_t location;

    if (sql->len == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_get_unnamed_stmt(session, &session->current_stmt));

    /* prepare stmt */
    stmt = session->current_stmt;
    sql_release_lob_info(stmt);
    sql_release_resource(stmt, OG_TRUE);
    sql_release_context(stmt);

    stmt->is_explain = OG_FALSE;
    if (sql->str[(sql->len - 1)] == ';') {
        sql->len--;
    }
    location.line = 1;
    location.column = 1;

    sql_audit = stmt->session->sql_audit;
    if (sql_parse(stmt, sql, &location) != OG_SUCCESS) {
        stmt->session->sql_audit = sql_audit;
        return OG_ERROR;
    }

    stmt->status = STMT_STATUS_PREPARED;

    if (type != NULL) {
        *type = stmt->context->type;
    }

    /* execute and reply to psql */
    stmt->chk_priv = (bool8)check_priv;
    status = sql_execute(stmt);
    stmt->session->stat.directly_execs++;
    stmt->session->sql_audit = sql_audit;
    stmt->chk_priv = OG_TRUE;
    return status;
}

static inline void sql_reset_sess_stmt(session_t *session, sql_stmt_t *save_curr_stmt, sql_stmt_t *save_unnamed_stmt)
{
    context_ctrl_t *ctrl = NULL;
    if (session->unnamed_stmt != NULL && session->unnamed_stmt->context != NULL) {
        ctrl = &session->unnamed_stmt->context->ctrl;
        cm_spin_lock(&ctrl->lock, NULL);
        ctrl->valid = OG_FALSE;
        cm_spin_unlock(&ctrl->lock);
    }

    sql_free_stmt(session->unnamed_stmt);
    session->current_stmt = save_curr_stmt;
    session->unnamed_stmt = save_unnamed_stmt;
}
status_t sql_execute_check(knl_handle_t handle, text_t *sql, bool32 *exist)
{
    session_t *session = (session_t *)handle;

    sql_stmt_t *save_curr_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    char *send_pack_buf = NULL;
    uint32 send_pack_size;
    errno_t errcode;

    *exist = OG_FALSE;

    if (session->unnamed_stmt != NULL) {
        session->unnamed_stmt = NULL;
    }

    /* save prepared send pack */
    send_pack_size = session->send_pack->head->size;
    OG_RETURN_IFERR(sql_push(save_curr_stmt, send_pack_size, (void **)&send_pack_buf));
    errcode = memcpy_s(send_pack_buf, send_pack_size, session->send_pack->buf, send_pack_size);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        OGSQL_POP(save_curr_stmt);
        return OG_ERROR;
    }

    if (sql_execute_directly(session, sql, NULL, OG_FALSE) != OG_SUCCESS) {
        sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
        OGSQL_POP(save_curr_stmt);
        return OG_ERROR;
    }
    errno_t ret = memcpy_s(session->send_pack->buf, send_pack_size, send_pack_buf, send_pack_size);
    if (ret != EOK) {
        sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
        OGSQL_POP(save_curr_stmt);
        return OG_ERROR;
    }
    /* restore prepared send pack */
    OGSQL_POP(save_curr_stmt);

    if (session->unnamed_stmt->total_rows != 0) {
        *exist = OG_TRUE;
    }

    sql_reset_sess_stmt(session, save_curr_stmt, save_unnamed_stmt);
    return OG_SUCCESS;
}

status_t sql_check_exist_cols_type(sql_stmt_t *stmt, uint32 col_type, bool32 *exist)
{
    status_t status;
    text_t sql;
    char *clause = NULL;
    uint32 len = OG_EXIST_COL_TYPE_SQL_LEN + 2 * OG_MAX_NAME_LEN;
    errno_t iret_len;

    OG_RETURN_IFERR(sql_push(stmt, len, (void **)&clause));

    iret_len =
        snprintf_s(clause, len, len - 1, OG_EXIST_COL_TYPE_SQL_FORMAT, SYS_USER_NAME, SYS_COLUMN_TABLE_NAME, col_type);
    if (iret_len == -1) {
        OGSQL_POP(stmt);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_len);
        return OG_ERROR;
    }

    sql.len = (uint32)iret_len;
    sql.str = clause;
    status = sql_execute_check((void *)stmt->session, &sql, exist);
    OGSQL_POP(stmt);

    return status;
}

status_t sql_alloc_mem_from_dc(void *mem, uint32 size, void **buf)
{
    if (dc_alloc_mem(&g_instance->kernel.dc_ctx, (memory_context_t *)mem, size, buf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    errno_t err = memset_s(*buf, size, 0, size);
    MEMS_RETURN_IFERR(err);

    return OG_SUCCESS;
}

void sql_convert_column_t(knl_column_t *column, knl_column_def_t *col_def)
{
    /* mainly used */
    col_def->name.str = column->name;
    col_def->name.len = (uint32)strlen(column->name);

    col_def->typmod.datatype = column->datatype;
    col_def->typmod.size = column->size;
    col_def->typmod.precision = column->precision;
    col_def->typmod.scale = column->scale;
    if (OG_IS_STRING_TYPE(column->datatype)) {
        col_def->typmod.is_char = KNL_COLUMN_IS_CHARACTER(column);
    }
    if (KNL_COLUMN_HAS_QUOTE(column)) {
        col_def->has_quote = OG_TRUE;
    }
    col_def->default_text.str = column->default_text.str;
    col_def->default_text.len = column->default_text.len;

    return;
}

static status_t sql_clone_default_expr_tree(session_t *session, memory_context_t *memory, expr_tree_t *expr_tree_src,
    void **expr_tree, expr_tree_t *expr_update_tree_src, void **expr_update_tree)
{
    status_t status;

    status = sql_clone_expr_tree(memory, expr_tree_src, (expr_tree_t **)expr_tree, sql_alloc_mem_from_dc);
    if (status != OG_SUCCESS) {
        return status;
    }

    if (expr_update_tree_src != NULL) {
        status =
            sql_clone_expr_tree(memory, expr_update_tree_src, (expr_tree_t **)expr_update_tree, sql_alloc_mem_from_dc);
        if (status != OG_SUCCESS) {
            return status;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_verify_virtual_column_expr(sql_verifier_t *verif, knl_handle_t entity, expr_tree_t *expr_tree)
{
    sql_table_t table;
    sql_table_entry_t entry;

    MEMS_RETURN_IFERR(memset_s(&table, sizeof(sql_table_t), 0, sizeof(sql_table_t)));

    entry.dc.type = DICT_TYPE_TABLE;
    entry.dc.handle = entity;
    table.entry = &entry;
    knl_table_desc_t *desc = knl_get_table(&entry.dc);

    entry.dblink.len = 0;
    entry.user.len = 0;
    cm_str2text(desc->name, &entry.name);

    table.id = 0;
    table.type = NORMAL_TABLE;
    table.name.value = entry.name;

    verif->is_check_cons = OG_FALSE;
    verif->table = &table;
    verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_SEQUENCE |
        SQL_EXCL_ROWNODEID;

    return sql_verify_expr(verif, expr_tree);
}

status_t sql_verify_column_expr_tree(sql_verifier_t *verif, knl_column_t *column, expr_tree_t *expr_tree_src,
    expr_tree_t *expr_update_tree_src)
{
    knl_column_def_t col_def;
    sql_convert_column_t(column, &col_def);

    verif->column = &col_def;
    verif->excl_flags = SQL_DEFAULT_EXCL;

    if (sql_verify_column_default_expr(verif, expr_tree_src, &col_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (expr_update_tree_src != NULL) {
        if (sql_verify_column_default_expr(verif, expr_update_tree_src, &col_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_ajust_node_type(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN) {
        (*node)->type = EXPR_NODE_DIRECT_COLUMN;
    }

    return OG_SUCCESS;
}

static status_t sql_create_expr_tree_from_text(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **expr_tree,
    expr_tree_t **expr_update_tree, text_t parse_text)
{
    typmode_t col_data_type;
    lex_t *lex = NULL;
    word_t word;
    status_t status;
    uint32 src_lex_flags;
    CM_POINTER4(stmt, column, expr_tree, expr_update_tree);
    word.id = RES_WORD_DEFAULT;
    lex = stmt->session->lex;
    lex->infer_numtype = USE_NATIVE_DATATYPE;
    src_lex_flags = lex->flags;

    word.type = WORD_TYPE_RESERVED;
    word.begin_addr = parse_text.str;
    word.loc.line = 1;
    word.loc.column = 1;
    word.text.value.str = parse_text.str;
    word.text.value.len = parse_text.len;
    word.text.loc.line = 1;
    word.text.loc.column = 1;

    if (lex_push(lex, &word.text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    status = sql_create_expr_until(stmt, expr_tree, &word);
    if (status != OG_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        return status;
    }

    // add cast node for normal column
    if (!KNL_COLUMN_IS_VIRTUAL(column)) {
        col_data_type.datatype = column->datatype;
        col_data_type.size = column->size;
        col_data_type.precision = column->precision;
        col_data_type.scale = column->scale;
        col_data_type.is_array = KNL_COLUMN_IS_ARRAY(column);

        if (sql_build_cast_expr(stmt, TREE_LOC(*expr_tree), *expr_tree, &col_data_type, expr_tree) != OG_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_CAST_TO_COLUMN, "default value", T2S(&word.text.value));
            return OG_ERROR;
        }
    } else {
        visit_assist_t va;
        sql_init_visit_assist(&va, stmt, NULL);
        OG_RETURN_IFERR(visit_expr_tree(&va, *expr_tree, sql_ajust_node_type));
    }

    if (word.id == KEY_WORD_ON) {
        status = lex_expected_fetch_word(lex, "UPDATE");
        if (status != OG_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            return status;
        }

        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        status = sql_create_expr_until(stmt, expr_update_tree, &word);
        if (status != OG_SUCCESS) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            return status;
        }

        if (OG_SUCCESS != sql_build_cast_expr(stmt, TREE_LOC(*expr_update_tree), *expr_update_tree, &col_data_type,
            expr_update_tree)) {
            lex_pop(lex);
            lex->flags = src_lex_flags;
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_CAST_TO_COLUMN, "update default value", T2S(&word.text.value));
            return OG_ERROR;
        }
    }

    lex_pop(lex);
    lex->flags = src_lex_flags;
    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "end of expression text expected but %s found",
            W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline void sql_inv_ctx_and_free_stmt(sql_stmt_t *stmt)
{
    if (stmt->context != NULL) {
        context_ctrl_t *ctrl = &stmt->context->ctrl;
        cm_spin_lock(&ctrl->lock, NULL);
        ctrl->valid = OG_FALSE;
        cm_spin_unlock(&ctrl->lock);
    }
    sql_free_stmt(stmt);
}

static status_t sql_prepare_new_stmt(session_t *session)
{
    status_t status;
    /* get a new stmt */
    if (sql_alloc_stmt(session, &session->current_stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status = sql_alloc_context(session->current_stmt);
    if (status != OG_SUCCESS) {
        sql_inv_ctx_and_free_stmt(session->current_stmt);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline void sql_restore_session(session_t *session, sql_stmt_t *curr_stmt, sql_stmt_t *unname_stmt, lex_t *lex)
{
    session->current_stmt = curr_stmt;
    session->unnamed_stmt = unname_stmt;
    session->lex = lex;
}

status_t sql_parse_default_from_text(knl_handle_t handle, knl_handle_t dc_entity, knl_handle_t column,
    memory_context_t *memory, void **expr_tree, void **expr_update_tree, text_t parse_text)
{
    status_t status = OG_ERROR;
    knl_column_t *col_info = (knl_column_t *)column;
    session_t *session = (session_t *)handle;
    sql_stmt_t *save_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    lex_t *save_lex = session->lex;
    expr_tree_t *expr_tree_src = NULL;
    expr_tree_t *expr_update_src = NULL;
    saved_schema_t schema;

    (*expr_tree) = (*expr_update_tree) = NULL;

    if (parse_text.len == 0) {
        return OG_SUCCESS;
    }

    if (sql_prepare_new_stmt(session) != OG_SUCCESS) {
        sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
        return OG_ERROR;
    }
    sql_stmt_t *parse_expr_stmt = session->current_stmt;

    do {
        /* create the default expr tree */
        parse_expr_stmt->context->type = OGSQL_TYPE_CREATE_EXPR_FROM_TEXT;
        OG_BREAK_IF_ERROR(sql_create_expr_tree_from_text(parse_expr_stmt, col_info, &expr_tree_src,
            &expr_update_src, parse_text));

        (void)sql_switch_schema_by_uid(parse_expr_stmt, ((dc_entity_t *)dc_entity)->entry->uid, &schema);
        sql_verifier_t verif = { 0 };
        verif.stmt = parse_expr_stmt;
        verif.context = parse_expr_stmt->context;
        verif.do_expr_optmz = OG_FALSE;
        verif.from_table_define = OG_TRUE;
        /* verify the default expr tree */
        if (KNL_COLUMN_IS_VIRTUAL(col_info)) {
            status = sql_verify_virtual_column_expr(&verif, dc_entity, expr_tree_src);
        } else {
            status = sql_verify_column_expr_tree(&verif, col_info, expr_tree_src, expr_update_src);
        }
        sql_restore_schema(parse_expr_stmt, &schema);
        OG_BREAK_IF_ERROR(status);

        /* deeply copy the default expr tree */
        status = sql_clone_default_expr_tree(session, memory, expr_tree_src, expr_tree, expr_update_src,
            expr_update_tree);
    } while (0);

    /* finally, free stmt and */
    sql_inv_ctx_and_free_stmt(parse_expr_stmt);
    sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
    return status;
}

status_t sql_verify_default_from_text(knl_handle_t handle, knl_handle_t column_handle, text_t parse_text)
{
    status_t status = OG_ERROR;
    knl_column_t *column = (knl_column_t *)column_handle;
    session_t *session = (session_t *)handle;
    sql_stmt_t *save_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    lex_t *save_lex = session->lex;
    expr_tree_t *expr_tree_src = NULL;
    expr_tree_t *expr_update_tree_src = NULL;

    if (parse_text.len == 0) {
        return OG_SUCCESS;
    }

    if (sql_prepare_new_stmt(session) != OG_SUCCESS) {
        sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
        return OG_ERROR;
    }
    sql_stmt_t *parse_expr_stmt = session->current_stmt;

    do {
        /* create the default expr tree */
        parse_expr_stmt->context->type = OGSQL_TYPE_CREATE_EXPR_FROM_TEXT;
        
        status = sql_create_expr_tree_from_text(parse_expr_stmt, column, &expr_tree_src,
                                                &expr_update_tree_src, parse_text);
        if (status != OG_SUCCESS) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
        }
        OG_BREAK_IF_ERROR(status);
        sql_verifier_t verif = { 0 };
        verif.stmt = parse_expr_stmt;
        verif.context = parse_expr_stmt->context;
        verif.do_expr_optmz = OG_FALSE;
        verif.from_table_define = OG_TRUE;
        /* verify the default expr tree */
        knl_panic(!KNL_COLUMN_IS_VIRTUAL(column));
        status = sql_verify_column_expr_tree(&verif, column, expr_tree_src, expr_update_tree_src);
        if (status != OG_SUCCESS) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
        }
        OG_BREAK_IF_ERROR(status);
    } while (0);

    /* finally, free stmt and */
    sql_inv_ctx_and_free_stmt(parse_expr_stmt);
    sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
    return status;
}

static status_t sql_create_cond_tree_from_text(sql_stmt_t *stmt, text_t *text, cond_tree_t **tree)
{
    lex_t *lex = NULL;
    word_t word;
    uint32 src_lex_flags;
    CM_POINTER3(stmt, text, tree);
    word.id = 0xFFFFFFFF;
    lex = stmt->session->lex;
    src_lex_flags = lex->flags;
    word.type = WORD_TYPE_BRACKET;
    word.begin_addr = text->str;
    word.loc.line = 1;
    word.loc.column = 1;
    word.text.value.str = text->str;
    word.text.value.len = text->len;
    word.text.loc.line = 1;
    word.text.loc.column = 1;

    if (lex_push(lex, &word.text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    if (sql_create_cond_until(stmt, tree, &word) != OG_SUCCESS) {
        lex_pop(lex);
        lex->flags = src_lex_flags;
        return OG_ERROR;
    }
    lex_pop(lex);
    lex->flags = src_lex_flags;
    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "end of condition text expected but %s found",
            W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_check_from_text(knl_handle_t handle, text_t *cond_text, knl_handle_t entity,
    memory_context_t *memory, void **cond_tree)
{
    status_t status = OG_ERROR;
    session_t *session = (session_t *)handle;
    sql_stmt_t *save_stmt = session->current_stmt;
    sql_stmt_t *save_unnamed_stmt = session->unnamed_stmt;
    lex_t *save_lex = session->lex;
    cond_tree_t *cond_tree_src = NULL;
    saved_schema_t schema;
    *cond_tree = NULL;

    if (sql_prepare_new_stmt(session) != OG_SUCCESS) {
        sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
        return OG_ERROR;
    }
    sql_stmt_t *parse_cond_stmt = session->current_stmt;

    do {
        /* create a check cond tree */
        parse_cond_stmt->context->type = OGSQL_TYPE_CREATE_CHECK_FROM_TEXT;
        OG_BREAK_IF_ERROR(sql_create_cond_tree_from_text(parse_cond_stmt, cond_text, &cond_tree_src));

        /* verfiy the check cond tree */
        sql_verifier_t verif = { 0 };
        verif.context = parse_cond_stmt->context;
        verif.context->type = OGSQL_TYPE_CREATE_CHECK_FROM_TEXT;
        verif.stmt = parse_cond_stmt;
        verif.is_check_cons = OG_TRUE;
        verif.dc_entity = entity;
        verif.do_expr_optmz = OG_FALSE;
        verif.excl_flags = SQL_CHECK_EXCL;
        verif.from_table_define = OG_TRUE;

        (void)sql_switch_schema_by_uid(parse_cond_stmt, ((dc_entity_t *)entity)->entry->uid, &schema);
        status = sql_verify_cond(&verif, cond_tree_src);
        sql_restore_schema(parse_cond_stmt, &schema);
        OG_BREAK_IF_ERROR(status);
        status = sql_clone_cond_tree(memory, cond_tree_src, (cond_tree_t **)cond_tree, sql_alloc_mem_from_dc);
    } while (0);

    /* deeply copy this cond tree */
    sql_inv_ctx_and_free_stmt(parse_cond_stmt);
    sql_restore_session(session, save_stmt, save_unnamed_stmt, save_lex);
    return status;
}


void sql_init_session(session_t *sess)
{
    sess->sender = &g_instance->sql.sender;
    sess->knl_session.match_cond = sql_match_cond;
    if (SECUREC_UNLIKELY(sess->knl_session.temp_pool == NULL)) {
        sess->knl_session.temp_pool = &g_instance->kernel.temp_pool[0];
        sess->knl_session.temp_mtrl->pool = &g_instance->kernel.temp_pool[0];
    }
}

static inline status_t sql_check_vm_lob(sql_stmt_t *stmt, vm_lob_t *vlob)
{
    status_t ret = OG_SUCCESS;
    id_list_t *vm_list = sql_get_pre_lob_list(stmt);
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    uint32 vm_id = vlob->entry_vmid;
    uint32 last_vm = vlob->last_vmid;
    uint32 vm_page_cnt = 1;

    if (vlob->size == 0) {
        return OG_SUCCESS;
    }

    do {
        if (sql_check_lob_vmid(vm_list, vm_pool, vm_id) != OG_SUCCESS) {
            ret = OG_ERROR;
            break;
        }
        vm_id = vm_get_ctrl(vm_pool, vm_id)->sort_next;
        if (vm_id != OG_INVALID_ID32) {
            vm_page_cnt++;
        }

        if (vm_id == last_vm) {
            if (sql_check_lob_vmid(vm_list, vm_pool, vm_id) != OG_SUCCESS) {
                ret = OG_ERROR;
            }

            break;
        }
    } while (vm_id != OG_INVALID_ID32);

    if (ret != OG_SUCCESS || ((uint64)vlob->size > (uint64)OG_VMEM_PAGE_SIZE * (uint64)vm_page_cnt)) {
        OG_THROW_ERROR(ERR_NO_FREE_VMEM, "invalid vmid when check lob");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* decode params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t sql_decode_params_eff(sql_stmt_t *stmt, char *param_buf, uint32 *actual_len)
{
    uint32 i;
    uint32 offset;
    uint32 count;
    uint8 *flags = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *val = NULL;
    text_t num_text;
    stmt->param_info.outparam_cnt = 0;
    count = stmt->context->params->count;

    // total_len
    offset = sizeof(uint32);
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
    stmt->session->recv_pack->offset += sizeof(uint32);

    // flags
    offset += CM_ALIGN4(count);
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, CM_ALIGN4(count));
    stmt->session->recv_pack->offset += CM_ALIGN4(count);
    flags = (uint8 *)(param_buf + sizeof(uint32));

    // bound_value
    for (i = 0; i < count; i++) {
        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(flags[i]);
        if (param->direction == OG_OUTPUT_PARAM || param->direction == OG_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }

        val = &param->value;
        val->is_null = cs_get_param_isnull(flags[i]);
        val->type = (stmt->param_info.param_types[i] == OG_TYPE_UNKNOWN) ?
            OG_TYPE_UNKNOWN :
            ((og_type_t)stmt->param_info.param_types[i] + OG_TYPE_BASE);

        if (param->direction == OG_OUTPUT_PARAM || val->is_null) {
            val->is_null = OG_TRUE;
            continue;
        }

        data = (char *)(param_buf + offset);

        switch (val->type) {
            case OG_TYPE_INTEGER:
                offset += sizeof(int32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int32));
                VALUE(int32, val) = *(int32 *)data;
                stmt->session->recv_pack->offset += sizeof(int32);
                break;

            case OG_TYPE_BIGINT:
            case OG_TYPE_DATE:
            case OG_TYPE_TIMESTAMP:
            case OG_TYPE_TIMESTAMP_TZ_FAKE:
            case OG_TYPE_TIMESTAMP_LTZ:
                offset += sizeof(int64);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int64));
                VALUE(int64, val) = *(int64 *)data;
                stmt->session->recv_pack->offset += sizeof(int64);
                break;

            case OG_TYPE_REAL:
                offset += sizeof(double);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(double));
                VALUE(double, val) = *(double *)data;
                stmt->session->recv_pack->offset += sizeof(double);
                break;

            case OG_TYPE_NUMBER:
            case OG_TYPE_DECIMAL:
            case OG_TYPE_NUMBER2:
                offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
                num_text.str = data + sizeof(uint32);
                num_text.len = *(uint32 *)data;
                stmt->param_info.param_strsize += num_text.len;
                OG_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, val)));
                stmt->session->recv_pack->offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                break;

            case OG_TYPE_BINARY:
            case OG_TYPE_VARBINARY:
            case OG_TYPE_RAW:
                val->v_bin.is_hex_const = OG_FALSE;
                /* fall-through */
            case OG_TYPE_CHAR:
            case OG_TYPE_VARCHAR:
            case OG_TYPE_STRING:
                offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
                val->v_text.len = *(uint32 *)data;
                stmt->param_info.param_strsize += val->v_text.len;
                val->v_text.str = data + sizeof(uint32);

                if (g_instance->sql.enable_empty_string_null) {
                    val->is_null = (val->v_text.len == 0);
                }
                stmt->session->recv_pack->offset += sizeof(uint32) + CM_ALIGN4(*(uint32 *)data);
                break;

            case OG_TYPE_CLOB:
            case OG_TYPE_BLOB:
            case OG_TYPE_IMAGE:
            case OG_TYPE_ARRAY:
                offset += sizeof(vm_cli_lob_t);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(vm_cli_lob_t));
                VALUE(var_lob_t, val).type = OG_LOB_FROM_VMPOOL;
                cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, val).vm_lob), (vm_cli_lob_t *)data);
                VALUE(var_lob_t, val).vm_lob.type = OG_LOB_FROM_VMPOOL;

                OG_RETURN_IFERR(sql_check_vm_lob(stmt, &(VALUE(var_lob_t, val).vm_lob)));

                if (g_instance->sql.enable_empty_string_null) {
                    val->is_null = (VALUE(var_lob_t, val).vm_lob.size == 0);
                }

                if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, val).vm_lob.size > 0) &&
                    (stmt->lob_info.inuse_count > 0)) {
                    stmt->lob_info.inuse_count--;
                }
                stmt->session->recv_pack->offset += sizeof(vm_cli_lob_t);
                if (val->type == OG_TYPE_ARRAY) {
                    VALUE(var_array_t, val).value.type = OG_LOB_FROM_VMPOOL;
                    cm_vmcli_lob2vm_lob(&(VALUE(var_array_t, val).value.vm_lob), (vm_cli_lob_t *)data);
                    VALUE(var_array_t, val).value.vm_lob.type = OG_LOB_FROM_VMPOOL;
                }
                break;

            case OG_TYPE_BOOLEAN:
                offset += sizeof(bool32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(bool32));
                VALUE(bool32, val) = *(bool32 *)data;
                stmt->session->recv_pack->offset += sizeof(bool32);
                break;

            case OG_TYPE_INTERVAL_YM:
                offset += sizeof(interval_ym_t);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(interval_ym_t));
                VALUE(interval_ym_t, val) = *(interval_ym_t *)data;
                stmt->session->recv_pack->offset += sizeof(interval_ym_t);
                break;

            case OG_TYPE_INTERVAL_DS:
                offset += sizeof(interval_ds_t);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(interval_ds_t));
                VALUE(interval_ds_t, val) = *(interval_ds_t *)data;
                stmt->session->recv_pack->offset += sizeof(interval_ds_t);
                break;

            case OG_TYPE_UINT32:
                offset += sizeof(uint32);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
                VALUE(uint32, val) = *(uint32 *)data;
                stmt->session->recv_pack->offset += sizeof(uint32);
                break;

            case OG_TYPE_TIMESTAMP_TZ:
                offset += sizeof(timestamp_tz_t);
                CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(timestamp_tz_t));
                VALUE(timestamp_tz_t, val) = *(timestamp_tz_t *)data;
                stmt->session->recv_pack->offset += sizeof(timestamp_tz_t);
                break;

            default:
                OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(val->type));
                return OG_ERROR;
        }
    }

    *actual_len = offset;
    return OG_SUCCESS;
}

static status_t sql_decode_plsql_params(sql_stmt_t *stmt)
{
    variant_t src;
    MEMS_RETURN_IFERR(memset_s(&src, sizeof(variant_t), 0, sizeof(variant_t)));
    sql_stmt_t *parent = NULL;
    pl_using_expr_t *using_expr = NULL;
    sql_param_mark_t *param_mark = NULL;
    sql_param_t *param = NULL;

    if (ple_get_dynsql_parent(stmt, &parent) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < stmt->context->params->count; i++) {
        param = &stmt->param_info.params[i];
        param_mark = (sql_param_mark_t *)cm_galist_get(stmt->context->params, i);
        OG_RETURN_IFERR(ple_get_dynsql_using_expr(parent, param_mark->pnid, &using_expr));
        param->direction = (using_expr->dir == PLV_DIR_IN) ?
            OG_INPUT_PARAM :
            ((using_expr->dir == PLV_DIR_OUT) ? OG_OUTPUT_PARAM : OG_INOUT_PARAM);

        if (param->direction == OG_OUTPUT_PARAM || param->direction == OG_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
            param->out_value = NULL;
        }

        if (param->direction == OG_INPUT_PARAM || param->direction == OG_INOUT_PARAM) {
            OG_RETURN_IFERR(ple_get_using_expr_value(parent, using_expr, &src, PLE_CHECK_NONE));
            sql_keep_stack_variant(stmt, &src);
            var_copy(&src, &param->value);
        }
    }
    return OG_SUCCESS;
}

static status_t sql_decode_params_core(sql_stmt_t *stmt, variant_t *value, char *data, uint16 param_len)
{
    text_t num_text;
    switch (value->type) {
        case OG_TYPE_INTEGER:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int32));
            VALUE(int32, value) = *(int32 *)data;
            stmt->session->recv_pack->offset += sizeof(int32);
            break;

        case OG_TYPE_BIGINT:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(int64));
            VALUE(int64, value) = *(int64 *)data;
            stmt->session->recv_pack->offset += sizeof(int64);
            break;

        case OG_TYPE_REAL:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(double));
            VALUE(double, value) = *(double *)data;
            stmt->session->recv_pack->offset += sizeof(double);
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
            num_text.str = data + sizeof(uint32);
            num_text.len = *(uint32 *)data;
            stmt->param_info.param_strsize += num_text.len;
            OG_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));
            stmt->session->recv_pack->offset += param_len;
            break;
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            value->v_bin.is_hex_const = OG_FALSE;
            /* fall-through */
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32) + CM_ALIGN4(*(uint32 *)data));
            value->v_text.len = *(uint32 *)data;
            stmt->param_info.param_strsize += value->v_text.len;
            value->v_text.str = data + sizeof(uint32);
            if (g_instance->sql.enable_empty_string_null) {
                value->is_null = (value->v_text.len == 0);
            }
            stmt->session->recv_pack->offset += param_len;
            break;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(vm_cli_lob_t));
            VALUE(var_lob_t, value).type = OG_LOB_FROM_VMPOOL;
            cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, value).vm_lob), (vm_cli_lob_t *)data);
            VALUE(var_lob_t, value).vm_lob.type = OG_LOB_FROM_VMPOOL;

            OG_RETURN_IFERR(sql_check_vm_lob(stmt, &(VALUE(var_lob_t, value).vm_lob)));

            if (g_instance->sql.enable_empty_string_null) {
                value->is_null = (VALUE(var_lob_t, value).vm_lob.size == 0);
            }

            if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, value).vm_lob.size > 0) &&
                (stmt->lob_info.inuse_count > 0)) {
                stmt->lob_info.inuse_count--;
            }
            stmt->session->recv_pack->offset += sizeof(vm_cli_lob_t);
            break;

        case OG_TYPE_BOOLEAN:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(bool32));
            VALUE(bool32, value) = *(bool32 *)data;
            stmt->session->recv_pack->offset += sizeof(bool32);
            break;

        case OG_TYPE_INTERVAL_YM:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(interval_ym_t));
            VALUE(interval_ym_t, value) = *(interval_ym_t *)data;
            stmt->session->recv_pack->offset += sizeof(interval_ym_t);
            break;

        case OG_TYPE_INTERVAL_DS:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(interval_ds_t));
            VALUE(interval_ds_t, value) = *(interval_ds_t *)data;
            stmt->session->recv_pack->offset += sizeof(interval_ds_t);
            break;

        case OG_TYPE_UINT32:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
            VALUE(uint32, value) = *(uint32 *)data;
            stmt->session->recv_pack->offset += sizeof(uint32);
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(timestamp_tz_t));
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
            stmt->session->recv_pack->offset += sizeof(timestamp_tz_t);
            break;

        default:
            OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* params data to decode may from execute request package or varea which used to keep params for process fetch */
static status_t sql_decode_params(sql_stmt_t *stmt, char *param_buf, uint32 *actual_len)
{
    uint32 i;
    uint32 offset;
    uint32 count;
    uint32 single_param_offset;
    cs_param_head_t *head = NULL;
    char *data = NULL;
    sql_param_t *sql_param = NULL;
    variant_t *val = NULL;
    uint16 param_len = 0;

    stmt->param_info.outparam_cnt = 0;
    count = stmt->context->params->count;
    offset = sizeof(uint32);
    stmt->session->recv_pack->offset += sizeof(uint32);

    for (i = 0; i < count; i++) {
        single_param_offset = stmt->session->recv_pack->offset;
        head = (cs_param_head_t *)(param_buf + offset);
        CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, head->len);
        CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, CS_PARAM_HEAD_SIZE);
        stmt->session->recv_pack->offset += CS_PARAM_HEAD_SIZE;

        sql_param = &stmt->param_info.params[i];
        sql_param->direction = cs_get_param_direction(head->flag);
        if (sql_param->direction == OG_OUTPUT_PARAM || sql_param->direction == OG_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }

        val = &sql_param->value;
        val->is_null = cs_get_param_isnull(head->flag);
        val->type = (head->type == OG_TYPE_UNKNOWN) ? OG_TYPE_UNKNOWN : ((og_type_t)head->type + OG_TYPE_BASE);

        if (sql_param->direction == OG_OUTPUT_PARAM || val->is_null) {
            val->is_null = OG_TRUE;
            /* jump read offset to get next param value */
            offset += (uint32)head->len;
            continue;
        }

        data = (char *)head + CS_PARAM_HEAD_SIZE;
        param_len = head->len - CS_PARAM_HEAD_SIZE;

        OG_RETURN_IFERR(sql_decode_params_core(stmt, val, data, param_len));

        if (head->len != stmt->session->recv_pack->offset - single_param_offset) {
            OG_THROW_ERROR(ERR_INVALID_TCP_PACKET, "decode param", head->len,
                stmt->session->recv_pack->offset - single_param_offset);
            return OG_ERROR;
        }
        /* jump read offset to get next param value */
        offset += (uint32)head->len;
    }

    *actual_len = offset;
    return OG_SUCCESS;
}

static inline status_t sql_read_local_params(sql_stmt_t *stmt)
{
    uint32 offset;
    OG_RETSUC_IFTRUE(stmt->context->params == NULL);
    OG_RETSUC_IFTRUE(stmt->context->params->count == 0);

    void *input = NULL;
    switch (stmt->plsql_mode) {
        case PLSQL_NONE:
            break;
        case PLSQL_CURSOR:
            input = ((pl_executor_t *)stmt->pl_exec)->curr_input;
            OG_RETURN_IFERR(ple_keep_input(stmt, (pl_executor_t *)stmt->pl_exec, input,
                ((pl_executor_t *)stmt->pl_exec)->is_dyncur));

            return sql_read_kept_params(stmt);
        case PLSQL_DYNBLK:
            return sql_read_dynblk_params(stmt);
        default:
            // PLSQL_STATIC or PLSQL_DYNSQL mode no need to read params.
            return OG_SUCCESS;
    }
    /* check whether remain pack len if less than sizeof(uint32) */
    char *param_buffer = NULL;
    uint32 total_len;
    uint32 actual_len;
    status_t status;

    if (stmt->session->pipe != NULL) {
        CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, sizeof(uint32));
        param_buffer = CS_READ_ADDR(stmt->session->recv_pack);
    } else {
        param_buffer = stmt->param_info.param_buf + stmt->param_info.param_offset;
    }

    if (param_buffer == NULL) {
        return OG_SUCCESS;
    }

    offset = stmt->session->recv_pack->offset;

    total_len = *(uint32 *)param_buffer;
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, total_len);
    actual_len = 0;

    if (stmt->session->call_version >= CS_VERSION_7) {
        status = sql_decode_params_eff(stmt, param_buffer, &actual_len);
    } else {
        status = sql_decode_params(stmt, param_buffer, &actual_len);
    }

    if (status == OG_SUCCESS && total_len != actual_len) {
        OG_THROW_ERROR(ERR_INVALID_TCP_PACKET, "decode params", total_len, actual_len);
        status = OG_ERROR;
    }

    stmt->params_ready = (status == OG_SUCCESS);

    // record param offset before decode.
    stmt->param_info.param_offset = offset;

    return status;
}

status_t sql_read_params(sql_stmt_t *stmt)
{
    if (stmt->session->proto_type != PROTO_TYPE_CT) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_read_local_params(stmt));

    return OG_SUCCESS;
}

status_t sql_fill_null_params(sql_stmt_t *stmt)
{
    uint32 i;
    uint32 count;

    count = stmt->context->params->count;
    if (stmt->context->in_params != NULL) {
        count += stmt->context->in_params->count;
    }

    if (count == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_params_buf(stmt));

    for (i = 0; i < count; i++) {
        stmt->param_info.params[i].direction = OG_INPUT_PARAM;
        stmt->param_info.params[i].value.is_null = OG_TRUE;
        stmt->param_info.params[i].value.type = OG_TYPE_STRING;
    }

    return OG_SUCCESS;
}

status_t sql_keep_params(sql_stmt_t *stmt)
{
    uint32 types_cost;
    uint32 value_cost;
    char *param_buf = stmt->param_info.param_buf;
    char *param_types = stmt->param_info.param_types;

    OG_RETURN_IFERR(sql_keep_in_params(stmt));
    if (stmt->context->params->count == 0 || stmt->plsql_mode != PLSQL_NONE) {
        return OG_SUCCESS;
    }

    if (stmt->session->call_version >= CS_VERSION_7) {
        types_cost = CM_ALIGN4(stmt->context->params->count);
        OG_RETURN_IFERR(vmc_alloc(&stmt->vmc, types_cost, (void **)&stmt->param_info.param_types));
        MEMS_RETURN_IFERR(memcpy_sp(stmt->param_info.param_types, types_cost, param_types, types_cost));
    }

    value_cost = *(uint32 *)stmt->param_info.param_buf;
    OG_RETURN_IFERR(vmc_alloc(&stmt->vmc, value_cost, (void **)&stmt->param_info.param_buf));
    MEMS_RETURN_IFERR(memcpy_sp(stmt->param_info.param_buf, value_cost, param_buf, value_cost));

    return OG_SUCCESS;
}

/* decode params efficiently:
types | total_len flags param ... param | ... | total_len flags param ... param
*/
static status_t sql_decode_kept_params_eff(sql_stmt_t *stmt, char *param_buffer)
{
    uint32 i;
    uint32 offset;
    uint32 count;
    int8 *types = NULL;
    uint8 *flags = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *value = NULL;
    char *param_str_buffer = NULL;
    uint32 param_str_offset = 0;
    text_t num_text;

    stmt->param_info.outparam_cnt = 0;

    count = stmt->context->params->count;

    OG_RETURN_IFERR(sql_push(stmt, stmt->param_info.param_strsize, (void **)&param_str_buffer));

    // types
    types = (int8 *)stmt->param_info.param_types;

    // total_len
    offset = sizeof(uint32);

    // flags
    flags = (uint8 *)(param_buffer + offset);
    offset += CM_ALIGN4(count);

    // bound_value
    for (i = 0; i < count; i++) {
        data = (char *)(param_buffer + offset);

        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(flags[i]);
        if (param->direction == OG_OUTPUT_PARAM || param->direction == OG_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }

        value = &param->value;
        value->is_null = cs_get_param_isnull(flags[i]);
        value->type = (types[i] == OG_TYPE_UNKNOWN) ? OG_TYPE_UNKNOWN : ((og_type_t)types[i] + OG_TYPE_BASE);

        if (param->direction == OG_OUTPUT_PARAM || value->is_null) {
            value->is_null = OG_TRUE;
            continue;
        }

        switch (value->type) {
            case OG_TYPE_INTEGER:
                VALUE(int32, value) = *(int32 *)data;
                offset += sizeof(int32);
                break;

            case OG_TYPE_BIGINT:
            case OG_TYPE_DATE:
            case OG_TYPE_TIMESTAMP:
            case OG_TYPE_TIMESTAMP_TZ_FAKE:
            case OG_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, value) = *(int64 *)data;
                offset += sizeof(int64);
                break;

            case OG_TYPE_REAL:
                VALUE(double, value) = *(double *)data;
                offset += sizeof(double);
                break;

            case OG_TYPE_NUMBER:
            case OG_TYPE_DECIMAL:
            case OG_TYPE_NUMBER2:
                num_text.str = param_str_buffer + param_str_offset;
                num_text.len = *(uint32 *)data;
                param_str_offset += num_text.len;
                if (num_text.len != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(num_text.str, num_text.len, data + sizeof(uint32), num_text.len));
                }

                OG_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));

                offset += sizeof(uint32) + CM_ALIGN4(num_text.len);
                break;

            case OG_TYPE_CHAR:
            case OG_TYPE_VARCHAR:
            case OG_TYPE_STRING:
            case OG_TYPE_BINARY:
            case OG_TYPE_VARBINARY:
            case OG_TYPE_RAW:
                value->v_text.len = *(uint32 *)data;
                value->v_text.str = param_str_buffer + param_str_offset;
                param_str_offset += value->v_text.len;
                if (value->v_text.len != 0) {
                    MEMS_RETURN_IFERR(
                        memcpy_s(value->v_text.str, value->v_text.len, data + sizeof(uint32), value->v_text.len));
                }

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (value->v_text.len == 0);
                }

                offset += sizeof(uint32) + CM_ALIGN4(value->v_text.len);
                break;

            case OG_TYPE_CLOB:
            case OG_TYPE_BLOB:
            case OG_TYPE_IMAGE:
                VALUE(var_lob_t, value).type = OG_LOB_FROM_VMPOOL;
                cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, value).vm_lob), (vm_cli_lob_t *)data);
                VALUE(var_lob_t, value).vm_lob.type = OG_LOB_FROM_VMPOOL;

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (VALUE(var_lob_t, value).vm_lob.size == 0);
                }

                if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, value).vm_lob.size > 0) &&
                    (stmt->lob_info.inuse_count > 0)) {
                    stmt->lob_info.inuse_count--;
                }

                offset += sizeof(vm_cli_lob_t);
                break;

            case OG_TYPE_BOOLEAN:
                VALUE(bool32, value) = *(bool32 *)data;
                offset += sizeof(bool32);
                break;

            case OG_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, value) = *(interval_ym_t *)data;
                offset += sizeof(interval_ym_t);
                break;

            case OG_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, value) = *(interval_ds_t *)data;
                offset += sizeof(interval_ds_t);
                break;

            case OG_TYPE_UINT32:
                VALUE(uint32, value) = *(uint32 *)data;
                offset += sizeof(uint32);
                break;

            case OG_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
                offset += sizeof(timestamp_tz_t);
                break;

            default:
                OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
                return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

/* params data to decode may from execute request package or varea which used to keep params for process fetch */
static status_t sql_decode_kept_params(sql_stmt_t *stmt, char *param_buffer)
{
    uint32 i;
    uint32 offset;
    uint32 count;
    cs_param_head_t *head = NULL;
    char *data = NULL;
    sql_param_t *param = NULL;
    variant_t *value = NULL;
    char *param_str_buf = NULL;
    uint32 param_str_offset = 0;
    text_t num_text;

    stmt->param_info.outparam_cnt = 0;

    count = stmt->context->params->count;

    OG_RETURN_IFERR(sql_push(stmt, stmt->param_info.param_strsize, (void **)&param_str_buf));

    offset = sizeof(uint32);

    for (i = 0; i < count; i++) {
        head = (cs_param_head_t *)(param_buffer + offset);
        data = (char *)head + sizeof(cs_param_head_t);
        offset += (uint32)head->len;

        param = &stmt->param_info.params[i];
        param->direction = cs_get_param_direction(head->flag);
        if (param->direction == OG_OUTPUT_PARAM || param->direction == OG_INOUT_PARAM) {
            stmt->param_info.outparam_cnt++;
        }
        value = &param->value;
        value->is_null = cs_get_param_isnull(head->flag);
        value->type = (head->type == OG_TYPE_UNKNOWN) ? OG_TYPE_UNKNOWN : ((og_type_t)head->type + OG_TYPE_BASE);

        if (param->direction == OG_OUTPUT_PARAM || value->is_null) {
            value->is_null = OG_TRUE;
            continue;
        }

        switch (value->type) {
            case OG_TYPE_INTEGER:
                VALUE(int32, value) = *(int32 *)data;
                break;

            case OG_TYPE_BIGINT:
            case OG_TYPE_DATE:
            case OG_TYPE_TIMESTAMP:
            case OG_TYPE_TIMESTAMP_TZ_FAKE:
            case OG_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, value) = *(int64 *)data;
                break;

            case OG_TYPE_REAL:
                VALUE(double, value) = *(double *)data;
                break;

            case OG_TYPE_NUMBER:
            case OG_TYPE_DECIMAL:
            case OG_TYPE_NUMBER2:
                num_text.str = param_str_buf + param_str_offset;
                ;
                num_text.len = *(uint32 *)data;
                param_str_offset += num_text.len;
                if (num_text.len != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(num_text.str, num_text.len, data + sizeof(uint32), num_text.len));
                }

                OG_RETURN_IFERR(cm_text_to_dec(&num_text, &VALUE(dec8_t, value)));
                break;

            case OG_TYPE_CHAR:
            case OG_TYPE_VARCHAR:
            case OG_TYPE_STRING:
            case OG_TYPE_BINARY:
            case OG_TYPE_VARBINARY:
            case OG_TYPE_RAW:
                value->v_text.len = *(uint32 *)data;
                value->v_text.str = param_str_buf + param_str_offset;
                param_str_offset += value->v_text.len;
                if (value->v_text.len != 0) {
                    MEMS_RETURN_IFERR(
                        memcpy_s(value->v_text.str, value->v_text.len, data + sizeof(uint32), value->v_text.len));
                }

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (value->v_text.len == 0);
                }
                break;

            case OG_TYPE_CLOB:
            case OG_TYPE_BLOB:
            case OG_TYPE_IMAGE:
                VALUE(var_lob_t, value).type = OG_LOB_FROM_VMPOOL;
                cm_vmcli_lob2vm_lob(&(VALUE(var_lob_t, value).vm_lob), (vm_cli_lob_t *)data);
                VALUE(var_lob_t, value).vm_lob.type = OG_LOB_FROM_VMPOOL;

                if (g_instance->sql.enable_empty_string_null) {
                    value->is_null = (VALUE(var_lob_t, value).vm_lob.size == 0);
                }

                if (stmt->session->call_version < CS_VERSION_10 && (VALUE(var_lob_t, value).vm_lob.size > 0) &&
                    (stmt->lob_info.inuse_count > 0)) {
                    stmt->lob_info.inuse_count--;
                }
                break;

            case OG_TYPE_BOOLEAN:
                VALUE(bool32, value) = *(bool32 *)data;
                break;

            case OG_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, value) = *(interval_ym_t *)data;
                break;

            case OG_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, value) = *(interval_ds_t *)data;
                break;

            case OG_TYPE_UINT32:
                VALUE(uint32, value) = *(uint32 *)data;
                break;

            case OG_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)data;
                break;

            default:
                OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(value->type));
                return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_read_dynblk_params(sql_stmt_t *stmt)
{
    if (stmt->context->params->count == 0) {
        return OG_SUCCESS;
    }

    if (stmt->param_info.params == NULL) {
        OG_RETURN_IFERR(sql_alloc_params_buf(stmt));
    }

    return sql_decode_plsql_params(stmt);
}

status_t sql_read_kept_params(sql_stmt_t *stmt)
{
    if (stmt->is_explain) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_alloc_params_buf(stmt));
    OG_RETURN_IFERR(sql_read_kept_in_params(stmt));

    if (stmt->context->params->count == 0) {
        return OG_SUCCESS;
    }

    if (stmt->param_info.param_buf == NULL) {
        OG_THROW_ERROR(ERR_VALUE_ERROR, "param_buf can't be NULL");
        return OG_ERROR;
    }

    if (stmt->session->call_version >= CS_VERSION_7 || stmt->plsql_mode != PLSQL_NONE) {
        return sql_decode_kept_params_eff(stmt, stmt->param_info.param_buf);
    } else {
        return sql_decode_kept_params(stmt, stmt->param_info.param_buf);
    }
}

status_t sql_prepare_params(sql_stmt_t *stmt)
{
    uint32 params_cnt = stmt->context->params->count;

    if (params_cnt == 0) {
        stmt->param_info.param_types = NULL;
        stmt->param_info.param_buf = NULL;
    } else {
        if (stmt->session->call_version >= CS_VERSION_7) {
            OG_RETURN_IFERR(
                cs_get_data(stmt->session->recv_pack, params_cnt, (void **)&stmt->param_info.param_types));
        }
        stmt->param_info.param_buf = CS_READ_ADDR(stmt->session->recv_pack);
        stmt->param_info.param_offset = CS_PACKET_OFFSET(stmt->session->recv_pack);
    }

    if (stmt->plsql_mode == PLSQL_NONE) {
        OG_RETURN_IFERR(sql_alloc_params_buf(stmt));
    }
    return OG_SUCCESS;
}

/* Keep the results of first executable nodes into variant_area */
status_t sql_keep_first_exec_vars(sql_stmt_t *stmt)
{
    uint32 var_cnt = stmt->context->fexec_vars_cnt;
    if (var_cnt == 0) {
        return OG_SUCCESS;
    }

    uint32 types_cost;
    uint32 *typs_buf = NULL;
    char *vars_buf = NULL;
    uint32 i;
    row_assist_t row_ass;
    variant_t *fvar = NULL;

    OGSQL_SAVE_STACK(stmt);

    types_cost = var_cnt * sizeof(uint32);
    OG_RETURN_IFERR(sql_push(stmt, types_cost + SQL_MAX_FEXEC_VAR_BYTES, (void **)&typs_buf));
    vars_buf = ((char *)typs_buf) + types_cost;
    row_init(&row_ass, vars_buf, OG_MAX_ROW_SIZE, var_cnt);
    for (i = 0; i < var_cnt; i++) {
        fvar = &stmt->fexec_info.first_exec_vars[i];
        typs_buf[i] = (uint32)fvar->type;

        if (sql_set_row_value(stmt, &row_ass, fvar->type, fvar, i) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    }

    uint32 mem_size = types_cost + (uint32)row_ass.head->size;
    if (vmc_alloc(&stmt->vmc, mem_size, (void **)&stmt->fexec_info.first_exec_buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    errno_t ret = memcpy_sp(stmt->fexec_info.first_exec_buf, mem_size, (char *)typs_buf, mem_size);
    if (ret != EOK) {
        OGSQL_RESTORE_STACK(stmt);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }

    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}

/* Load the results of first executable nodes from variant_area at FETCH phase */
status_t sql_load_first_exec_vars(sql_stmt_t *stmt)
{
    if (stmt->fexec_info.first_exec_buf == NULL) {
        return OG_SUCCESS;
    }

    uint32 *typs_buf = NULL;
    char *vars_buf = NULL;
    uint32 var_count = stmt->context->fexec_vars_cnt;
    uint16 offsets[SQL_MAX_FEXEC_VARS] = { 0 };
    uint16 lens[SQL_MAX_FEXEC_VARS] = { 0 };
    variant_t *fvar = NULL;
    char *data = NULL;

    stmt->fexec_info.fexec_buff_offset = 0;

    OG_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, sizeof(variant_t) * var_count +
        stmt->context->fexec_vars_bytes,
        (void **)&stmt->fexec_info.first_exec_vars));

    typs_buf = (uint32 *)stmt->fexec_info.first_exec_buf;
    vars_buf = ((char *)typs_buf) + var_count * sizeof(uint32);
    cm_decode_row(vars_buf, offsets, lens, NULL);
    for (uint32 i = 0; i < var_count; i++) {
        fvar = &stmt->fexec_info.first_exec_vars[i];
        fvar->type = (og_type_t)typs_buf[i];
        if (fvar->type == OG_TYPE_LOGIC_TRUE) {
            fvar->is_null = OG_FALSE;
            continue;
        }
        if (lens[i] == OG_NULL_VALUE_LEN) {
            fvar->is_null = OG_TRUE;
            continue;
        }
        fvar->is_null = OG_FALSE;
        data = vars_buf + offsets[i];
        switch (fvar->type) {
            case OG_TYPE_BIGINT:
            case OG_TYPE_DATE:
            case OG_TYPE_TIMESTAMP:
            case OG_TYPE_TIMESTAMP_TZ_FAKE:
            case OG_TYPE_TIMESTAMP_LTZ:
                VALUE(int64, fvar) = *(int64 *)data;
                break;

            case OG_TYPE_TIMESTAMP_TZ:
                VALUE(timestamp_tz_t, fvar) = *(timestamp_tz_t *)data;
                break;

            case OG_TYPE_INTERVAL_DS:
                VALUE(interval_ds_t, fvar) = *(interval_ds_t *)data;
                break;

            case OG_TYPE_INTERVAL_YM:
                VALUE(interval_ym_t, fvar) = *(interval_ym_t *)data;
                break;
            case OG_TYPE_UINT32:
                VALUE(uint32, fvar) = *(uint32 *)data;
                break;

            case OG_TYPE_INTEGER:
                VALUE(int32, fvar) = *(int32 *)data;
                break;

            case OG_TYPE_BOOLEAN:
                VALUE(bool32, fvar) = *(bool32 *)data;
                break;

            case OG_TYPE_REAL:
                VALUE(double, fvar) = *(double *)data;
                break;

            case OG_TYPE_NUMBER:
            case OG_TYPE_DECIMAL:
                OG_RETURN_IFERR(cm_dec_4_to_8(&VALUE(dec8_t, fvar), (dec4_t *)data, lens[i]));
                break;
            case OG_TYPE_NUMBER2:
                OG_RETURN_IFERR(cm_dec_2_to_8(&VALUE(dec8_t, fvar), (const payload_t *)data, lens[i]));
                break;

            case OG_TYPE_CLOB:
            case OG_TYPE_BLOB:
            case OG_TYPE_IMAGE: {
                // decode from row_put_lob(size + type + lob_locator)
                uint32 lob_type = *(uint32 *)(data + sizeof(uint32));
                VALUE(var_lob_t, fvar).type = lob_type;
                if (lob_type == OG_LOB_FROM_KERNEL) {
                    VALUE(var_lob_t, fvar).knl_lob.bytes = (uint8 *)data;
                    VALUE(var_lob_t, fvar).knl_lob.size = KNL_LOB_LOCATOR_SIZE;
                } else if (lob_type == OG_LOB_FROM_VMPOOL) {
                    VALUE(var_lob_t, fvar).vm_lob = *(vm_lob_t *)data;
                } else {
                    OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do decode pl_inputs");
                }
                break;
            }

            default:
                // copy var-len datatype
                // if buff space is insufficient, then do not optimize
                if ((stmt->fexec_info.fexec_buff_offset + lens[i]) > stmt->context->fexec_vars_bytes) {
                    fvar->type = OG_TYPE_UNINITIALIZED;
                    break;
                }

                fvar->v_text.len = lens[i];
                fvar->v_text.str = (char *)stmt->fexec_info.first_exec_vars +
                    (stmt->context->fexec_vars_cnt * sizeof(variant_t)) + stmt->fexec_info.fexec_buff_offset;
                if (lens[i] != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(fvar->v_text.str, lens[i], data, lens[i]));
                }
                stmt->fexec_info.fexec_buff_offset += lens[i];
                break;
        }
    }

    return OG_SUCCESS;
}

static inline void sql_get_column_def_typmod(rs_column_t *rs_col, typmode_t *typmod)
{
    typmod->datatype = (uint16)(rs_col->datatype - OG_TYPE_BASE);
    typmod->precision = 0;
    typmod->scale = 0;

    switch (rs_col->datatype) {
        case OG_TYPE_UNKNOWN:
            typmod->datatype = (uint16)OG_TYPE_UNKNOWN;
            typmod->size = OG_MAX_COLUMN_SIZE;
            break;

        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
            typmod->size = sizeof(int32);
            break;
        case OG_TYPE_BIGINT:
            typmod->size = sizeof(int64);
            break;
        case OG_TYPE_REAL:
            typmod->size = sizeof(double);
            break;

        case OG_TYPE_DECIMAL:
            typmod->datatype = (uint16)(OG_TYPE_NUMBER - OG_TYPE_BASE);
            /* fall-through */
        case OG_TYPE_NUMBER:
            if (rs_col->precision == OG_UNSPECIFIED_NUM_PREC) {
                typmod->size = MAX_DEC_BYTE_SZ;
            } else {
                typmod->size = MAX_DEC_BYTE_BY_PREC(rs_col->precision);
            }
            typmod->precision = rs_col->precision;
            typmod->scale = rs_col->scale;
            break;
        case OG_TYPE_NUMBER2:
            if (rs_col->precision == OG_UNSPECIFIED_NUM_PREC) {
                typmod->size = MAX_DEC2_BYTE_SZ;
            } else {
                typmod->size = MAX_DEC2_BYTE_BY_PREC(rs_col->precision);
            }
            typmod->precision = rs_col->precision;
            typmod->scale = rs_col->scale;
            break;
        case OG_TYPE_DATE:
            typmod->size = sizeof(date_t);
            typmod->precision = rs_col->precision;
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            typmod->size = sizeof(timestamp_t);
            typmod->precision = rs_col->precision;
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            typmod->size = sizeof(timestamp_tz_t);
            typmod->precision = rs_col->precision;
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            typmod->size = (!OG_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) && rs_col->size == 0) ?
                OG_MAX_COLUMN_SIZE :
                MIN(rs_col->size, OG_MAX_EXEC_LOB_SIZE);
            break;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            typmod->size = g_instance->sql.sql_lob_locator_size;
            break;

        case OG_TYPE_INTERVAL_YM:
            typmod->size = sizeof(interval_ym_t);
            typmod->precision = rs_col->typmod.precision;
            typmod->scale = rs_col->typmod.scale;
            break;

        case OG_TYPE_INTERVAL_DS:
            typmod->size = sizeof(interval_ds_t);
            typmod->precision = rs_col->typmod.precision;
            typmod->scale = rs_col->typmod.scale;
            break;

        default:
            typmod->size = OG_MAX_COLUMN_SIZE;
            break;
    }
}

static void sql_set_column_attr(rs_column_t *rs_col, cs_column_def_t *col_def, typmode_t typmode)
{
    col_def->datatype = typmode.datatype;
    col_def->size = typmode.size;
    col_def->precision = typmode.precision;
    col_def->scale = typmode.scale;

    if (OG_BIT_TEST(rs_col->rs_flag, RS_NULLABLE)) {
        OG_COLUMN_SET_NULLABLE(col_def);
    }

    if (OG_BIT_TEST(rs_col->rs_flag, RS_IS_SERIAL)) {
        OG_COLUMN_SET_AUTO_INCREMENT(col_def);
    }

    if (OG_IS_CHAR_DATATYPE(rs_col->datatype) && rs_col->typmod.is_char) {
        OG_COLUMN_SET_CHARACTER(col_def);
    }
}

static status_t sql_prepare_and_send_stmt_expl(sql_stmt_t *stmt)
{
    cs_column_def_t *col_def = NULL;
    cs_packet_t *send_pack = stmt->session->send_pack;

    uint32 column_def_offset = 0;
    OG_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_column_def_t), &column_def_offset));
    col_def = (cs_column_def_t *)CS_RESERVE_ADDR(send_pack, column_def_offset);
    MEMS_RETURN_IFERR(memset_sp(col_def, sizeof(cs_column_def_t), 0, sizeof(cs_column_def_t)));

    col_def->size = OG_MAX_COLUMN_SIZE;
    col_def->datatype = OG_TYPE_STRING - OG_TYPE_BASE;
    col_def->name_len = strlen(EXPLAIN_HEAD);

    uint32 column_name_offset = 0;
    OG_RETURN_IFERR(cs_reserve_space(send_pack, col_def->name_len, &column_name_offset));
    char *name = (char *)CS_RESERVE_ADDR(send_pack, column_name_offset);
    uint32 align_len = CM_ALIGN4(col_def->name_len);
    MEMS_RETURN_IFERR(memcpy_sp(name, align_len, EXPLAIN_HEAD, col_def->name_len));
    if (col_def->name_len < align_len) {
        name[col_def->name_len] = '\0';
    }

    return OG_SUCCESS;
}

status_t sql_send_parsed_stmt_normal(sql_stmt_t *stmt, uint16 columnCount)
{
    rs_column_t *rs_col = NULL;
    sql_context_t *ogx = (sql_context_t *)stmt->context;
    cs_packet_t *send_pack = stmt->session->send_pack;
    cs_column_def_t *col_def = NULL;
    typmode_t typmode;
    uint32 column_def_offset;
    uint32 column_name_offset;

    if (columnCount == 0) {
        return OG_SUCCESS;
    }

    // check whether project column count is valid for client
    if (columnCount >= OG_SPRS_COLUMNS && stmt->session->call_version <= CS_VERSION_3) {
        OG_THROW_ERROR(ERR_MAX_COLUMN_SIZE, OG_SPRS_COLUMNS - 1);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < ogx->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(ogx->rs_columns, i);

        OG_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_column_def_t), &column_def_offset));
        col_def = (cs_column_def_t *)CS_RESERVE_ADDR(send_pack, column_def_offset);
        MEMS_RETURN_IFERR(memset_sp(col_def, sizeof(cs_column_def_t), 0, sizeof(cs_column_def_t)));

        if ((rs_col->type == RS_COL_COLUMN && rs_col->v_col.is_array == OG_TRUE &&
            rs_col->v_col.ss_start <= rs_col->v_col.ss_end) ||
            (rs_col->type == RS_COL_CALC && rs_col->expr->root->typmod.is_array == OG_TRUE)) {
            if (stmt->session->call_version >= CS_VERSION_10) {
                OG_COLUMN_SET_ARRAY(col_def);
            } else {
                OG_THROW_ERROR(ERR_ARRAY_NOT_SUPPORT);
                return OG_ERROR;
            }
        }

        if (stmt->session->call_version >= CS_VERSION_24 && rs_col->v_col.is_jsonb) {
            OG_COLUMN_SET_JSONB(col_def);
        }

        col_def->name_len = rs_col->name.len;
        if (col_def->name_len > 0) {
            OG_RETURN_IFERR(cs_reserve_space(send_pack, col_def->name_len, &column_name_offset));

            /* after "cs_reserve_space" column_def should be refresh by "CS_RESERVE_ADDR" */
            col_def = (cs_column_def_t *)CS_RESERVE_ADDR(send_pack, column_def_offset);
            char *name = CS_RESERVE_ADDR(send_pack, column_name_offset);
            uint32 align_len = CM_ALIGN4(col_def->name_len);
            MEMS_RETURN_IFERR(memcpy_sp(name, align_len, rs_col->name.str, rs_col->name.len));
            if (col_def->name_len < align_len) {
                name[col_def->name_len] = '\0';
            }
        }

        sql_get_column_def_typmod(rs_col, &typmode);
        sql_set_column_attr(rs_col, col_def, typmode);
    }

    return OG_SUCCESS;
}

static status_t sql_send_parsed_stmt_pl(sql_stmt_t *stmt)
{
    cs_packet_t *send_pack = stmt->session->send_pack;
    function_t *func = NULL;
    plv_decl_t *decl = NULL;
    plv_direction_t plv_dir;
    cs_outparam_def_t *outparams = NULL;
    uint32 outparams_offset;
    uint32 i;
    uint32 outparam_id = 0;
    status_t status = OG_SUCCESS;

    if (!sql_send_get_node_function(stmt, &func)) {
        return cs_put_int32(send_pack, 0);
    }

    do {
        status = cs_put_int32(send_pack, func->desc.outparam_count);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);
        if (func->desc.outparam_count == 0) {
            break;
        }

        // check whether project column count is valid for client
        if (func->desc.outparam_count >= OG_SPRS_COLUMNS && stmt->session->call_version <= CS_VERSION_3) {
            OG_THROW_ERROR(ERR_MAX_COLUMN_SIZE, OG_SPRS_COLUMNS - 1);
            return OG_ERROR;
        }

        status = cs_reserve_space(send_pack, sizeof(cs_outparam_def_t) * func->desc.outparam_count, &outparams_offset);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);
        outparams = (cs_outparam_def_t *)CS_RESERVE_ADDR(send_pack, outparams_offset);

        for (i = 0; i < func->desc.params->count; i++) {
            decl = (plv_decl_t *)cm_galist_get(func->desc.params, i);
            plv_dir = decl->drct;
            if (plv_dir == PLV_DIR_OUT || plv_dir == PLV_DIR_INOUT) {
                OG_RETURN_IFERR(cm_text2str(&decl->name, outparams[outparam_id].name, OG_NAME_BUFFER_SIZE));
                outparams[outparam_id].size = (decl->type == PLV_CUR) ? (uint16)0 : decl->variant.type.size;
                outparams[outparam_id].direction = (uint8)plv_dir;
                if (decl->type == PLV_CUR) {
                    outparams[outparam_id].datatype = (uint8)(OG_TYPE_CURSOR - OG_TYPE_BASE);
                } else if (decl->variant.type.datatype == OG_TYPE_DECIMAL) {
                    outparams[outparam_id].datatype = (uint8)(OG_TYPE_NUMBER - OG_TYPE_BASE);
                } else {
                    outparams[outparam_id].datatype = (uint8)(decl->variant.type.datatype - OG_TYPE_BASE);
                }
                outparam_id++;
            }
        }
    } while (0);

    return status;
}

static uint16 sql_get_ack_column_count(sql_stmt_t *stmt)
{
    if (stmt->is_explain) {
        return 1;
    }
    sql_context_t *ctx = (sql_context_t *)stmt->context;
    return (ctx->rs_columns == NULL) ? 0 : ctx->rs_columns->count;
}

static status_t sql_send_param_info_impl(sql_stmt_t *stmt, galist_t *params_list)
{
    sql_param_mark_t *param_mark = NULL;
    uint32 params_offset;
    uint32 param_name_offset;
    uint32 param_count;
    cs_packet_t *send_pack = stmt->session->send_pack;
    char *sql_text = NULL;
    uint32 sql_len;

    if (stmt->pl_context != NULL) {
        pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
        sql_text = entity->anonymous->desc.sql.str;
        sql_len = entity->anonymous->desc.sql_len;
    } else {
        sql_text = stmt->context->ctrl.text_addr;
        sql_len = stmt->context->ctrl.text_size;
    }

    param_count = params_list->count;

    // new communication protocol for support cursor sharing
    for (uint32 i = 0; i < param_count; i++) {
        OG_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_param_def_new_t), &params_offset));
        cs_param_def_new_t *param_new = (cs_param_def_new_t *)CS_RESERVE_ADDR(send_pack, params_offset);
        MEMS_RETURN_IFERR(memset_sp(param_new, sizeof(cs_param_def_new_t), 0, sizeof(cs_param_def_new_t)));
        param_mark = (sql_param_mark_t *)cm_galist_get(params_list, i);
        param_new->len = param_mark->len;
        if (param_mark->len > 0) {
            OG_RETURN_IFERR(cs_reserve_space(send_pack, param_mark->len, &param_name_offset));
            char *name = CS_RESERVE_ADDR(send_pack, param_name_offset);
            uint32 align_len = CM_ALIGN4(param_mark->len);
            if (param_mark->offset >= sql_len || param_mark->offset + param_mark->len > sql_len) {
                OG_THROW_ERROR(ERR_CURSOR_SHARING, "params offset or params len is large than sql len.");
                return OG_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_sp(name, align_len, sql_text + param_mark->offset - stmt->text_shift,
                param_mark->len));
            if (param_mark->len < align_len) {
                name[param_mark->len] = '\0';
            }
        }
    }
    return OG_SUCCESS;
}

static status_t sql_send_params_info(sql_stmt_t *stmt, cs_prepare_ack_t *prepare_ack)
{
    galist_t *params_list = NULL;
    sql_context_t *ogx = (sql_context_t *)stmt->context;

    prepare_ack->param_count = (ogx->params == NULL) ? 0 : ogx->params->count;
    if (prepare_ack->param_count > 0) {
        params_list = ogx->params;
        OG_RETURN_IFERR(sql_send_param_info_impl(stmt, params_list));
    }
    return OG_SUCCESS;
}

status_t sql_send_parsed_stmt(sql_stmt_t *stmt)
{
    uint32 ack_offset;
    cs_prepare_ack_t *prepare_ack = NULL;
    cs_packet_t *send_pack = stmt->session->send_pack;

    OG_BIT_RESET(send_pack->head->flags, CS_FLAG_WITH_TS);
    OG_RETURN_IFERR(cs_reserve_space(send_pack, sizeof(cs_prepare_ack_t), &ack_offset));

    prepare_ack = (cs_prepare_ack_t *)CS_RESERVE_ADDR(send_pack, ack_offset);
    prepare_ack->stmt_id = stmt->id;
    if (stmt->context == NULL) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    prepare_ack->stmt_type = ACK_STMT_TYPE(stmt->lang_type, stmt->context->type);
    prepare_ack->column_count = sql_get_ack_column_count(stmt);

    // Do not optimize the temporary variables column_count,
    // because the message expansion may cause the ack address to change,
    // and the ack address cannot be used later
    uint16 column_count = prepare_ack->column_count;
    OG_RETURN_IFERR(sql_send_params_info(stmt, prepare_ack));

    if (stmt->is_explain) {
        OG_RETURN_IFERR(sql_prepare_and_send_stmt_expl(stmt));
    } else {
        OG_RETURN_IFERR(sql_send_parsed_stmt_normal(stmt, column_count));
    }

    if (stmt->lang_type == LANG_PL) {
        OG_RETURN_IFERR(sql_send_parsed_stmt_pl(stmt));
    }

    return OG_SUCCESS;
}

status_t sql_send_exec_begin(sql_stmt_t *stmt)
{
    sql_select_t *select_ctx = NULL;
    rs_column_t *rs_col = NULL;
    typmode_t type_mode;
    uint32 i;
    cs_execute_ack_t *exec_ack = NULL;
    uint32 pending_col_defs_offset;

    if (stmt->session->agent->recv_pack.head->cmd == CS_CMD_EXE_MULTI_SQL) {
        return OG_SUCCESS;
    }

    if (CS_XACT_WITH_TS(stmt->session->recv_pack->head->flags)) {
        stmt->session->send_pack->head->flags |= CS_FLAG_WITH_TS;
        stmt->gts_offset = stmt->session->send_pack->head->size;
        OG_RETURN_IFERR(cs_put_scn(stmt->session->send_pack, &stmt->gts_scn));
    }

    OG_RETURN_IFERR(cs_reserve_space(stmt->session->send_pack, sizeof(cs_execute_ack_t), &stmt->exec_ack_offset));
    exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);
    MEMS_RETURN_IFERR(memset_s(exec_ack, sizeof(cs_execute_ack_t), 0, sizeof(cs_execute_ack_t)));

    if (!stmt->is_explain && stmt->context != NULL && stmt->context->type == OGSQL_TYPE_SELECT) {
        select_ctx = (sql_select_t *)stmt->context->entry;
        if (select_ctx->pending_col_count > 0) {
            exec_ack->pending_col_count = select_ctx->rs_columns->count;
            OG_RETURN_IFERR(cs_reserve_space(stmt->session->send_pack,
                select_ctx->rs_columns->count * sizeof(cs_final_column_def_t), &pending_col_defs_offset));
            /* after "cs_reserve_space" exec_ack should be refresh by "CS_RESERVE_ADDR" */
            exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);
            *((cs_final_column_def_t **)&exec_ack->pending_col_defs) =
                (cs_final_column_def_t *)CS_RESERVE_ADDR(stmt->session->send_pack, pending_col_defs_offset);
            for (i = 0; i < select_ctx->rs_columns->count; i++) {
                rs_col = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
                sql_get_column_def_typmod(rs_col, &type_mode);
                exec_ack->pending_col_defs[i].col_id = i;
                exec_ack->pending_col_defs[i].datatype = type_mode.datatype;
                exec_ack->pending_col_defs[i].size = type_mode.size;
                exec_ack->pending_col_defs[i].precision = type_mode.precision;
                exec_ack->pending_col_defs[i].scale = type_mode.scale;
            }
        }
    }

    return OG_SUCCESS;
}

void sql_send_exec_end(sql_stmt_t *stmt)
{
    if (stmt->session->agent->recv_pack.head->cmd == CS_CMD_EXE_MULTI_SQL) {
        return;
    }

    uint32 i;
    og_type_t type;
    sql_select_t *select_ctx = NULL;
    rs_column_t *rs_col = NULL;
    cs_execute_ack_t *execute_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack,
        stmt->exec_ack_offset);

    execute_ack->batch_count = 1;
    execute_ack->total_rows = stmt->total_rows;
    execute_ack->batch_rows = stmt->batch_rows;
    execute_ack->rows_more = !stmt->eof;
    execute_ack->xact_status = knl_xact_status(&stmt->session->knl_session);
    execute_ack->batch_errs = stmt->actual_batch_errs;

    if (execute_ack->pending_col_count > 0 && !stmt->mark_pending_done) {
        select_ctx = (sql_select_t *)stmt->context->entry;
        for (i = 0; i < execute_ack->pending_col_count; i++) {
            if (execute_ack->pending_col_defs[i].datatype != (uint16)OG_TYPE_UNKNOWN) {
                continue;
            }
            rs_col = (rs_column_t *)cm_galist_get(select_ctx->rs_columns, i);
            type = OG_TYPE_UNKNOWN;
            if (rs_col->type == RS_COL_CALC && rs_col->expr->root->type == EXPR_NODE_PARAM) {
                (void)sql_get_expr_datatype(stmt, rs_col->expr, &type);
            }
            execute_ack->pending_col_defs[i].datatype =
                (type == OG_TYPE_UNKNOWN) ? (uint16)(OG_TYPE_VARCHAR - OG_TYPE_BASE) : (uint16)(type - OG_TYPE_BASE);
        }
    }
}

status_t sql_send_import_rows(sql_stmt_t *stmt)
{
    OG_RETURN_IFERR(sql_send_exec_begin(stmt));
    sql_send_exec_end(stmt);
    stmt->session->send_pack->head->flags |= OG_FLAG_CREATE_TABLE_AS;
    return OG_SUCCESS;
}
status_t sql_send_fetch_begin(sql_stmt_t *stmt)
{
    return cs_reserve_space(stmt->session->send_pack, sizeof(cs_fetch_ack_t), &stmt->fetch_ack_offset);
}

void sql_send_fetch_end(sql_stmt_t *stmt)
{
    cs_fetch_ack_t *fetch_ack = (cs_fetch_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->fetch_ack_offset);
    fetch_ack->total_rows = stmt->total_rows;
    fetch_ack->batch_rows = stmt->batch_rows;
    fetch_ack->rows_more = !stmt->eof;
}

bool32 sql_send_check_is_full(sql_stmt_t *stmt)
{
    cs_packet_t *send_pack = stmt->session->send_pack;

    if (stmt->return_generated_key &&
        (stmt->context->type == OGSQL_TYPE_INSERT || stmt->context->type == OGSQL_TYPE_MERGE)) {
        // when JDBC wants Server to return auto_increment keys (insert SQL),
        // should not judge prefetch rows count and remove OG_MAX_ROW_SIZE limit
        return (send_pack->head->size + OG_GENERATED_KEY_ROW_SIZE > send_pack->buf_size);
    } else {
        if ((stmt->batch_rows + 1 >= stmt->prefetch_rows) ||
            (CM_REALLOC_SEND_PACK_SIZE(send_pack, OG_MAX_ROW_SIZE) > send_pack->max_buf_size)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

status_t sql_send_serveroutput(sql_stmt_t *stmt, text_t *output)
{
    return OG_SUCCESS;
}

status_t sql_send_return_result(sql_stmt_t *stmt, uint32 stmt_id)
{
    return OG_SUCCESS;
}

status_t sql_send_nls_feedback(sql_stmt_t *stmt, nlsparam_id_t id, text_t *value)
{
    cs_packet_t *send_pack;

    send_pack = stmt->session->send_pack;
    send_pack->head->flags = CS_FLAG_FEEDBACK;
    // put the feedback type
    OG_RETURN_IFERR(cs_put_int32(send_pack, FB_ALTSESSION_SET_NLS));
    // put the feedback data
    OG_RETURN_IFERR(cs_put_int32(send_pack, id));
    OG_RETURN_IFERR(cs_put_text(send_pack, value));

    return OG_SUCCESS;
}

status_t sql_send_session_tz_feedback(sql_stmt_t *stmt, timezone_info_t client_timezone)
{
    cs_packet_t *send_pack;

    send_pack = stmt->session->send_pack;
    send_pack->head->flags = CS_FLAG_FEEDBACK;
    // put the feedback type
    OG_RETURN_IFERR(cs_put_int32(send_pack, FB_ALTSESSION_SET_SESSIONTZ));
    // put the feedback data
    OG_RETURN_IFERR(cs_put_int32(send_pack, client_timezone));

    return OG_SUCCESS;
}

static status_t sql_send_outparams_core(sql_stmt_t *stmt, variant_t *value)
{
    switch (value->type) {
        case OG_TYPE_UINT32:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_uint32(stmt, VALUE(uint32, value)));
            break;
        case OG_TYPE_INTEGER:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_int32(stmt, VALUE(int32, value)));
            break;

        case OG_TYPE_BIGINT:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_int64(stmt, VALUE(int64, value)));
            break;

        case OG_TYPE_REAL:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_real(stmt, VALUE(double, value)));
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_decimal(stmt, VALUE_PTR(dec8_t, value)));
            break;
        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_decimal2(stmt, VALUE_PTR(dec8_t, value)));
            break;
        case OG_TYPE_DATE:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_date(stmt, VALUE(date_t, value)));
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_ts(stmt, VALUE(date_t, value)));
            break;

        case OG_TYPE_TIMESTAMP_LTZ:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_tsltz(stmt, VALUE(timestamp_ltz_t, value)));
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_tstz(stmt, VALUE_PTR(timestamp_tz_t, value)));
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_text(stmt, VALUE_PTR(text_t, value)));
            break;

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_bin(stmt, VALUE_PTR(binary_t, value)));
            break;

        case OG_TYPE_BOOLEAN:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_bool(stmt, VALUE(bool32, value)));
            break;

        case OG_TYPE_INTERVAL_YM:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_ymitvl(stmt, VALUE(interval_ym_t, value)));
            break;

        case OG_TYPE_INTERVAL_DS:
            OG_RETURN_IFERR(my_sender(stmt)->send_column_dsitvl(stmt, VALUE(interval_ds_t, value)));
            break;

        default:
            OG_THROW_ERROR(ERR_VALUE_ERROR, "unsupport datatype");
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_send_outparams(sql_stmt_t *stmt)
{
    variant_t *value = NULL;
    uint32 i;
    sql_stmt_t *sub_stmt = NULL;
    cs_execute_ack_t *execute_ack = NULL;
    bool32 is_full = OG_FALSE;
    if (stmt->session->pipe == NULL) {
        if (stmt->param_info.outparam_cnt > 0) {
            OG_THROW_ERROR(ERR_JOB_UNSUPPORT, "out parameter");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(my_sender(stmt)->send_exec_begin(stmt));

    /* "my_sender(stmt)->send_exec_begin"-->exec_ack may from SQL_PUSH */
    execute_ack =
        (stmt->exec_ack != NULL ? stmt->exec_ack :
                                  (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset));

    execute_ack->batch_count = 1;
    execute_ack->batch_rows = 0;
    execute_ack->total_rows = 0;
    execute_ack->rows_more = 0;
    execute_ack->pending_col_count = 0;
    execute_ack->xact_status = knl_xact_status(&stmt->session->knl_session);
    execute_ack->batch_errs = 0;

    if (stmt->param_info.outparam_cnt == 0) {
        return OG_SUCCESS;
    }

    stmt->session->send_pack->head->flags |= CS_FLAG_PL_OUPUT_PARAM;
    OG_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, stmt->param_info.outparam_cnt));

    for (i = 0; i < stmt->context->params->count; i++) { // equals to pl_context->arg_count
        if (stmt->param_info.params[i].direction == PLV_DIR_IN) {
            continue;
        }

        value = stmt->param_info.params[i].out_value;

        if (value == NULL) {
            continue;
        }

        if (value->is_null) {
            (void)my_sender(stmt)->send_column_null(stmt, value->type);
            continue;
        }

        if (value->type == OG_TYPE_CURSOR) {
            cursor_t cursor;
            sub_stmt = ple_ref_cursor_get(stmt, (pl_cursor_slot_t *)value->v_cursor.ref_cursor);
            if (sub_stmt == NULL) {
                OG_THROW_ERROR(ERR_INVALID_CURSOR);
                return OG_ERROR;
            }
            cursor.stmt_id = sub_stmt->id;
            // open cursor has exec sql,fetch mode must be 2
            cursor.fetch_mode = 2;
            OG_RETURN_IFERR(my_sender(stmt)->send_column_cursor(stmt, &cursor));
            continue;
        }

        OG_RETURN_IFERR(sql_send_outparams_core(stmt, value));
    }

    return my_sender(stmt)->send_row_end(stmt, &is_full);
}

status_t sql_send_row_entire(sql_stmt_t *stmt, char *row, bool32 *is_full)
{
    char *buf = NULL;
    uint32 buf_offset;
    cs_packet_t *send_pack = stmt->session->send_pack;

    OG_RETURN_IFERR(cs_reserve_space(send_pack, ROW_SIZE(row), &buf_offset));
    buf = CS_RESERVE_ADDR(send_pack, buf_offset);
    if (0 != ROW_SIZE(row)) {
        MEMS_RETURN_IFERR(memcpy_s(buf, ROW_SIZE(row), row, ROW_SIZE(row)));
    }
    *is_full = sql_send_check_is_full(stmt);

    return OG_SUCCESS;
}

// generate result set for client
void sql_init_sender(session_t *session)
{
    cs_init_set(session->send_pack, CS_LOCAL_VERSION);
}

void sql_init_sender_row(sql_stmt_t *stmt, char *buf, uint32 size, uint32 column_count)
{
    row_init(&stmt->ra, buf, size, column_count);
}

static void sql_get_error(int32 *code, const char **message, source_location_t *loc)
{
    cm_get_error(code, message, loc);
    if (SECUREC_UNLIKELY(*code == 0)) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "has error info at %s:%u", g_tls_error.err_file, g_tls_error.err_line);
        cm_get_error(code, message, loc);
    }
}

status_t sql_send_result_error(session_t *session)
{
    int32 code;
    const char *message = NULL;
    cs_packet_t *pack = NULL;
    source_location_t location;
    sql_stmt_t *stmt = NULL;

    CM_POINTER(session);
    pack = &session->agent->send_pack;
    cs_init_set(pack, session->call_version);
    pack->head->cmd = session->agent->recv_pack.head->cmd;
    pack->head->result = (uint8)OG_ERROR;
    pack->head->flags = 0;
    pack->head->serial_number = session->agent->recv_pack.head->serial_number;
    sql_get_error(&code, &message, &location);

    if (code == 0) {
        CM_ASSERT(0);
        OG_LOG_RUN_ERR("error returned without throwing error msg");
    }

    if (code == ERR_PL_EXEC) {
        location.line = 0;
        location.column = 0;
    }

    OG_RETURN_IFERR(cs_put_int32(pack, (uint32)code));
    OG_RETURN_IFERR(cs_put_int16(pack, location.line));
    OG_RETURN_IFERR(cs_put_int16(pack, location.column));
    OG_RETURN_IFERR(cs_put_err_msg(pack, session->call_version, message));

    // Beside error info, some st_cs_execute_ack may be useful and should
    // be send to client.
    stmt = session->current_stmt;
    if (stmt != NULL) {
        OG_RETURN_IFERR(cs_put_int32(pack, stmt->total_rows));
        OG_RETURN_IFERR(cs_put_int32(pack, stmt->batch_rows));
    }

    return cs_write(session->pipe, pack);
}

status_t sql_send_result_success(session_t *session)
{
    cs_packet_t *pack = NULL;
    CM_POINTER(session);
    pack = &session->agent->send_pack;
    pack->head->cmd = session->agent->recv_pack.head->cmd;
    pack->head->result = (uint8)OG_SUCCESS;
    pack->head->serial_number = session->agent->recv_pack.head->serial_number;
    return cs_write(session->pipe, pack);
}

status_t sql_send_row_begin(sql_stmt_t *stmt, uint32 column_count)
{
    char *buf = NULL;

    CM_CHECK_SEND_PACK_FREE(stmt->session->send_pack, OG_MAX_ROW_SIZE);
    buf = CS_WRITE_ADDR(stmt->session->send_pack);
    row_init(&stmt->ra, buf, OG_MAX_ROW_SIZE, column_count);

    return OG_SUCCESS;
}

status_t sql_send_row_end(sql_stmt_t *stmt, bool32 *is_full)
{
    cs_packet_t *send_pack = stmt->session->send_pack;
    OG_RETURN_IFERR(cs_reserve_space(send_pack, stmt->ra.head->size, NULL));
    *is_full = sql_send_check_is_full(stmt);
    stmt->session->stat.fetched_rows++;
    return OG_SUCCESS;
}

status_t sql_send_column_null(sql_stmt_t *stmt, uint32 type)
{
    return row_put_null(&stmt->ra);
}

status_t sql_send_column_uint32(sql_stmt_t *stmt, uint32 val)
{
    return row_put_uint32(&stmt->ra, val);
}

status_t sql_send_column_int32(sql_stmt_t *stmt, int32 val)
{
    return row_put_int32(&stmt->ra, val);
}

status_t sql_send_column_int64(sql_stmt_t *stmt, int64 val)
{
    return row_put_int64(&stmt->ra, val);
}

status_t sql_send_column_real(sql_stmt_t *stmt, double val)
{
    return row_put_real(&stmt->ra, val);
}

status_t sql_send_column_date(sql_stmt_t *stmt, date_t val)
{
    return row_put_date(&stmt->ra, val);
}

status_t sql_send_column_ts(sql_stmt_t *stmt, date_t val)
{
    return row_put_date(&stmt->ra, val);
}

status_t sql_send_column_tstz(sql_stmt_t *stmt, timestamp_tz_t *val)
{
    return row_put_timestamp_tz(&stmt->ra, val);
}

status_t sql_send_column_tsltz(sql_stmt_t *stmt, timestamp_ltz_t val)
{
    /* send as timestamp */
    return sql_send_column_ts(stmt, val);
}

static status_t sql_convert_normal_lob(sql_stmt_t *stmt, var_lob_t *lob)
{
    vm_lob_t vlob;
    uint32 remain_size;
    uint32 copy_size;
    uint32 write_size = 0;
    errno_t errcode;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);
    vm_page_t *page = NULL;
    cm_reset_vm_lob(&vlob);

    do {
        OG_RETURN_IFERR(sql_extend_lob_vmem(stmt, vm_list, &vlob));
        OG_RETURN_IFERR(vm_open(stmt->session, stmt->mtrl.pool, vm_list->last, &page));

        copy_size = OG_VMEM_PAGE_SIZE;
        remain_size = lob->normal_lob.value.len - write_size;
        if (copy_size > remain_size) {
            copy_size = remain_size;
        }
        if (copy_size != 0) {
            errcode = memcpy_s((char *)page->data, copy_size, lob->normal_lob.value.str + write_size, copy_size);
            if (errcode != EOK) {
                vm_close(stmt->session, stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
                OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return OG_ERROR;
            }
        }
        write_size += copy_size;
        vm_close(stmt->session, stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
    } while (write_size < lob->normal_lob.value.len);

    vlob.size = lob->normal_lob.value.len;

    lob->type = OG_LOB_FROM_VMPOOL;
    lob->vm_lob = vlob;
    if (stmt->session->call_version < CS_VERSION_10) {
        stmt->lob_info.inuse_count++;
    }

    return OG_SUCCESS;
}


static status_t sql_convert_inline_lob(sql_stmt_t *stmt, var_lob_t *v_lob)
{
    uint32 remain_size;
    uint32 copy_size;
    uint32 write_size = 0;
    vm_lob_t vlob;
    char *lob_data = NULL;
    uint32 lob_size;
    vm_page_t *page = NULL;
    errno_t errcode;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    cm_reset_vm_lob(&vlob);

    lob_data = knl_inline_lob_data(v_lob->knl_lob.bytes);
    lob_size = knl_lob_size(v_lob->knl_lob.bytes);

    do {
        OG_RETURN_IFERR(sql_extend_lob_vmem(stmt, vm_list, &vlob));
        OG_RETURN_IFERR(vm_open(stmt->session, stmt->mtrl.pool, vm_list->last, &page));

        copy_size = OG_VMEM_PAGE_SIZE;
        remain_size = lob_size - write_size;
        if (copy_size > remain_size) {
            copy_size = remain_size;
        }
        if (copy_size != 0) {
            errcode = memcpy_s((char *)page->data, copy_size, lob_data + write_size, copy_size);
            if (errcode != EOK) {
                vm_close(stmt->session, stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
                OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return OG_ERROR;
            }
        }
        write_size += copy_size;
        vm_close(stmt->session, stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
    } while (write_size < lob_size);

    vlob.size = lob_size;

    v_lob->type = OG_LOB_FROM_VMPOOL;
    v_lob->vm_lob = vlob;
    if (stmt->session->call_version < CS_VERSION_10) {
        stmt->lob_info.inuse_count++;
    }
    return OG_SUCCESS;
}

// when project lob column, value must convert to knl_lob or vm_lob !!!
status_t sql_row_put_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *v_lob)
{
    if (!OG_IS_VALID_LOB_TYPE(v_lob->type)) {
        OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do put row");
        return OG_ERROR;
    }

    // convert nomal_lob to vm_lob
    if (v_lob->type == OG_LOB_FROM_NORMAL) {
        OG_RETURN_IFERR(sql_convert_normal_lob(stmt, v_lob));
    } else if (v_lob->type == OG_LOB_FROM_KERNEL) {
        // is inline v_lob
        bool32 is_inline = knl_lob_is_inline(v_lob->knl_lob.bytes);
        if (is_inline) {
            if (stmt->session->call_version <= CS_VERSION_2) {
                OG_RETURN_IFERR(sql_convert_inline_lob(stmt, v_lob));
            } else {
                return row_put_lob(ra, v_lob->knl_lob.size, v_lob);
            }
        }
    } else {
        if (stmt->session->call_version < CS_VERSION_10) {
            stmt->lob_info.inuse_count++;
        }
    }

    return row_put_lob(ra, g_instance->sql.sql_lob_locator_size, v_lob);
}

static status_t sql_copy_array_to_vm(sql_stmt_t *stmt, vm_lob_t *vlob, bool32 copy_element, char *buf, uint32 size,
    uint32 offset_delta)
{
    elem_dir_t *plv_dir = NULL;
    vm_page_t *page = NULL;
    char *addr = buf;
    uint32 read_size = size;
    uint32 copy_size;
    errno_t err;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    while (read_size > 0) {
        if (sql_extend_lob_vmem(stmt, vm_list, vlob) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (vm_open(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, &page) != OG_SUCCESS) {
            return OG_ERROR;
        }

        copy_size = MIN(read_size, OG_VMEM_PAGE_SIZE);
        err = memcpy_s(page->data, OG_VMEM_PAGE_SIZE, addr, copy_size);
        if (err != EOK) {
            vm_close(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        /* update offset */
        if (copy_element) {
            if (read_size == size) {
                array_head_t *head = (array_head_t *)(page->data);
                head->size += offset_delta;
                head->offset = (OG_VMEM_PAGE_SIZE * (size / OG_VMEM_PAGE_SIZE + 1));
                plv_dir = (elem_dir_t *)(head + 1);
            } else {
                plv_dir = (elem_dir_t *)page->data;
            }
            while ((char *)plv_dir < page->data + copy_size) {
                if (plv_dir->offset != ELEMENT_NULL_OFFSET) {
                    plv_dir->offset += offset_delta;
                }
                plv_dir++;
            }
        }

        vm_close(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
        addr += copy_size;
        read_size -= copy_size;
    }

    return OG_SUCCESS;
}

static status_t sql_get_array_from_inline_lob(sql_stmt_t *stmt, knl_handle_t locator, vm_lob_t *vlob)
{
    uint32 offset_delta;
    uint32 lob_size = knl_lob_size(locator);
    array_head_t *head = (array_head_t *)knl_inline_lob_data(locator);
    uint32 ctrl_size = sizeof(array_head_t) + head->count * sizeof(elem_dir_t);

    cm_reset_vm_lob(vlob);
    if (ctrl_size % OG_VMEM_PAGE_SIZE == 0) {
        offset_delta = 0;
    } else {
        offset_delta = OG_VMEM_PAGE_SIZE - ctrl_size % OG_VMEM_PAGE_SIZE;
    }
    /* copy array head and element directories, and update dir->offset */
    OG_RETURN_IFERR(sql_copy_array_to_vm(stmt, vlob, OG_TRUE, (char *)head, ctrl_size, offset_delta));
    /* copy elements' value */
    OG_RETURN_IFERR(sql_copy_array_to_vm(stmt, vlob, OG_FALSE, (char *)head + ctrl_size, lob_size - ctrl_size, 0));
    vlob->size = lob_size + offset_delta;
    return OG_SUCCESS;
}

static status_t sql_mv_arr_ele_between_two_vm(handle_t session, vm_pool_t *vm_pool, vm_lob_t *vlob,
    uint32 old_last_vmid, uint32 mv_offset)
{
    /* array must occupy two vm pages */
    CM_ASSERT(vlob->entry_vmid != vlob->last_vmid &&
        vm_get_ctrl(vm_pool, vlob->entry_vmid)->sort_next == vlob->last_vmid);

    errno_t err;
    vm_page_t *first_page = NULL;
    vm_page_t *last_page = NULL;
    uint32 data_offset = OG_VMEM_PAGE_SIZE - mv_offset;

    OG_RETURN_IFERR(vm_open(session, vm_pool, vlob->entry_vmid, &first_page));
    if (vm_open(session, vm_pool, vlob->last_vmid, &last_page) != OG_SUCCESS) {
        vm_close(session, vm_pool, vlob->entry_vmid, VM_ENQUE_TAIL);
        return OG_ERROR;
    }

    do {
        if (old_last_vmid == vlob->last_vmid) {
            err = memmove_s(last_page->data + mv_offset, data_offset, last_page->data, data_offset);
            if (SECUREC_UNLIKELY(err != EOK)) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
                break;
            }
        }
        err = memcpy_sp(last_page->data, mv_offset, first_page->data + data_offset, mv_offset);
        if (SECUREC_UNLIKELY(err != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            break;
        }
    } while (0);

    vm_close(session, vm_pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    vm_close(session, vm_pool, vlob->last_vmid, VM_ENQUE_TAIL);

    return ((err != EOK) ? OG_ERROR : OG_SUCCESS);
}

static status_t sql_uncompress_array_in_vm_inner(sql_stmt_t *stmt, vm_lob_t *vlob, array_head_t *head)
{
    array_assist_t aa;
    vm_pool_t *pool = stmt->mtrl.pool;
    uint32 mv_offset = OG_VMEM_PAGE_SIZE - head->offset % OG_VMEM_PAGE_SIZE;
    uint32 vm_num = cm_get_vlob_page_num(pool, vlob);
    uint32 old_last_vmid = vlob->last_vmid;
    uint32 uncompress_size = head->size + mv_offset;
    handle_t se = KNL_SESSION(stmt);
    uint32 ctrl_size = sizeof(array_head_t) + head->count * sizeof(elem_dir_t);

    /* 1) if current vm pages is not big enough to hold uncompressed array, need to extend one vm page */
    ARRAY_INIT_ASSIST_INFO(&aa, stmt);
    if (uncompress_size > vm_num * OG_VMEM_PAGE_SIZE) {
        OG_RETURN_IFERR(array_extend_vm_page(&aa, vlob));
    }

    /* 2) move array element to head of vm page which is next to last directory's vm page
    notice: when all element are null, no need to move array element */
    if (ctrl_size != head->size) {
        OG_RETURN_IFERR(sql_mv_arr_ele_between_two_vm(se, pool, vlob, old_last_vmid, mv_offset));
    }

    /* 3) update head_size head_offset and dir_offset */
    OG_RETURN_IFERR(array_update_ctrl(se, pool, vlob, uncompress_size, head->count, UNCOMPRESS_ARRAY));

    /* 4) update vlob size */
    vlob->size = uncompress_size;

    return OG_SUCCESS;
}

static status_t sql_uncompress_array_in_vm(sql_stmt_t *stmt, vm_lob_t *vlob)
{
    array_head_t head;

    OG_RETURN_IFERR(cm_get_array_head(KNL_SESSION(stmt), stmt->mtrl.pool, vlob, &head));
    if (head.offset % OG_VMEM_PAGE_SIZE == 0) {
        return OG_SUCCESS;
    }

    return sql_uncompress_array_in_vm_inner(stmt, vlob, &head);
}

static status_t sql_get_array_from_outline_lob(sql_stmt_t *stmt, knl_handle_t locator, vm_lob_t *vlob)
{
    uint32 offset;
    uint32 lob_size;
    uint32 read_size;
    vm_page_t *page = NULL;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    cm_reset_vm_lob(vlob);
    lob_size = knl_lob_size(locator);
    vlob->size = lob_size;
    offset = 0;

    /* read array data from kernel lob to vm lob */
    while (lob_size > 0) {
        if (sql_extend_lob_vmem(stmt, vm_list, vlob) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (vm_open(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, &page) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (knl_read_lob(KNL_SESSION(stmt), locator, offset, page->data, OG_VMEM_PAGE_SIZE, &read_size, NULL) !=
            OG_SUCCESS) {
            vm_close(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, VM_ENQUE_HEAD);
            return OG_ERROR;
        }

        vm_close(KNL_SESSION(stmt), stmt->mtrl.pool, vm_list->last, VM_ENQUE_HEAD);
        offset += read_size;
        lob_size -= read_size;
    }

    return sql_uncompress_array_in_vm(stmt, vlob);
}

status_t sql_get_array_from_knl_lob(sql_stmt_t *stmt, knl_handle_t locator, vm_lob_t *v_lob)
{
    if (knl_lob_is_inline(locator)) {
        return sql_get_array_from_inline_lob(stmt, locator, v_lob);
    } else {
        return sql_get_array_from_outline_lob(stmt, locator, v_lob);
    }
}

status_t sql_get_array_vm_lob(sql_stmt_t *stmt, var_lob_t *var_lob, vm_lob_t *vm_lob)
{
    switch (var_lob->type) {
        case OG_LOB_FROM_KERNEL:
            return sql_get_array_from_knl_lob(stmt, (knl_handle_t)(var_lob->knl_lob.bytes), vm_lob);
        case OG_LOB_FROM_VMPOOL:
            *vm_lob = var_lob->vm_lob;
            return OG_SUCCESS;
        default:
            OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "get array value");
            return OG_ERROR;
    }
}

static inline void sql_set_vm_lob_id_info(sql_stmt_t *stmt, var_lob_t *vm)
{
    sql_cursor_t *cursor = OGSQL_CURR_CURSOR(stmt);

    for (uint32 i = 0; i < cursor->columns->count; i++) {
        if (stmt->vm_lob_ids[i].entry_vmid == vm->vm_lob.entry_vmid) {
            break;
        }
        if (stmt->vm_lob_ids[i].entry_vmid == OG_INVALID_ID32) {
            stmt->vm_lob_ids[i].entry_vmid = vm->vm_lob.entry_vmid;
            stmt->vm_lob_ids[i].last_vmid = vm->vm_lob.last_vmid;
            break;
        }
    }
}

void sql_free_array_vm(sql_stmt_t *stmt, uint32 entry_vmid, uint32 last_vmid)
{
    uint32 next;
    uint32 vmid = entry_vmid;
    vm_ctrl_t *ctrl = NULL;
    id_list_t *list = sql_get_exec_lob_list(stmt);

    while (vmid != OG_INVALID_ID32) {
        ctrl = vm_get_ctrl(stmt->mtrl.pool, vmid);
        next = ctrl->sort_next;
        vm_remove(stmt->mtrl.pool, list, vmid);
        vm_free(stmt->session, stmt->mtrl.pool, vmid);
        if (vmid == last_vmid) {
            break;
        }
        vmid = next;
    }
}

status_t sql_row_put_inline_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v, uint32 real_size)
{
    status_t status;
    char *array_str = NULL;
    uint32 array_len = sizeof(lob_head_t) + real_size;

    /* struct according to lob_locator_t */
    OG_RETURN_IFERR(sql_push(stmt, array_len, (void **)&array_str));

    lob_head_t *lob_head = (lob_head_t *)array_str;
    lob_head->size = real_size;
    lob_head->type = OG_LOB_FROM_KERNEL;
    lob_head->is_outline = OG_FALSE;
    lob_head->node_id = 0;
    lob_head->unused = 0;

    array_head_t *array_head = (array_head_t *)(array_str + sizeof(lob_head_t));
    array_head->count = v->count;
    array_head->size = real_size;
    array_head->datatype = v->type;
    array_head->offset = sizeof(array_head_t) + v->count * sizeof(elem_dir_t);

    if (v->count > 0) {
        char *data = array_str + (sizeof(lob_head_t) + sizeof(array_head_t));
        uint32 data_len = array_len - (sizeof(lob_head_t) + sizeof(array_head_t));
        if (array_convert_inline_lob(KNL_SESSION(stmt), stmt->mtrl.pool, v, data, data_len) != OG_SUCCESS) {
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
    }

    sql_cursor_t *cursor = OGSQL_CURR_CURSOR(stmt);
    if (stmt->vm_lob_ids != NULL && cursor->columns != NULL) {
        sql_set_vm_lob_id_info(stmt, &v->value);
    } else {
        sql_free_array_vm(stmt, v->value.vm_lob.entry_vmid, v->value.vm_lob.last_vmid);
    }

    v->value.type = OG_LOB_FROM_KERNEL;
    v->value.knl_lob.bytes = (uint8 *)array_str;
    v->value.knl_lob.size = array_len;
    v->value.knl_lob.is_hex_const = OG_FALSE;

    status = row_put_lob(ra, v->value.knl_lob.size, &v->value);
    OGSQL_POP(stmt);
    return status;
}

status_t sql_row_put_array(sql_stmt_t *stmt, row_assist_t *ra, var_array_t *v)
{
    if (v->value.type == OG_LOB_FROM_KERNEL) {
        return row_put_lob(ra, v->value.knl_lob.size, &v->value);
    } else {
        uint32 real_size = 0;
        uint32 head_offset = 0;
        OG_RETURN_IFERR(array_actual_size(KNL_SESSION(stmt), stmt->mtrl.pool, v, &real_size, &head_offset));
        if (real_size <= LOB_MAX_INLIINE_SIZE) {
            return sql_row_put_inline_array(stmt, ra, v, real_size);
        }
        OG_RETURN_IFERR(row_put_lob(ra, sizeof(vm_lob_t), &v->value));

        if (stmt->session->call_version < CS_VERSION_10 && v->value.vm_lob.entry_vmid != OG_INVALID_ID32) {
            stmt->lob_info.inuse_count++;
        }
        return OG_SUCCESS;
    }
}

status_t sql_send_column_array(sql_stmt_t *stmt, var_array_t *val)
{
    return sql_row_put_array(stmt, &stmt->ra, val);
}

status_t sql_row_set_lob(sql_stmt_t *stmt, row_assist_t *ra, uint32 lob_locator_size, var_lob_t *lob, uint32 col_id)
{
    ra->col_id = col_id;
    return sql_row_put_lob(stmt, ra, lob_locator_size, lob);
}

status_t sql_row_set_array(sql_stmt_t *stmt, row_assist_t *ra, variant_t *val, uint16 col_id)
{
    ra->col_id = col_id;
    return sql_row_put_array(stmt, ra, &val->v_array);
}

status_t sql_send_column_lob(sql_stmt_t *stmt, var_lob_t *val)
{
    return sql_row_put_lob(stmt, &stmt->ra, g_instance->sql.sql_lob_locator_size, val);
}

status_t sql_send_column_str(sql_stmt_t *stmt, char *str)
{
    return row_put_str(&stmt->ra, str);
}

status_t sql_send_column_text(sql_stmt_t *stmt, text_t *text)
{
    return row_put_text(&stmt->ra, text);
}

status_t sql_send_column_bin(sql_stmt_t *stmt, binary_t *binary)
{
    return row_put_bin(&stmt->ra, binary);
}

status_t sql_send_column_decimal(sql_stmt_t *stmt, dec8_t *dec)
{
    return row_put_dec4(&stmt->ra, dec);
}

status_t sql_send_column_decimal2(sql_stmt_t *stmt, dec8_t *dec)
{
    return row_put_dec2(&stmt->ra, dec);
}


status_t sql_send_column_cursor(sql_stmt_t *stmt, cursor_t *cur)
{
    return row_put_cursor(&stmt->ra, cur);
}


status_t sql_send_return_values(sql_stmt_t *stmt, og_type_t type, typmode_t *typmod, variant_t *val)
{
    return sql_send_value(stmt, NULL, type, typmod, val);
}

static inline uint16 sql_get_datatype_size(int32 datatype)
{
    switch (datatype) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_SMALLINT:
        case OG_TYPE_USMALLINT:
        case OG_TYPE_TINYINT:
        case OG_TYPE_UTINYINT:
            return sizeof(int32);

        case OG_TYPE_BIGINT:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_INTERVAL_DS:
            return sizeof(int64);

        case OG_TYPE_TIMESTAMP_TZ:
            return sizeof(timestamp_tz_t);

        case OG_TYPE_REAL:
            return sizeof(double);

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            return MAX_DEC_BYTE_SZ;
        case OG_TYPE_NUMBER2:
            return MAX_DEC2_BYTE_SZ;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            return g_instance->sql.sql_lob_locator_size;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        default:
            return OG_MAX_COLUMN_SIZE;
    }
}

void sql_send_column_def(sql_stmt_t *stmt, void *sql_cursor)
{
    sql_select_t *select_ctx = NULL;
    sql_cursor_t *cursor = (sql_cursor_t *)sql_cursor;
    og_type_t *types = NULL;
    cs_execute_ack_t *exec_ack = NULL;
    uint32 pending_col_count;
    uint16 parse_type;
    uint8 cmd;

    // 1.pending col has been fixed  2.no need to fix if it has no resultset
    if (stmt->mark_pending_done || stmt->batch_rows == 0) {
        return;
    }

    if (stmt->session->pipe != NULL) {
        cmd = stmt->session->recv_pack->head->cmd;
        // the type of pl-variant which in cursor query is unknown until calc.
        // the cmd include CS_CMD_EXECUTE / CS_CMD_PREP_AND_EXEC
        if (!(cmd == CS_CMD_EXECUTE || cmd == CS_CMD_PREP_AND_EXEC)) {
            return;
        }

        if (stmt->context->type != OGSQL_TYPE_SELECT) {
            return;
        }
    } else {
        return;
    }

    select_ctx = (sql_select_t *)stmt->context->entry;
    if (select_ctx->pending_col_count == 0 || select_ctx != cursor->select_ctx) {
        return;
    }

    exec_ack = (cs_execute_ack_t *)CS_RESERVE_ADDR(stmt->session->send_pack, stmt->exec_ack_offset);
    pending_col_count = exec_ack->pending_col_count;
    if (pending_col_count != cursor->columns->count) {
        return;
    }

    if (cursor->mtrl.rs.buf == NULL) {
        return;
    }

    types = (og_type_t *)(cursor->mtrl.rs.buf + PENDING_HEAD_SIZE);
    for (uint32 i = 0; i < pending_col_count; i++) {
        parse_type = exec_ack->pending_col_defs[i].datatype;
        exec_ack->pending_col_defs[i].datatype = (uint16)(types[i] - OG_TYPE_BASE);
        if (parse_type != exec_ack->pending_col_defs[i].datatype) {
            /* 1.parse_type is unknown 2.parse_type is changed by reparse */
            exec_ack->pending_col_defs[i].size = sql_get_datatype_size(types[i]);
        }
    }

    stmt->mark_pending_done = OG_TRUE;
}

static void sql_read_sqltext(text_t *text, text_t *sql)
{
    text_t line;

    sql->str = text->str;
    sql->len = text->len;

    while (cm_fetch_line(text, &line, OG_TRUE)) {
        cm_rtrim_text(&line);
        if (line.len == 1 && *line.str == '/') {
            sql->len = (uint32)(line.str - sql->str);
            break;
        }
    }
}

static status_t sql_process_sqlfile(session_t *session, int32 file, char *buf, uint32 buf_size)
{
    int32 read_size;
    text_t text;
    text_t sql;

    if (cm_seek_file(file, 0, SEEK_SET) != 0) {
        OG_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        OG_LOG_RUN_ERR("failed to seek file head");
        return OG_ERROR;
    }

    if (cm_read_file(file, buf, (int32)buf_size, &read_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("failed to read data from file");
        return OG_ERROR;
    }

    text.str = buf;
    text.len = (uint32)read_size;

    cm_trim_text(&text);

    while (text.len > 0) {
        sql_read_sqltext(&text, &sql);
        cm_trim_text(&sql);

        if (sql.len == 0) {
            continue;
        }

        if (sql_execute_directly(session, &sql, NULL, OG_TRUE) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_load_sql_file(knl_handle_t handle, const char *full_name)
{
    session_t *session = (session_t *)handle;
    char *buf = NULL;
    int32 file;
    int64 file_size;
    status_t status;

    if (cm_open_file(full_name, O_RDONLY | O_BINARY, &file) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("failed to open file %s", full_name);
        return OG_ERROR;
    }

    file_size = cm_file_size(file);
    if (file_size == -1) {
        cm_close_file(file);
        OG_LOG_RUN_ERR("failed to get file %s size", full_name);
        OG_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return OG_ERROR;
    }

    if (file_size > (int64)OG_MAX_SQLFILE_SIZE) {
        cm_close_file(file);
        OG_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, full_name);
        return OG_ERROR;
    }

    buf = (char *)malloc(OG_MAX_SQLFILE_SIZE);
    if (buf == NULL) {
        cm_close_file(file);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)OG_MAX_SQLFILE_SIZE, "loading sql file");
        return OG_ERROR;
    }

    status = sql_process_sqlfile(session, file, buf, OG_MAX_SQLFILE_SIZE);

    CM_FREE_PTR(buf);
    cm_close_file(file);
    return status;
}

static status_t sql_get_scripts_name(char *full_name, const char *file_name)
{
    char *home = getenv(OG_ENV_HOME);

    if (home == NULL) {
        OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, OG_ENV_HOME);
        return OG_ERROR;
    }

    if (strlen(home) > OG_MAX_PATH_BUFFER_SIZE - 1) {
        OG_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, OG_MAX_PATH_BUFFER_SIZE - 1);
        return OG_ERROR;
    }

    if (cm_check_exist_special_char(home, (uint32)strlen(home))) {
        OG_THROW_ERROR(ERR_INVALID_DIR, home);
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(full_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
        "%s/admin/scripts/%s", home, file_name));

    if (!cm_file_exist(full_name)) {
        OG_THROW_ERROR(ERR_FILE_NOT_EXIST, "scripts", file_name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_load_scripts(knl_handle_t handle, const char *file_name, bool8 is_necessary)
{
    char full_name[OG_FILE_NAME_BUFFER_SIZE] = {'\0'};

    PRTS_RETURN_IFERR(snprintf_s(full_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
        "%s/admin/scripts/%s", g_instance->home, file_name));

    if (!cm_file_exist(full_name)) {
        if (sql_get_scripts_name(full_name, file_name) == OG_ERROR) {
            if (!is_necessary) {
                int32 err_code = cm_get_error_code();
                if (err_code == ERR_FILE_NOT_EXIST) {
                    cm_reset_error();
                    return OG_SUCCESS;
                }
            }
            return OG_ERROR;
        }
    }

    return sql_load_sql_file(handle, full_name);
}
status_t sql_extend_lob_vmem(sql_stmt_t *stmt, id_list_t *list, vm_lob_t *vlob)
{
    if (vlob->entry_vmid != OG_INVALID_ID32) {
        /* simply check whether vmid is in vm_pool or not */
        if (sql_check_lob_vmid(list, stmt->mtrl.pool, vlob->entry_vmid) != OG_SUCCESS ||
            sql_check_lob_vmid(list, stmt->mtrl.pool, vlob->last_vmid) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_NO_FREE_VMEM, "vm page is invalid when write lob value");
            return OG_ERROR;
        }
    }

    if (vm_alloc_and_append(stmt->session, stmt->mtrl.pool, list) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (vlob->entry_vmid == OG_INVALID_ID32) {
        vlob->entry_vmid = list->last;
        vlob->last_vmid = list->last;
    } else {
        vm_get_ctrl(stmt->mtrl.pool, vlob->last_vmid)->sort_next = list->last;
        vlob->last_vmid = list->last;
    }

    return OG_SUCCESS;
}

static status_t sql_copy_lob_data2vm(sql_stmt_t *stmt, lob_write_req_t *req, vm_lob_t *vlob, char *recv_data)
{
    errno_t errcode = 0;
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    uint32 page_offset;
    uint32 copy_size;
    uint32 remain_size;
    uint32 total_size;
    id_list_t *vm_list = sql_get_pre_lob_list(stmt);
    vm_page_t *page = NULL;
    uint32 recv_offset = 0;

    total_size = vlob->size;

    do {
        page_offset = total_size % OG_VMEM_PAGE_SIZE;
        if (vlob->entry_vmid == OG_INVALID_ID32 || page_offset == 0) {
            OG_RETURN_IFERR(sql_extend_lob_vmem(stmt, vm_list, vlob));
            page_offset = 0;
        } else if (sql_check_lob_vmid(vm_list, stmt->mtrl.pool, vlob->last_vmid) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_NO_FREE_VMEM, "vm page is invalid when recv lob data");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(vm_open(stmt->session, vm_pool, vlob->last_vmid, &page));

        copy_size = OG_VMEM_PAGE_SIZE - page_offset;
        remain_size = (uint32)req->size - recv_offset;

        if (copy_size > remain_size) {
            copy_size = remain_size;
        }
        if (copy_size != 0) {
            errcode = memcpy_s(page->data + page_offset, copy_size, recv_data + recv_offset, copy_size);
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                vm_close(stmt->session, vm_pool, vlob->last_vmid, VM_ENQUE_TAIL);
                return OG_ERROR;
            }
        }

        recv_offset += copy_size;
        total_size += copy_size;

        vm_close(stmt->session, vm_pool, vlob->last_vmid, VM_ENQUE_TAIL);
    } while (recv_offset < (uint32)req->size);

    return OG_SUCCESS;
}

static status_t sql_recv_lob_data(sql_stmt_t *stmt, lob_write_req_t *req, vm_lob_t *vlob)
{
    char *recv_data = NULL;
    CM_CHECK_RECV_PACK_FREE(stmt->session->recv_pack, req->size);

    recv_data = CS_READ_ADDR(stmt->session->recv_pack);
    cm_vmcli_lob2vm_lob(vlob, &req->vlob);

    /* write size is 0. */
    if (req->size == 0) {
        vlob->type = OG_LOB_FROM_VMPOOL;
        return OG_SUCCESS;
    }

    /* check whether lob write exceeds to maximum */
    if (((uint64)vlob->size + (uint64)req->size) >= OG_MAX_LOB_SIZE) {
        OG_THROW_ERROR(ERR_LOB_SIZE_TOO_LARGE, "4294967295 bytes");
        return OG_ERROR;
    }

    if (stmt->session->call_version < CS_VERSION_10 && vlob->entry_vmid == OG_INVALID_ID32) {
        stmt->lob_info.inuse_count++;
    }

    OG_RETURN_IFERR(sql_copy_lob_data2vm(stmt, req, vlob, recv_data));

    vlob->size += req->size;
    vlob->type = OG_LOB_FROM_VMPOOL;
    return OG_SUCCESS;
}

status_t sql_write_lob(sql_stmt_t *stmt, lob_write_req_t *req)
{
    cs_packet_t *send_pack = stmt->session->send_pack;
    vm_lob_t vlob;

    OG_RETURN_IFERR(sql_recv_lob_data(stmt, req, &vlob));

    cs_init_set(send_pack, stmt->session->call_version);
    send_pack->head->cmd = CS_CMD_LOB_WRITE;

    OG_RETURN_IFERR(cs_put_int16(send_pack, (uint16)stmt->id));
    // only need to transform vm_cli_lob_t to client
    return cs_put_data(send_pack, &vlob, sizeof(vm_cli_lob_t));
}

status_t sql_read_lob(sql_stmt_t *stmt, void *locator, uint32 offset, void *buf, uint32 size, uint32 *read_size)
{
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    vm_lob_t *vlob = (vm_lob_t *)locator;
    vm_page_t *page = NULL;
    uint32 page_offset;
    uint32 vmid;
    uint32 i;
    uint32 page_size;
    uint32 remain_size;
    uint32 copy_size;
    errno_t errcode;

    *read_size = 0;

    // get the page to read lob data with offset
    if (offset >= vlob->size) {
        return OG_SUCCESS;
    }

    page_offset = offset / OG_VMEM_PAGE_SIZE + 1;
    for (i = 0; i < page_offset; i++) {
        if (i == 0) {
            vmid = vlob->entry_vmid;
        } else {
            vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
        }

        if ((vmid == OG_INVALID_ID32) || (sql_check_lob_vmid(vm_list, vm_pool, vmid) != OG_SUCCESS)) {
            OG_THROW_ERROR(ERR_NO_FREE_VMEM, "invalid vmid to read when do process lob read");
            return OG_ERROR;
        }
    }

    // get size to read
    page_size = page_offset * OG_VMEM_PAGE_SIZE - offset;
    remain_size = vlob->size - offset;
    remain_size = MIN(remain_size, size);

    while (remain_size > 0) {
        OG_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &page));
        copy_size = MIN(remain_size, page_size);
        if (copy_size != 0) {
            errcode = memcpy_s((char *)buf + *read_size, copy_size, (char *)page->data + OG_VMEM_PAGE_SIZE - page_size,
                copy_size);
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
                return OG_ERROR;
            }
        }
        vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);

        remain_size -= copy_size;
        *read_size += copy_size;
        if (remain_size == 0) {
            break;
        }

        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
        if ((vmid == OG_INVALID_ID32) || (sql_check_lob_vmid(vm_list, vm_pool, vmid) != OG_SUCCESS)) {
            OG_THROW_ERROR(ERR_NO_FREE_VMEM, "invalid vmid to read when do process lob read");
            return OG_ERROR;
        }

        page_size = OG_VMEM_PAGE_SIZE;
    }

    return OG_SUCCESS;
}

status_t sql_check_lob_vmid(id_list_t *vm_list, vm_pool_t *vm_pool, uint32 vmid)
{
    vm_ctrl_t *ctrl = NULL;
    uint32 i;
    bool32 found = OG_FALSE;

    /* simply check whether vmid is in current stmt lob list or not */
    do {
        if (vm_list->count == 0) {
            break;
        }

        found = (vm_list->first == vmid);
        if (found || vm_list->first == OG_INVALID_ID32) {
            break;
        }
        ctrl = vm_get_ctrl(vm_pool, vm_list->first);

        for (i = 1; i < vm_list->count; i++) {
            found = (ctrl->next == vmid);
            if (found || ctrl->next == OG_INVALID_ID32) {
                break;
            }
            ctrl = vm_get_ctrl(vm_pool, ctrl->next);
        }
    } while (OG_FALSE);

    if (!found) {
        return OG_ERROR;
    }

    /* simply check whether vmid is in vm_pool or not */
    if (vm_pool->map_pages[vmid / VM_CTRLS_PER_PAGE].cached_page_id >= vm_pool->page_count) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t do_commit(session_t *session)
{
    if (session->knl_session.kernel->db.is_readonly) {
        OG_LOG_DEBUG_WAR("[INST] [COMMIT]:operation not supported on read only mode");
        return OG_SUCCESS;
    }

    knl_commit(&session->knl_session);
    return OG_SUCCESS;
}

void do_rollback(session_t *session, knl_savepoint_t *savepoint)
{
    if (session->knl_session.kernel->db.is_readonly) {
        OG_LOG_DEBUG_WAR("[INST] [ROLLBACK]:operation not supported on read only mode");
        return;
    }

    knl_rollback(&session->knl_session, savepoint);
}

status_t sql_alloc_object_id(sql_stmt_t *stmt, int64 *id)
{
    text_t name;
    text_t sys = {
        .str = SYS_USER_NAME,
        .len = 3
    };
    cm_str2text("OBJECT_ID$", &name);

    return knl_seq_nextval(stmt->session, &sys, &name, id);
}

/*
 * sql_stack_reach_limit
 *
 * This function is used to check the using of current stack.
 */
const long g_stack_reserve_size = (long)OG_STACK_DEPTH_THRESHOLD_SIZE;
static inline bool32 sql_stack_reach_limit(stack_base_t n)
{
    char stack_top_loc;
    if (SECUREC_UNLIKELY(n == NULL)) {
        return OG_FALSE;
    }

    if (labs((long)(n - &stack_top_loc)) > ((long)g_instance->kernel.attr.thread_stack_size - g_stack_reserve_size)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

/*
 * sql_stack_safe
 *
 * This function is used to check the stack is safe or not.
 */
status_t sql_stack_safe(sql_stmt_t *stmt)
{
    if (SECUREC_UNLIKELY(stmt->session->agent == NULL) || stmt->session->type == SESSION_TYPE_SQL_PAR ||
        stmt->session->type == SESSION_TYPE_KERNEL_PAR) {
        return OG_SUCCESS;
    }

    if (sql_stack_reach_limit(stmt->session->agent->thread.stack_base)) {
        OG_THROW_ERROR(ERR_STACK_LIMIT_EXCEED);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_stack_alloc(void *sql_stmt, uint32 size, void **ptr)
{
    sql_stmt_t *stmt = (sql_stmt_t *)sql_stmt;

    if (cm_stack_alloc(stmt->session->stack, size, ptr) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        return OG_ERROR;
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*ptr, size, 0, size));
    }
    return OG_SUCCESS;
}

/*
 * sql_check_trig_commit
 *
 * Commit can not be used in trigger.
 */
status_t sql_check_trig_commit(sql_stmt_t *stmt)
{
    sql_stmt_t *check_stmt = stmt;
    pl_executor_t *exec = NULL;
    pl_entity_t *entity = NULL;

    while (check_stmt != NULL) {
        if (check_stmt->pl_exec != NULL) {
            exec = (pl_executor_t *)check_stmt->pl_exec;
            entity = exec->entity;
            if (entity != NULL && entity->is_auton_trans &&
                (entity->pl_type == PL_FUNCTION || entity->pl_type == PL_PROCEDURE || entity->pl_type == PL_TRIGGER)) {
                return OG_SUCCESS;
            }
            if (entity != NULL && entity->pl_type == PL_TRIGGER) {
                OG_THROW_ERROR(ERR_TRIG_COMMIT);
                return OG_ERROR;
            }
        }

        check_stmt = (sql_stmt_t *)check_stmt->parent_stmt;
    }

    return OG_SUCCESS;
}

static status_t sql_check_curr_user_select_priv(sql_stmt_t *stmt, text_t *username, text_t *tbl_name)
{
    bool32 check;
    if (!cm_text_equal_ins(username, &stmt->session->curr_user)) {
        check = knl_check_sys_priv_by_name(KNL_SESSION(stmt), &stmt->session->curr_user, SELECT_ANY_TABLE);
        if (!check) {
            check = knl_check_obj_priv_by_name(KNL_SESSION(stmt), &stmt->session->curr_user, username, tbl_name,
                OBJ_TYPE_TABLE, OG_PRIV_SELECT);
            if (!check) {
                OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

status_t sql_get_serial_cached_value(sql_stmt_t *stmt, text_t *username, text_t *tbl_name, int64 *val)
{
    knl_dictionary_t dc;
    status_t status;

    OG_RETURN_IFERR(sql_check_curr_user_select_priv(stmt, username, tbl_name));
    OG_RETURN_IFERR(dc_open(KNL_SESSION(stmt), username, tbl_name, &dc));
    status = knl_get_serial_cached_value(KNL_SESSION(stmt), dc.handle, val);
    dc_close(&dc);
    return status;
}

static status_t sql_convert_string(sql_stmt_t *stmt, typmode_t *mode, variant_t *val)
{
    uint32 value_len;
    if (mode->is_char) {
        if (val->v_text.len > OG_MAX_COLUMN_SIZE) {
            OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, val->v_text.len, OG_MAX_COLUMN_SIZE);
            return OG_ERROR;
        }
        if (GET_DATABASE_CHARSET->length(&val->v_text, &value_len) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        value_len = val->v_text.len;
    }

    if (value_len > mode->size) {
        OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, value_len, (uint32)mode->size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline status_t sql_adjust_element_prepare(sql_stmt_t *stmt, typmode_t *mode, uint32 datatype, char *ele_val,
    uint32 *size, variant_t *val)
{
    if (var_gen_variant(ele_val, *size, datatype, val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (datatype != (uint32)mode->datatype) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, val, mode->datatype));
    }
    return OG_SUCCESS;
}

static status_t sql_adjust_element_by_typemode(sql_stmt_t *stmt, typmode_t *mode, uint32 datatype, char *ele_val,
    uint32 *size, variant_t *val)
{
    status_t status = OG_SUCCESS;
    OG_RETURN_IFERR(sql_adjust_element_prepare(stmt, mode, datatype, ele_val, size, val));

    /* convert & check value */
    switch (mode->datatype) {
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
            status = cm_adjust_dec(&val->v_dec, mode->precision, mode->scale);
            break;
        case OG_TYPE_REAL:
            status = cm_adjust_double(&val->v_real, mode->precision, mode->scale);
            break;
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&val->v_tstamp, mode->precision);
            break;
        case OG_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&val->v_tstamp_tz, mode->precision);
            break;
        case OG_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&val->v_itvl_ds, (uint32)mode->precision, (uint32)mode->scale);
            break;
        case OG_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&val->v_itvl_ym, (uint32)mode->precision);
            break;
        case OG_TYPE_CHAR:
            status = sql_convert_char(KNL_SESSION(stmt), val, mode->size, mode->is_char);
            break;
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            status = sql_convert_string(stmt, mode, val);
            break;
        case OG_TYPE_BINARY:
            status = sql_convert_bin(stmt, val, mode->size);
            break;
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            if (val->v_bin.size > mode->size) {
                OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, val->v_bin.size, (uint32)mode->size);
                status = OG_ERROR;
            }
            break;

        default:
            break;
    }

    *size = var_get_size(val);

    return status;
}

status_t sql_var_as_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode)
{
    char *buf = NULL;
    char *ptr = NULL;
    uint32 size;
    uint32 subscript;
    status_t status;
    vm_lob_t *vlob = NULL;
    variant_t tmp_val;
    MEMS_RETURN_IFERR(memset_s(&tmp_val, sizeof(variant_t), 0, sizeof(variant_t)));
    bool32 last = OG_FALSE;
    array_assist_t aa;
    text_t element_str = { NULL, 0 };
    int16 type = v->type;
    text_t array_str = v->v_text;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    if (!OG_IS_ARRAY_TYPE(type) || array_str_invalid(&array_str)) {
        OG_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
        return OG_ERROR;
    }

    v->type = OG_TYPE_ARRAY;
    v->is_null = OG_FALSE;
    v->v_array.type = (int16)mode->datatype;
    v->v_array.value.type = OG_LOB_FROM_VMPOOL;
    v->v_array.count = 0;
    vlob = &v->v_array.value.vm_lob;

    if (array_init(&aa, KNL_SESSION(stmt), stmt->mtrl.pool, vm_list, vlob) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* process null array */
    if (array_str_null(&array_str)) {
        if (array_update_head_datatype(&aa, vlob, (uint32)mode->datatype) != OG_SUCCESS) {
            return OG_ERROR;
        }
        v->v_array.count = 0;
        return OG_SUCCESS;
    }

    sql_keep_stack_variant(stmt, v);
    if (sql_push(stmt, array_str.len, (void **)&buf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    element_str.str = buf;
    element_str.len = 0;
    subscript = 1;

    status = array_get_element_str(&array_str, &element_str, &last);
    while (status == OG_SUCCESS) {
        /* convert & check value */
        size = element_str.len;
        if (cm_text_str_equal_ins(&element_str, "NULL")) {
            if (array_append_element(&aa, subscript, NULL, 0, OG_TRUE, last, vlob) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            /* get the next element */
            subscript++;
            element_str.str = buf;
            element_str.len = 0;
            v->v_array.count++;
            status = array_get_element_str(&array_str, &element_str, &last);
            continue;
        }
        if (sql_adjust_element_by_typemode(stmt, mode, (uint32)type, element_str.str, &size, &tmp_val) != OG_SUCCESS) {
            OGSQL_POP(stmt);
            return OG_ERROR;
        }

        if (OG_IS_VARLEN_TYPE(mode->datatype)) {
            ptr = (char *)tmp_val.v_bin.bytes;
        } else {
            ptr = (char *)VALUE_PTR(int32, &tmp_val);
        }

        status = array_append_element(&aa, subscript, ptr, size, OG_FALSE, last, vlob);
        if (status != OG_SUCCESS) {
            OGSQL_POP(stmt);
            return OG_ERROR;
        }

        if (last) {
            /* no more element */
            v->v_array.count++;
            break;
        }

        /* get the next element */
        subscript++;
        element_str.str = buf;
        element_str.len = 0;
        v->v_array.count++;
        status = array_get_element_str(&array_str, &element_str, &last);
    }

    OGSQL_POP(stmt);
    OG_RETURN_IFERR(status);

    return array_update_head_datatype(&aa, vlob, (uint32)mode->datatype);
}

status_t var_get_value_in_row(variant_t *var, char *buf, uint32 size, uint16 *len)
{
    errno_t err;
    uint16 offset;
    row_assist_t ra;
    status_t status;
    date_t date_val;

    row_init(&ra, buf, size, 1);
    switch (var->type) {
        case OG_TYPE_UINT32:
            status = row_put_uint32(&ra, var->v_uint32);
            break;

        case OG_TYPE_INTEGER:
            status = row_put_int32(&ra, var->v_int);
            break;

        case OG_TYPE_BOOLEAN:
            status = row_put_bool(&ra, var->v_bool);
            break;

        case OG_TYPE_BIGINT:
            status = row_put_int64(&ra, var->v_bigint);
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            status = row_put_dec4(&ra, &var->v_dec);
            break;
        case OG_TYPE_NUMBER2:
            status = row_put_dec2(&ra, &var->v_dec);
            break;

        case OG_TYPE_REAL:
            status = row_put_real(&ra, var->v_real);
            break;

        case OG_TYPE_DATE:
            date_val = cm_adjust_date(var->v_date);
            status = row_put_int64(&ra, date_val);
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            status = row_put_int64(&ra, var->v_tstamp);
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            status = row_put_timestamp_tz(&ra, &var->v_tstamp_tz);
            break;

        case OG_TYPE_INTERVAL_DS:
            status = row_put_dsinterval(&ra, var->v_itvl_ds);
            break;

        case OG_TYPE_INTERVAL_YM:

            status = row_put_yminterval(&ra, var->v_itvl_ym);
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            status = row_put_text(&ra, &var->v_text);
            break;

        default:
            OG_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            status = OG_ERROR;
            break;
    }

    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_decode_row((char *)ra.head, &offset, len, NULL);
    err = memmove_s(buf, size, ra.buf + offset, *len);
    if (err != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t array_convert_datatype(const nlsparams_t *nls, array_assist_t *aa, vm_lob_t *src, text_buf_t *src_buf,
    typmode_t *mode, vm_lob_t *dst, text_buf_t *dst_buf)
{
    uint16 len;
    int32 type;
    uint32 dir_vmid;
    elem_dir_t dir;
    vm_page_t *dir_page = NULL;
    array_head_t *head = NULL;
    array_assist_t dst_aa;
    variant_t var;
    MEMS_RETURN_IFERR(memset_s(&var, sizeof(variant_t), 0, sizeof(variant_t)));
    char *val = NULL;

    OG_RETURN_IFERR(array_init(&dst_aa, aa->session, aa->pool, aa->list, dst));

    aa->dir_curr = sizeof(array_head_t);
    OG_RETURN_IFERR(vm_open(aa->session, aa->pool, src->entry_vmid, &dir_page));

    head = (array_head_t *)(dir_page->data);
    type = head->datatype;
    aa->dir_end = sizeof(array_head_t) + sizeof(elem_dir_t) * head->count;
    vm_close(aa->session, aa->pool, src->entry_vmid, VM_ENQUE_TAIL);

    /* convert datatype for each element in src */
    while (aa->dir_curr < aa->dir_end) {
        dir_vmid = array_get_vmid_by_offset(aa, src, aa->dir_curr);
        if (dir_vmid == OG_INVALID_ID32) {
            return OG_ERROR;
        }

        OG_RETURN_IFERR(vm_open(aa->session, aa->pool, dir_vmid, &dir_page));

        dir = *(elem_dir_t *)(dir_page->data + aa->dir_curr % OG_VMEM_PAGE_SIZE);
        vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);

        if (dir.size == 0) {
            OG_RETURN_IFERR(
                array_append_element(&dst_aa, (uint32)dir.subscript, NULL, 0, ELEMENT_IS_NULL(&dir), dir.last, dst));
            aa->dir_curr += sizeof(elem_dir_t);
            continue;
        }

        OG_RETURN_IFERR(array_get_value_by_dir(aa, src_buf->str, src_buf->max_size, src, &dir));

        src_buf->len = dir.size;
        OG_RETURN_IFERR(var_gen_variant(src_buf->str, src_buf->len, (uint32)type, &var));

        OG_RETURN_IFERR(var_convert(nls, &var, mode->datatype, dst_buf));

        OG_RETURN_IFERR(sql_apply_typmode(&var, mode, dst_buf->str, OG_TRUE));

        /* save the convert value to vm lob */
        if (OG_IS_VARLEN_TYPE(var.type) && var.v_text.str != src_buf->str) {
            OG_RETURN_IFERR(var_get_value_in_row(&var, src_buf->str, src_buf->max_size, &len));
            val = src_buf->str;
        } else {
            OG_RETURN_IFERR(var_get_value_in_row(&var, dst_buf->str, dst_buf->max_size, &len));
            val = dst_buf->str;
        }
        OG_RETURN_IFERR(
            array_append_element(&dst_aa, (uint32)dir.subscript, val, (uint32)len, OG_FALSE, dir.last, dst));

        aa->dir_curr += sizeof(elem_dir_t);
    }

    return array_update_head_datatype(&dst_aa, dst, (uint32)mode->datatype);
}

status_t sql_convert_to_collection(sql_stmt_t *stmt, variant_t *v, void *pl_coll)
{
    switch (v->type) {
        case OG_TYPE_ARRAY:
            return ple_array_as_collection(stmt, v, pl_coll);

        default:
            OG_SET_ERROR_MISMATCH(OG_TYPE_ARRAY, v->type);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* convert to array rules:
   1. array (datatype A -> B): convert every element's datatype of array from A to B.
   2. string -> array : '{va1,val2,val3...,valN}' -> array variant
   3. others -> array : not match.
*/
status_t sql_convert_to_array(sql_stmt_t *stmt, variant_t *v, typmode_t *mode, bool32 apply_mode)
{
    array_assist_t aa;
    vm_lob_t vlob;
    text_buf_t src_textbuf;
    text_buf_t dst_textbuf;
    status_t status = OG_SUCCESS;

    switch (v->type) {
        case OG_TYPE_ARRAY:
            if (v->v_array.value.type == OG_LOB_FROM_KERNEL) {
                OG_RETURN_IFERR(
                    sql_get_array_from_knl_lob(stmt, (knl_handle_t)(v->v_array.value.knl_lob.bytes), &vlob));
                v->v_array.value.vm_lob = vlob;
                v->v_array.value.type = OG_LOB_FROM_VMPOOL;
            }

            if (v->v_array.type == mode->datatype && apply_mode == OG_FALSE) {
                break;
            }

            OG_RETURN_IFERR(sql_push_textbuf(stmt, OG_CONVERT_BUFFER_SIZE, &src_textbuf));
            if (sql_push_textbuf(stmt, OG_CONVERT_BUFFER_SIZE, &dst_textbuf) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }

            ARRAY_INIT_ASSIST_INFO(&aa, stmt);
            if (array_convert_datatype(SESSION_NLS(stmt), &aa, &v->v_array.value.vm_lob, &src_textbuf, mode, &vlob,
                &dst_textbuf) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            v->v_array.value.vm_lob = vlob;
            OGSQL_POP(stmt);
            OGSQL_POP(stmt);
            break;
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            status = sql_var_as_array(stmt, v, mode);
            break;
        default:
            OG_SET_ERROR_MISMATCH(OG_TYPE_ARRAY, v->type);
            return OG_ERROR;
    }

    OG_RETURN_IFERR(status);
    v->type = OG_TYPE_ARRAY;
    /* set the datatype of elements */
    v->v_array.type = (int16)mode->datatype;
    return OG_SUCCESS;
}

status_t sql_compare_array(sql_stmt_t *stmt, variant_t *v1, variant_t *v2, int32 *result)
{
    OG_THROW_ERROR(ERR_INVALID_DATA_TYPE, "comparision");
    return OG_ERROR;
}

/* define convert type methods */
static status_t sql_apply_typmode_char(variant_t *var, const typmode_t *typmod, char *buffer)
{
    uint32 value_len;
    uint32 blank_count;

    // column is defined char attr
    if (typmod->is_char) {
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&var->v_text, &value_len));
    } else {
        value_len = var->v_text.len;
    }

    if (value_len == (uint32)typmod->size) {
        return OG_SUCCESS;
    }

    if (value_len > (uint32)typmod->size) {
        var->v_text.len = (uint32)typmod->size;
        blank_count = 0;
    } else {
        blank_count = (uint32)typmod->size - value_len;
    }

    if (var->v_text.str != buffer) {
        if (var->v_text.len > 0) {
            MEMS_RETURN_IFERR(memcpy_s(buffer, var->v_text.len, var->v_text.str, var->v_text.len));
        }

        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(buffer + var->v_text.len, blank_count, ' ', blank_count));
        }
        var->v_text.str = buffer;
    } else {
        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(var->v_text.str + var->v_text.len, blank_count, ' ', blank_count));
        }
    }

    var->v_text.len += blank_count;

    return OG_SUCCESS;
}

static status_t sql_apply_typmode_str(variant_t *var, const typmode_t *typmod, bool32 is_truc)
{
    uint32 value_len;

    if (typmod->is_char) {
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&var->v_text, &value_len));
    } else {
        value_len = var->v_text.len;
    }

    if (value_len > typmod->size) {
        if (is_truc) {
            var->v_text.len = typmod->size;
        } else {
            OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, value_len, (uint32)typmod->size);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_apply_typmode_bin(variant_t *var, const typmode_t *type_mod, char *buffer)
{
    uint32 blank_count;

    if (var->v_bin.size == (uint32)type_mod->size) {
        return OG_SUCCESS;
    }

    // char that large than definition will be ignore
    if (var->v_bin.size > (uint32)type_mod->size) {
        OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, var->v_bin.size, (uint32)type_mod->size);
        return OG_ERROR;
    }

    blank_count = (uint32)type_mod->size - var->v_bin.size;
    if (var->v_bin.bytes != (uint8 *)buffer) {
        if (var->v_bin.size > 0) {
            MEMS_RETURN_IFERR(memcpy_s(buffer, var->v_bin.size, var->v_bin.bytes, var->v_bin.size));
        }

        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(buffer + var->v_bin.size, blank_count, 0x00, blank_count));
        }
        var->v_bin.bytes = (uint8 *)buffer;
    } else {
        if (blank_count != 0) {
            MEMS_RETURN_IFERR(memset_s(var->v_bin.bytes + var->v_bin.size, blank_count, 0x00, blank_count));
        }
    }

    var->v_bin.size += blank_count;

    return OG_SUCCESS;
}

status_t sql_apply_typmode(variant_t *var, const typmode_t *type_mod, char *buf, bool32 is_truc)
{
    switch (type_mod->datatype) {
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER3:
        case OG_TYPE_NUMBER2:
            return cm_adjust_dec(&var->v_dec, type_mod->precision, type_mod->scale);

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            return cm_adjust_timestamp(&var->v_tstamp, type_mod->precision);

        case OG_TYPE_TIMESTAMP_TZ:
            return cm_adjust_timestamp_tz(&var->v_tstamp_tz, type_mod->precision);

        case OG_TYPE_CHAR:
            return sql_apply_typmode_char(var, type_mod, buf);

        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return sql_apply_typmode_str(var, type_mod, is_truc);

        case OG_TYPE_BINARY:
            return sql_apply_typmode_bin(var, type_mod, buf);

        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            if (var->v_bin.size > type_mod->size) {
                OG_THROW_ERROR(ERR_VALUE_CAST_FAILED, var->v_bin.size, (uint32)type_mod->size);
                return OG_ERROR;
            }
            return OG_SUCCESS;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
        case OG_TYPE_ARRAY:

        case OG_TYPE_BOOLEAN:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_DATE:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:

        case OG_TYPE_RECORD:
            return OG_SUCCESS;

        case OG_TYPE_REAL:
            return cm_adjust_double(&var->v_real, type_mod->precision, type_mod->scale);

        case OG_TYPE_CURSOR:
        case OG_TYPE_COLUMN:
        case OG_TYPE_BASE:

        default:
            OG_THROW_ERROR(ERR_INVALID_DATA_TYPE, "casting");
            return OG_ERROR;
    }
}

status_t sql_convert_bin(sql_stmt_t *stmt, variant_t *v, uint32 def_size)
{
    char *buf = NULL;
    errno_t errcode;

    if (v->v_bin.size == def_size) {
        return OG_SUCCESS;
    }

    if (v->v_bin.size > def_size) {
        OG_THROW_ERROR(ERR_SIZE_ERROR, v->v_bin.size, def_size, "binary");
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, v);

    if (sql_push(stmt, def_size, (void **)&buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if ((v->v_bin.size) != 0) {
        errcode = memcpy_s(buf, def_size, v->v_bin.bytes, v->v_bin.size);
        if (errcode != EOK) {
            OGSQL_RESTORE_STACK(stmt);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
    }
    if ((def_size - v->v_bin.size) != 0) {
        errcode = memset_s(buf + v->v_bin.size, def_size - v->v_bin.size, 0x00, def_size - v->v_bin.size);
        if (errcode != EOK) {
            OGSQL_RESTORE_STACK(stmt);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
    }
    v->v_bin.bytes = (uint8 *)buf;
    v->v_bin.size = def_size;

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

status_t sql_get_char_length(text_t *text, uint32 *characters, uint32 def_size)
{
    uint32 pos;
    uint32 temp_bytes;
    uint32 temp_characters;

    if (g_instance->attr.enable_permissive_unicode == OG_FALSE) {
        return GET_DATABASE_CHARSET->length(text, characters);
    }

    pos = temp_characters = 0;

    while (pos < text->len) {
        (void)GET_DATABASE_CHARSET->str_bytes(text->str + pos, text->len - pos, &temp_bytes);

        if (temp_characters == def_size) {
            text->len = pos;
            break;
        }

        pos += temp_bytes;
        temp_characters++;
    }

    *characters = temp_characters;
    return OG_SUCCESS;
}

status_t sql_convert_char(knl_session_t *session, variant_t *v, uint32 def_size, bool32 is_character)
{
    char *buf = NULL;
    uint32 value_len;
    uint32 column_len;
    errno_t errcode;

    if (v->v_text.len > OG_MAX_COLUMN_SIZE) {
        OG_THROW_ERROR(ERR_SIZE_ERROR, v->v_text.len, OG_MAX_COLUMN_SIZE, "char");
        return OG_ERROR;
    }

    if (is_character) {
        OG_RETURN_IFERR(sql_get_char_length(&v->v_text, &value_len, def_size));
    } else {
        value_len = v->v_text.len;
    }

    if (value_len == def_size) {
        return OG_SUCCESS;
    }

    if (value_len > def_size) {
        OG_THROW_ERROR(ERR_SIZE_ERROR, v->v_text.len, def_size, "char");
        return OG_ERROR;
    }

    // one_character may contain multi char
    column_len = MIN((v->v_text.len + (def_size - value_len)), OG_MAX_COLUMN_SIZE);

    CM_SAVE_STACK(session->stack);
    cm_keep_stack_variant(session->stack, v->v_text.str);

    buf = cm_push(session->stack, column_len);
    if (buf == NULL) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        return OG_ERROR;
    }

    if (v->v_text.len != 0) {
        errcode = memcpy_s(buf, column_len, v->v_text.str, v->v_text.len);
        if (errcode != EOK) {
            CM_RESTORE_STACK(session->stack);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
    }
    if ((column_len - v->v_text.len) != 0) {
        errcode = memset_sp(buf + v->v_text.len, column_len - v->v_text.len, ' ', column_len - v->v_text.len);
        if (errcode != EOK) {
            CM_RESTORE_STACK(session->stack);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
    }
    v->v_text.str = buf;
    v->v_text.len = column_len;

    CM_RESTORE_STACK(session->stack);
    return OG_SUCCESS;
}

status_t sql_convert_char_cb(knl_handle_t session, text_t *text, uint32 def_size, bool32 is_char)
{
    variant_t v;
    v.type = OG_TYPE_CHAR;
    v.v_text.str = text->str;
    v.v_text.len = text->len;

    OG_RETURN_IFERR(sql_convert_char((knl_session_t *)session, &v, def_size, is_char));

    text->str = v.v_text.str;
    text->len = v.v_text.len;
    return OG_SUCCESS;
}

/* define put key methods */
status_t sql_part_put_number_key(variant_t *value, og_type_t data_type, part_key_t *partkey, uint32 precision)
{
    switch (data_type) {
        case OG_TYPE_UINT32:
            return part_put_uint32(partkey, value->v_uint32);
        case OG_TYPE_UINT64:
            return part_put_uint64(partkey, value->v_ubigint);
        case OG_TYPE_INTEGER:
            return part_put_int32(partkey, value->v_int);

        case OG_TYPE_BIGINT:
            return part_put_int64(partkey, value->v_bigint);

        case OG_TYPE_REAL:
            return part_put_real(partkey, value->v_real);

        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER3:
        case OG_TYPE_DECIMAL:
            return part_put_dec4(partkey, &value->v_dec);

        case OG_TYPE_NUMBER2:
            return part_put_dec2(partkey, &value->v_dec);

        case OG_TYPE_DATE:
            return part_put_date(partkey, value->v_date);

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            return part_put_timestamp(partkey, value->v_tstamp);

        case OG_TYPE_TIMESTAMP_TZ:
            return part_put_timestamptz(partkey, &value->v_tstamp_tz);

        case OG_TYPE_INTERVAL_DS:
            return part_put_dsinterval(partkey, value->v_itvl_ds);

        case OG_TYPE_INTERVAL_YM:
            return part_put_yminterval(partkey, value->v_itvl_ym);

        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type");
            return OG_ERROR;
    }
}

status_t sql_part_put_scan_key(sql_stmt_t *stmt, variant_t *value, og_type_t data_type, part_key_t *partkey)
{
    if (value->is_null) {
        part_put_null(partkey);
        return OG_SUCCESS;
    }

    if (value->type != data_type) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, value, data_type));
    }

    switch (data_type) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return part_put_text(partkey, &value->v_text);

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            return part_put_bin(partkey, &value->v_bin);

        default:
            return sql_part_put_number_key(value, data_type, partkey, MQ_MAX_PRECISION);
    }
}

status_t sql_part_put_key(sql_stmt_t *stmt, variant_t *value, og_type_t data_type, uint32 def_size, bool32 is_character,
    uint32 precision, int32 scale, part_key_t *partkey)
{
    uint32 value_len;

    if (value->is_null) {
        part_put_null(partkey);
        return OG_SUCCESS;
    }

    if (value->type != data_type) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, value, data_type));
    }

    switch (data_type) {
        case OG_TYPE_CHAR:
            OG_RETURN_IFERR(sql_convert_char(KNL_SESSION(stmt), value, def_size, is_character));
            return part_put_text(partkey, &value->v_text);

        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            if (is_character) {
                OG_RETURN_IFERR(sql_get_char_length(&value->v_text, &value_len, def_size));
            } else {
                value_len = value->v_text.len;
            }

            return part_put_text(partkey, &value->v_text);

        case OG_TYPE_BINARY:
            OG_RETURN_IFERR(sql_convert_bin(stmt, value, def_size));
            return part_put_bin(partkey, &value->v_bin);

        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            if (value->v_bin.size > def_size) {
                OG_THROW_ERROR(ERR_SIZE_ERROR, value->v_text.len, def_size, "varchar");
                return OG_ERROR;
            }
            return part_put_bin(partkey, &value->v_bin);

        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER:
            OG_RETURN_IFERR(cm_adjust_dec(&value->v_dec, precision, scale));
            return part_put_dec4(partkey, &value->v_dec);

        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(cm_adjust_dec(&value->v_dec, precision, scale));
            return part_put_dec2(partkey, &value->v_dec);

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            OG_RETURN_IFERR(cm_adjust_timestamp(&value->v_tstamp, precision));
            return part_put_timestamp(partkey, value->v_tstamp);

        case OG_TYPE_TIMESTAMP_TZ:
            OG_RETURN_IFERR(cm_adjust_timestamp_tz(&value->v_tstamp_tz, precision));
            return part_put_timestamptz(partkey, &value->v_tstamp_tz);

        case OG_TYPE_REAL:
            OG_RETURN_IFERR(cm_adjust_double(&value->v_real, precision, scale));
            return part_put_real(partkey, value->v_real);

        default:
            return sql_part_put_number_key(value, data_type, partkey, precision);
    }
}

status_t sql_stmt_clone(sql_stmt_t *src, sql_stmt_t *sql_dest)
{
    uint32 pos = 0;
    uint32 count = src->context->params->count;

    sql_dest->parent_stmt = src;

    sql_dest->context = src->context;
    sql_dest->query_scn = src->query_scn;
    sql_dest->gts_scn = src->gts_scn;
    sql_dest->ssn = src->ssn;
    sql_dest->xid = src->xid;
    sql_dest->xact_ssn = src->xact_ssn;
    sql_dest->rs_plan = src->rs_plan;
    sql_dest->rs_type = src->rs_type;
    sql_dest->status = src->status;
    sql_dest->param_info = src->param_info;
    if (count > 0) {
        OG_RETURN_IFERR(sql_alloc_params_buf(sql_dest));
        for (pos = 0; pos < count; pos++) {
            sql_dest->param_info.params[pos] = src->param_info.params[pos];
        }
    }
    sql_dest->params_ready = src->params_ready;

    // reinit
    if (sql_dest->context->fexec_vars_cnt > 0) {
        OG_RETURN_IFERR(cm_stack_alloc(sql_dest->session->stack,
            sizeof(variant_t) * sql_dest->context->fexec_vars_cnt + sql_dest->context->fexec_vars_bytes,
            (void **)&sql_dest->fexec_info.first_exec_vars));

        sql_reset_first_exec_vars(sql_dest);
    }

    sql_dest->hash_views = NULL;
    sql_dest->fexec_info.fexec_buff_offset = 0;
    sql_dest->fexec_info.first_exec_buf = NULL;

    return OG_SUCCESS;
}

status_t sql_init_stmt_plan_time(sql_stmt_t *stmt)
{
    if (stmt->context->plan_count == 0) {
        return OG_SUCCESS;
    }
    if (stmt->plan_cnt < stmt->context->plan_count) {
        OG_RETURN_IFERR(vmc_alloc(&stmt->vmc, sizeof(date_t) * stmt->context->plan_count, (void **)&stmt->plan_time));
        stmt->plan_cnt = stmt->context->plan_count;
        for (uint32 i = 0; i < stmt->context->plan_count; i++) {
            stmt->plan_time[i] = 0;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_init_context_sign(sql_stmt_t *stmt, sql_context_t *ogx)
{
    OG_RETURN_IFERR(sql_alloc_mem(ogx, OG_MD5_SIZE, (void **)&ogx->ctrl.signature.str));
    ogx->ctrl.signature.len = OG_MD5_SIZE;
    OG_RETURN_IFERR(sql_alloc_mem(ogx, OG_MD5_SIZE, (void **)&ogx->spm_sign.str));
    ogx->spm_sign.len = OG_MD5_SIZE;
    OG_RETURN_IFERR(sql_alloc_mem(ogx, OG_MD5_SIZE, (void **)&ogx->sql_sign.str));
    ogx->sql_sign.len = OG_MD5_SIZE;
    return OG_SUCCESS;
}

static status_t sql_init_context(sql_stmt_t *stmt, sql_context_t *sql_ctx)
{
    OG_RETURN_IFERR(sql_init_context_sign(stmt, sql_ctx));
    OG_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(galist_t), (void **)&sql_ctx->tables));
    cm_galist_init(sql_ctx->tables, sql_ctx, sql_alloc_mem);

    OG_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(galist_t), (void **)&sql_ctx->selects));
    cm_galist_init(sql_ctx->selects, sql_ctx, sql_alloc_mem);

    OG_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(galist_t), (void **)&sql_ctx->dc_lst));
    cm_galist_init(sql_ctx->dc_lst, sql_ctx, sql_alloc_mem);

    OG_RETURN_IFERR(sql_alloc_mem(sql_ctx, sizeof(uint32) * TAB_TYPE_MAX, (void **)&sql_ctx->unnamed_tab_counter));

    sql_ctx->large_page_id = OG_INVALID_ID32;
    sql_ctx->sequences = NULL;
    sql_ctx->unsinkable = OG_FALSE;
    sql_ctx->has_func_tab = OG_FALSE;

    sql_ctx->ref_objects = NULL;
    sql_ctx->fexec_vars_cnt = 0;
    sql_ctx->fexec_vars_bytes = 0;
    sql_ctx->hash_optm_count = 0;
    sql_ctx->withas_entry = NULL;
    sql_ctx->opt_by_rbo = OG_FALSE;
    sql_ctx->stat.first_load_time = 0;
    sql_ctx->stat.last_load_time = 0;
    (void)cm_atomic_set(&sql_ctx->stat.last_active_time, 0);
    sql_ctx->module_kind = CLIENT_KIND_UNKNOWN;
    sql_ctx->stat.proc_oid = 0;  /* a valid object id of user-defined procedure starts from 1000 */
    sql_ctx->stat.proc_line = 0; /* a valid line number of user-defined procedure starts from 1 */
    sql_ctx->obj_belong_self = OG_TRUE;
    sql_ctx->has_pl_objects = OG_FALSE;
    sql_ctx->hash_bucket_size = 0;
    sql_ctx->sql_whitelist = OG_FALSE;
    sql_ctx->policy_used = OG_FALSE;
    sql_ctx->nl_batch_cnt = 0;
    sql_ctx->plan_count = 0;
    sql_ctx->parent = NULL;
    sql_ctx->sub_map_id = OG_INVALID_ID32;
    sql_ctx->in_sql_pool = OG_FALSE;
    sql_ctx->cacheable = OG_TRUE;
    sql_ctx->dynamic_sampling = 0;
    sql_ctx->vm_view_count = 0;
    sql_ctx->hash_mtrl_count = 0;
    sql_ctx->query_count = 0;
    return OG_SUCCESS;
}

#ifndef TEST_MEM
status_t sql_alloc_context(sql_stmt_t *stmt)
{
    CM_ASSERT(stmt->context == NULL);
    cm_spin_lock(&stmt->stmt_lock, NULL);
    if (ogx_create(sql_pool, (context_ctrl_t **)&stmt->context)) {
        cm_spin_unlock(&stmt->stmt_lock);
        return OG_ERROR;
    }

    cm_spin_unlock(&stmt->stmt_lock);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_pool_maps(sql_pool->memory);
#endif // DEBUG

    return sql_init_context(stmt, stmt->context);
}
#else
status_t sql_alloc_context(sql_stmt_t *stmt)
{
    errno_t rc_memzero;
    sql_context_t *ogx = (sql_context_t *)malloc(sizeof(sql_context_t));

    if (ogx == NULL) {
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, (uint32)sizeof(sql_context_t));
        return OG_ERROR;
    }

    rc_memzero = memset_s(ogx, sizeof(sql_context_t), 0, sizeof(sql_context_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(ogx);
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, (uint32)sizeof(sql_context_t));
        return OG_ERROR;
    }

    ogx->ctrl.valid = OG_TRUE;
    ogx->ctrl.is_free = OG_FALSE;
    ogx->test_mem_count = 0;
    ogx->test_mem = (void **)malloc(sizeof(void *) * OG_MAX_TEST_MEM_COUNT);

    if (ogx->test_mem == NULL) {
        CM_FREE_PTR(ogx);
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, (uint32)(sizeof(void *) * OG_MAX_TEST_MEM_COUNT));
        return OG_ERROR;
    }
    rc_memzero =
        memset_s(ogx->test_mem, sizeof(void *) * OG_MAX_TEST_MEM_COUNT, 0, sizeof(void *) * OG_MAX_TEST_MEM_COUNT);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(ogx->test_mem);
        CM_FREE_PTR(ogx);
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, (uint32)(sizeof(void *) * OG_MAX_TEST_MEM_COUNT));
        return OG_ERROR;
    }
    SET_STMT_CONTEXT(stmt, ogx);
    return sql_init_context(stmt, ogx);
}

#endif

#ifdef __cplusplus
}
#endif
