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
 * ddl_executor.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ddl_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_dependency.h"
#include "ogsql_privilege.h"
#include "ogsql_insert.h"
#include "knl_tenant.h"
#include "pl_ddl_executor.h"
#include "pl_upgrade.h"
#include "srv_param_common.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_dc.h"

#ifdef DB_DEBUG_VERSION
#include "knl_syncpoint.h"
#endif /* DB_DEBUG_VERSION */
#include "ddl_executor.h"
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#include "var_inc.h"
#endif
#include "dml_parser.h"
#include "dc_tenant.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_execute_create_database(sql_stmt_t *ogsql_stmt, bool32 clustered)
{
    status_t status;
    void *def = ogsql_stmt->context->entry;

    status = knl_create_database(&ogsql_stmt->session->knl_session, (knl_database_def_t *)def, clustered);
    if (status != OG_SUCCESS) {
        (void)srv_shutdown(ogsql_stmt->session, SHUTDOWN_MODE_ABORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_execute_create_space(sql_stmt_t *ogsql_stmt)
{
    knl_space_def_t *def = (knl_space_def_t *)ogsql_stmt->context->entry;

    return knl_create_space(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_init_select_vmc(sql_stmt_t *ogsql_stmt, select_node_t *select_node);
static status_t sql_init_query_vmc(sql_stmt_t *ogsql_stmt, sql_query_t *query)
{
    OG_RETURN_IFERR(vmc_alloc_mem(&ogsql_stmt->vmc, sizeof(vmc_t), (void **)&query->vmc));
    vmc_init(&ogsql_stmt->session->vmp, query->vmc);
    query->filter_infos = NULL;

    for (uint32 i = 0; i < query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == VIEW_AS_TABLE || table->type == SUBSELECT_AS_TABLE) {
            OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, table->select_ctx->root));
        }
    }

    if (query->s_query != NULL) {
        OG_RETURN_IFERR(sql_init_query_vmc(ogsql_stmt, query->s_query));
    }

    for (uint32 i = 0; i < query->ssa.count; ++i) {
        sql_select_t *select_ctx = (sql_select_t *)sql_array_get(&query->ssa, i);
        OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, select_ctx->root));
    }
    return OG_SUCCESS;
}

static status_t sql_init_select_vmc(sql_stmt_t *ogsql_stmt, select_node_t *select_node)
{
    if (select_node->type == SELECT_NODE_QUERY) {
        return sql_init_query_vmc(ogsql_stmt, select_node->query);
    }
    OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, select_node->left));
    return sql_init_select_vmc(ogsql_stmt, select_node->right);
}

static status_t sql_init_withas_vmc(sql_stmt_t *ogsql_stmt, sql_withas_t *withas_ctx)
{
    sql_withas_factor_t *factor = NULL;
    sql_select_t *select_ctx = NULL;
    for (uint32 i = 0; i < withas_ctx->withas_factors->count; ++i) {
        factor = (sql_withas_factor_t *)cm_galist_get(withas_ctx->withas_factors, i);
        select_ctx = (sql_select_t *)factor->subquery_ctx;
        OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, select_ctx->root));
    }
    return OG_SUCCESS;
}

// Note: The memory of query VMC has been released and needs to be initialized again.
static status_t sql_init_insert_vmc(sql_stmt_t *ogsql_stmt, sql_insert_t *insert_ctx)
{
    sql_free_vmemory(ogsql_stmt);
    if (ogsql_stmt->context->withas_entry != NULL) {
        OG_RETURN_IFERR(sql_init_withas_vmc(ogsql_stmt, (sql_withas_t *)ogsql_stmt->context->withas_entry));
    }
    if (insert_ctx->select_ctx != NULL) {
        OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, insert_ctx->select_ctx->root));
    }
    for (uint32 i = 0; i < insert_ctx->ssa.count; ++i) {
        sql_select_t *select_ctx = (sql_select_t *)sql_array_get(&insert_ctx->ssa, i);
        OG_RETURN_IFERR(sql_init_select_vmc(ogsql_stmt, select_ctx->root));
    }
    return OG_SUCCESS;
}

status_t sql_get_ddl_sql(void *sql_stmt, text_t *sql, vmc_t *vmc, bool8 *need_free)
{
    sql_stmt_t *ogsql_stmt = (sql_stmt_t *)sql_stmt;

    *need_free = OG_FALSE;

    if (ogsql_stmt == NULL || ogsql_stmt->lang_type != LANG_DDL || ogsql_stmt->context == NULL) {
        sql->len = 0;
        return OG_ERROR;
    }

    vmc_init(&ogsql_stmt->session->vmp, vmc);
    if (vmc_alloc(vmc, ogsql_stmt->context->ctrl.text_size + 1, (void **)&sql->str) != OG_SUCCESS) {
        sql->len = 0;
        return OG_ERROR;
    }
    sql->len = ogsql_stmt->context->ctrl.text_size + 1;
    *need_free = OG_TRUE;
    if (ogx_read_text(sql_pool, &ogsql_stmt->context->ctrl, sql, OG_FALSE) != OG_SUCCESS) {
        sql->len = 0;
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_try_import_rows(void *sql_stmt, uint32 count)
{
    sql_stmt_t *ogsql_stmt = (sql_stmt_t *)sql_stmt;
    sql_insert_t *insert_ctx = NULL;
    knl_table_def_t *table_def = NULL;
    uint32 col_count;
    uint32 loop;
    uint16 col_id;
    uint16 partkeys;
    sql_cursor_t *cursor = NULL;

    // temporary table, on-commit-preserved-rows not specified, no need to import rows
    table_def = (knl_table_def_t *)ogsql_stmt->context->entry;
    if (table_def->type == TABLE_TYPE_TRANS_TEMP) {
        return OG_SUCCESS;
    }

    // considering create table as select, ogsql_stmt->context->supplement will not be null
    if (!ogsql_stmt->context->supplement) {
        return OG_SUCCESS;
    }

    // generate insert context:
    // 1. allocate memory for insert context
    OG_RETURN_IFERR(sql_alloc_mem(ogsql_stmt->context, sizeof(sql_insert_t), (void **)&insert_ctx));

    // generate insert context:
    // 2. assign select context generated in SQL parsing phase
    insert_ctx->select_ctx = (sql_select_t *)ogsql_stmt->context->supplement;

    // generate insert context:
    // 3. prepare sql table data structure
    OG_RETURN_IFERR(sql_alloc_mem(ogsql_stmt->context, sizeof(sql_table_t), (void **)&insert_ctx->table));
    insert_ctx->table->name.value = table_def->name;
    insert_ctx->table->user.value = table_def->schema;
    insert_ctx->table->alias.len = 0;
    insert_ctx->table->type = NORMAL_TABLE;
    insert_ctx->table->id = 0;
    insert_ctx->batch_commit_cnt = count;

    // generate insert context:
    // 4. prepare sql table entry data structure
    OG_RETURN_IFERR(
        cm_galist_new(ogsql_stmt->context->tables, sizeof(sql_table_entry_t), (pointer_t *)&insert_ctx->table->entry));
    if (knl_open_dc(ogsql_stmt->session, &table_def->schema, &table_def->name, &insert_ctx->table->entry->dc) !=
        OG_SUCCESS) {
        // if open dc failed for insert table,remove this table from table  lists.
        ogsql_stmt->context->tables->count--; // insert table is the last table in list
        return OG_ERROR;
    }
    insert_ctx->table->entry->name = table_def->name;
    insert_ctx->table->entry->user = table_def->schema;

    // generate insert context:
    // 5. mark that columns is not specified
    insert_ctx->flags = INSERT_SET_NONE;

    // generate insert context:
    // 6. generate maps from column to expr in select clause
    col_count = table_def->columns.count;
    OG_RETURN_IFERR(sql_alloc_mem(ogsql_stmt->context, sizeof(uint32) * col_count, (void **)&insert_ctx->col_map));
    MEMS_RETURN_IFERR(
        memset_s(insert_ctx->col_map, sizeof(uint32) * col_count, (int)OG_INVALID_ID8, sizeof(uint32) * col_count));

    insert_ctx->pairs = NULL;

    for (loop = 0; loop < col_count; loop++) {
        // new table, no hidden columns, no deleted column
        insert_ctx->col_map[loop] = loop;
    }
    // 7. generate part_key_map from column to expr in select clause
    if (knl_is_part_table(insert_ctx->table->entry->dc.handle)) {
        OG_RETURN_IFERR(sql_alloc_mem(ogsql_stmt->context, sizeof(uint16) * col_count, (void
            **)&insert_ctx->part_key_map));
        MEMS_RETURN_IFERR(memset_s(insert_ctx->part_key_map, sizeof(uint16) * col_count, (int)OG_INVALID_ID16,
            sizeof(uint16) * col_count));
        partkeys = knl_part_key_count(insert_ctx->table->entry->dc.handle);
        for (loop = 0; loop < partkeys; loop++) {
            col_id = knl_part_key_column_id(insert_ctx->table->entry->dc.handle, loop);
            insert_ctx->part_key_map[col_id] = loop;
        }
    }
    OG_RETURN_IFERR(sql_init_insert_vmc(ogsql_stmt, insert_ctx));
    OG_RETURN_IFERR(sql_generate_insert_plan(ogsql_stmt, insert_ctx, NULL));
    sql_free_vmemory(ogsql_stmt);
    OG_RETURN_IFERR(sql_begin_dml(ogsql_stmt));
    {
        OG_RETURN_IFERR(sql_execute_insert_with_ctx(ogsql_stmt, insert_ctx));
    }
    cursor = OGSQL_ROOT_CURSOR(ogsql_stmt);
    ogsql_stmt->total_rows = cursor->total_rows;
    OG_RETURN_IFERR(my_sender(ogsql_stmt)->send_import_rows(ogsql_stmt));
    knl_commit(&ogsql_stmt->session->knl_session);
    return OG_SUCCESS;
}

static status_t sql_execute_create_ltt(sql_stmt_t *ogsql_stmt, knl_table_def_t *table_def)
{
    bool32 is_existed = OG_FALSE;
    cm_latch_x(&ogsql_stmt->session->knl_session.ltt_latch, ogsql_stmt->session->knl_session.id, NULL);
    if (knl_create_ltt(&ogsql_stmt->session->knl_session, table_def, &is_existed) != OG_SUCCESS) {
        cm_unlatch(&ogsql_stmt->session->knl_session.ltt_latch, NULL);
        return OG_ERROR;
    }
    cm_unlatch(&ogsql_stmt->session->knl_session.ltt_latch, NULL);
    OG_RETSUC_IFTRUE(is_existed);

    status_t status = sql_try_import_rows(ogsql_stmt, 0);
    if (status != OG_SUCCESS) {
        knl_rollback(&ogsql_stmt->session->knl_session, NULL);
        knl_drop_def_t drop_def = { { 0 } };
        drop_def.purge = OG_TRUE;
        drop_def.name = table_def->name;
        drop_def.owner = table_def->schema;
        OG_RETURN_IFERR(knl_drop_ltt(&ogsql_stmt->session->knl_session, &drop_def));
    }

    return status;
}

static status_t sql_execute_create_table(sql_stmt_t *ogsql_stmt)
{
    knl_table_def_t *table_def = (knl_table_def_t *)ogsql_stmt->context->entry;
    knl_part_obj_def_t *obj_def = table_def->part_def;
    char name_arr[OG_NAME_BUFFER_SIZE] = { '\0' };
    text_t part_name;

    if (IS_LTT_BY_NAME(table_def->name.str)) {
        table_def->type = TABLE_TYPE_SESSION_TEMP;
        return sql_execute_create_ltt(ogsql_stmt, table_def);
    }

    // generate the partition name
    if (obj_def != NULL) {
        int64 part_name_id = 0;
        knl_part_def_t *part_def = NULL;
        knl_part_def_t *subpart_def = NULL;
        for (uint32 i = 0; i < obj_def->parts.count; i++) {
            part_def = (knl_part_def_t *)cm_galist_get(&obj_def->parts, i);
            if (part_def->name.len == 0) {
                OG_RETURN_IFERR(sql_alloc_object_id(ogsql_stmt, &part_name_id));
                PRTS_RETURN_IFERR(
                    snprintf_s(name_arr, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "SYS_P%lld", part_name_id));
                part_name.len = (uint32)strlen(name_arr);
                part_name.str = name_arr;

                OG_RETURN_IFERR(sql_copy_object_name(ogsql_stmt->context, WORD_TYPE_STRING, &part_name,
                    &part_def->name));
            }

            if (!part_def->is_parent) {
                continue;
            }

            for (uint32 j = 0; j < part_def->subparts.count; j++) {
                subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, j);
                if (subpart_def->name.len == 0) {
                    OG_RETURN_IFERR(sql_alloc_object_id(ogsql_stmt, &part_name_id));
                    PRTS_RETURN_IFERR(snprintf_s(name_arr, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "SYS_SUBP%lld",
                        part_name_id));
                    part_name.len = (uint32)strlen(name_arr);
                    part_name.str = name_arr;
                    OG_RETURN_IFERR(
                        sql_copy_object_name(ogsql_stmt->context, WORD_TYPE_STRING, &part_name, &subpart_def->name));
                }
            }
        }
    }

    /*
    create table as select scenarios:
               IS_COORD_CONN && distribute_type != none
       1.CN:        0                  1   --> create_table_as_select
       2.DN:        1                  1   --> create_table
       3.singleton: 0                  0   --> create_table_as_select
       4.singleton --datanode with SYSDBA Login:
                    1                  0   --> create_table_as_select
    */
    if (ogsql_stmt->context->supplement == NULL) {
        return knl_create_table(&ogsql_stmt->session->knl_session, ogsql_stmt, table_def);
    }

    return knl_create_table_as_select(&ogsql_stmt->session->knl_session, ogsql_stmt, table_def);
}

static status_t sql_execute_create_user(sql_stmt_t *ogsql_stmt)
{
    status_t ret = OG_SUCCESS;
    errno_t errcode;

    knl_user_def_t *user_def = (knl_user_def_t *)ogsql_stmt->context->entry;

    ret = knl_create_user(&ogsql_stmt->session->knl_session, user_def);
    errcode = memset_s(user_def->password, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }
    return ret;
}

static status_t sql_execute_create_role(sql_stmt_t *ogsql_stmt)
{
    status_t ret = OG_SUCCESS;
    errno_t errcode;

    knl_role_def_t *role_def = (knl_role_def_t *)ogsql_stmt->context->entry;
    ret = knl_create_role(&ogsql_stmt->session->knl_session, role_def);
    errcode = memset_s(role_def->password, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }

    return ret;
}

static status_t sql_execute_drop_user(sql_stmt_t *ogsql_stmt)
{
    uint32 uid;
    knl_drop_user_t *def = (knl_drop_user_t *)ogsql_stmt->context->entry;

    if (!knl_get_user_id(&ogsql_stmt->session->knl_session, &def->owner, &uid)) {
        if (def->options & DROP_IF_EXISTS) {
            cm_reset_error();
            return OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->owner));
            return OG_ERROR;
        }
    }

    /* check if there has an online session with the user dropped now */
    if (srv_whether_login_with_user(&def->owner)) {
        OG_THROW_ERROR(ERR_USER_HAS_LOGIN, T2S(&def->owner));
        return OG_ERROR;
    }

    if (ogsql_stmt->session->knl_session.kernel->dc_ctx.users[uid]->desc.astatus & ACCOUNT_SATTUS_PERMANENT) {
        if (!cm_text_str_equal_ins(&ogsql_stmt->session->curr_user, SYS_USER_NAME)) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only sys can drop the parmanent user");
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(knl_drop_user(&ogsql_stmt->session->knl_session, def));
    return OG_SUCCESS;
}

static status_t sql_execute_drop_tenant(sql_stmt_t *ogsql_stmt)
{
    knl_drop_tenant_t *def = (knl_drop_tenant_t *)ogsql_stmt->context->entry;
    CM_MAGIC_CHECK(def, knl_drop_tenant_t);

    return knl_drop_tenant(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_create_tenant(sql_stmt_t *ogsql_stmt)
{
    knl_tenant_def_t *def = (knl_tenant_def_t *)ogsql_stmt->context->entry;
    CM_MAGIC_CHECK(def, knl_tenant_def_t);

    return knl_create_tenant(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_alter_user_core(sql_stmt_t *ogsql_stmt)
{
    knl_user_def_t *def = (knl_user_def_t *)ogsql_stmt->context->entry;

    OG_RETURN_IFERR(knl_alter_user(&ogsql_stmt->session->knl_session, def));

    return OG_SUCCESS;
}

static status_t sql_execute_alter_user(sql_stmt_t *ogsql_stmt)
{
    errno_t errcode;

    status_t ret = sql_execute_alter_user_core(ogsql_stmt);

    knl_user_def_t *def = (knl_user_def_t *)ogsql_stmt->context->entry;
    errcode = memset_s(def->password, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }

    errcode = memset_s(def->old_password, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }

    return ret;
}

static status_t knl_alter_tenant(knl_session_t *session, knl_tenant_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 id = se->id;
    status_t status;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);

    if (knl_ddl_enabled(session, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    dls_latch_x(session, ddl_latch, id, NULL);
    status = tenant_alter(se, def);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

static status_t sql_execute_alter_tenant(sql_stmt_t *ogsql_stmt)
{
    knl_tenant_def_t *def = (knl_tenant_def_t *)ogsql_stmt->context->entry;
    CM_MAGIC_CHECK(def, knl_tenant_def_t);

    return knl_alter_tenant(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_drop_role(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;
    return knl_drop_role(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_create_sequence(sql_stmt_t *ogsql_stmt)
{
    knl_sequence_def_t *seuqence_def = (knl_sequence_def_t *)ogsql_stmt->context->entry;
    return knl_create_sequence(&ogsql_stmt->session->knl_session, ogsql_stmt, seuqence_def);
}

status_t sql_execute_create_index(sql_stmt_t *ogsql_stmt)
{
    knl_index_def_t *def = (knl_index_def_t *)ogsql_stmt->context->entry;
    status_t status;

    if (IS_LTT_BY_NAME(def->table.str)) {
        status = knl_create_ltt_index(&ogsql_stmt->session->knl_session, def);
    } else {
        status = knl_create_index(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    }

    return status;
}

static status_t sql_execute_create_indexes(sql_stmt_t *ogsql_stmt)
{
    knl_indexes_def_t *def = (knl_indexes_def_t *)ogsql_stmt->context->entry;
    return knl_create_indexes(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_execute_create_view(sql_stmt_t *ogsql_stmt)
{
    knl_view_def_t *def = (knl_view_def_t *)ogsql_stmt->context->entry;

    if (def->is_replace) {
        return knl_create_or_replace_view(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    }
    return knl_create_view(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_execute_create_synonym(sql_stmt_t *ogsql_stmt)
{
    knl_synonym_t synonym;
    bool32 found_object = OG_FALSE;
    knl_synonym_def_t *def = (knl_synonym_def_t *)ogsql_stmt->context->entry;

    /* check synonym is or not exists and load info of synonym */
    if (knl_check_and_load_synonym(KNL_SESSION(ogsql_stmt), &def->owner, &def->name, &synonym, &found_object) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    /* IF found the synonym and  SYNONYM_IS_REPLACE ,According to the synonym type,drop it first */
    if (found_object) {
        if (SYNONYM_IS_REPLACE & def->flags) {
            if (!IS_PL_SYN(synonym.type)) {
                knl_drop_def_t *drop_def = (knl_drop_def_t *)ogsql_stmt->context->entry;
                if (knl_drop_synonym(KNL_SESSION(ogsql_stmt), NULL, drop_def) != OG_SUCCESS) {
                    return OG_ERROR;
                }
            }
        } else {
            OG_THROW_ERROR(ERR_OBJECT_EXISTS, T2S(&def->owner), T2S_EX(&def->name));
            return OG_ERROR;
        }
    }

    if (def->is_knl_syn) {
        return knl_create_synonym(KNL_SESSION(ogsql_stmt), ogsql_stmt, def);
    } else {
        if (pl_execute_create_replace_synonym(ogsql_stmt) != OG_SUCCESS) {
            sql_check_user_priv(ogsql_stmt, &def->table_owner);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
}

static status_t sql_execute_drop_synonym(sql_stmt_t *ogsql_stmt)
{
    status_t status = OG_SUCCESS;
    bool32 found_object = OG_FALSE;
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;
    knl_synonym_t synonym;

    /* check synonym is or not exists and load info of synonym */
    if (knl_check_and_load_synonym(KNL_SESSION(ogsql_stmt), &def->owner, &def->name, &synonym, &found_object) !=
        OG_SUCCESS) {
        cm_reset_error();
    }

    if (!found_object) {
        cm_reset_error();
        if (def->options & DROP_IF_EXISTS) {
            return OG_SUCCESS;
        }
        OG_THROW_ERROR(ERR_SYNONYM_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return OG_ERROR;
    } else if (synonym.type != OBJ_TYPE_FUNCTION) {
        /*
         * judge whether the command should be delivered to dn.
         * if found the object of synonym, open the dc of the object.the function knl_open_dc can actually return the dc
         * of the object of synonym, so we can pass the name of synonym to it. if the type of the object of synonym is
         * equal to DICT_TYPE_GLOBAL_DYNAMIC_VIEW, do not deliver the command to dn. e.g. gdv_sessions
         */
    }

    // init the obj_addr for updating depender status
    if (!IS_PL_SYN(synonym.type)) {
        status = knl_drop_synonym(KNL_SESSION(ogsql_stmt), ogsql_stmt, def);
    } else {
        status = pl_execute_drop_synonym(ogsql_stmt);
    }

    return status;
}

static status_t sql_execute_alter_database_tz(sql_stmt_t *ogsql_stmt, text_t *timezone_offset_name)
{
    bool32 exist = OG_FALSE;
    char param_new_value[TIMEZONE_OFFSET_STRLEN] = { 0 };

    /* check if there are columns which type are timestamp with local timezone exists in database  */
    OG_RETURN_IFERR(sql_check_exist_cols_type(ogsql_stmt, OG_TYPE_TIMESTAMP_LTZ, &exist));
    if (exist) {
        OG_THROW_ERROR(ERR_ALTER_DB_TIMEZONE_FAILED);
        return OG_ERROR;
    }

    /* EFFECT_REBOOT */
    MEMS_RETURN_IFERR(
        memcpy_sp(param_new_value, TIMEZONE_OFFSET_STRLEN, timezone_offset_name->str, timezone_offset_name->len));

    /* write this config to configfile */
    if (cm_alter_config(ogsql_stmt->session->knl_session.kernel->attr.config, "DB_TIMEZONE", param_new_value,
        CONFIG_SCOPE_BOTH, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_execute_alter_database(sql_stmt_t *ogsql_stmt)
{
    knl_alterdb_def_t *def = (knl_alterdb_def_t *)ogsql_stmt->context->entry;

    switch (def->action) {
        case ALTER_DB_TIMEZONE:
            return sql_execute_alter_database_tz(ogsql_stmt, &def->timezone_offset_name);
        case UPGRADE_PROCEDURE:
            return pl_upgrade_build_object(&ogsql_stmt->session->knl_session);
        default:
            break;
    }

    OG_RETURN_IFERR(knl_alter_database(&ogsql_stmt->session->knl_session, def));

    if (def->action == DELETE_ARCHIVELOG && def->dele_arch.delete_abnormal) {
        if (sql_try_send_backup_warning(ogsql_stmt) != OG_SUCCESS) {
            return OG_ERROR;
        }
        cm_reset_error();
    }
    return OG_SUCCESS;
}

static status_t sql_execute_alter_table(sql_stmt_t *ogsql_stmt)
{
    status_t status = OG_SUCCESS;
    bool32 altab_depend_modify = OG_FALSE;
    knl_altable_def_t *def = (knl_altable_def_t *)ogsql_stmt->context->entry;
    obj_info_t obj_addr;
    bool32 alter_local_table = OG_TRUE;

    if (def->action == ALTABLE_SHRINK) {
        return knl_alter_table_shrink(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    }
    sql_table_entry_t *table = (sql_table_entry_t *)cm_galist_get(ogsql_stmt->context->tables, 0);
    obj_addr.oid = table->dc.oid;
    obj_addr.tid = OBJ_TYPE_TABLE;
    obj_addr.uid = table->dc.uid;

    if (alter_local_table) {
        status = knl_alter_table(&ogsql_stmt->session->knl_session, ogsql_stmt, def, OG_TRUE);
    }

    altab_depend_modify = def->action == ALTABLE_DROP_COLUMN || def->action == ALTABLE_RENAME_COLUMN ||
        def->action == ALTABLE_ADD_COLUMN || def->action == ALTABLE_RENAME_TABLE ||
        def->action == ALTABLE_MODIFY_COLUMN;

    if (status == OG_SUCCESS && altab_depend_modify) {
        OG_RETURN_IFERR(sql_update_depender_status(KNL_SESSION(ogsql_stmt), (obj_info_t *)&obj_addr));
        knl_commit(KNL_SESSION(ogsql_stmt));
    }

    return status;
}

status_t sql_execute_alter_index(sql_stmt_t *ogsql_stmt)
{
    knl_alindex_def_t *def = (knl_alindex_def_t *)ogsql_stmt->context->entry;

    if (IS_ALTER_INDEX_COALESCE(def)) {
        return knl_alter_index_coalesce(&ogsql_stmt->session->knl_session, def);
    } else {
        return knl_alter_index(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    }
}

static status_t sql_execute_drop_table(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;
    status_t status;

    if (IS_LTT_BY_NAME(def->name.str)) {
        status = knl_drop_ltt(&ogsql_stmt->session->knl_session, def);
    } else {
        status = knl_drop_table(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
        if (status == OG_ERROR) {
            int32 code = cm_get_error_code();
            if (((ERR_TABLE_OR_VIEW_NOT_EXIST == code) || (ERR_USER_NOT_EXIST == code)) &&
                (def->options & DROP_IF_EXISTS)) {
                // return success if drop clause containt if exists and object is not exists
                cm_reset_error();
                return OG_SUCCESS;
            }
        }
    }
    return status;
}

status_t sql_execute_drop_index(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;
    status_t status;
    if (def->ex_name.str != NULL && IS_LTT_BY_NAME(def->ex_name.str)) {
        status = knl_drop_ltt_index(&ogsql_stmt->session->knl_session, def);
    } else {
        status = knl_drop_index(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    }
    return status;
}

static status_t sql_execute_drop_view(sql_stmt_t *ogsql_stmt)
{
    status_t status;
    int32 errcode;
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;

    status = knl_drop_view(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
    if (status == OG_ERROR) {
        // drop if exists return success
        if (def->options & DROP_IF_EXISTS) {
            errcode = cm_get_error_code();
            if (errcode == ERR_TABLE_OR_VIEW_NOT_EXIST || errcode == ERR_USER_NOT_EXIST) {
                cm_reset_error();
                return OG_SUCCESS;
            }
        }

        sql_check_user_priv(ogsql_stmt, &def->owner);
    }
    return status;
}

static status_t sql_execute_truncate_table(sql_stmt_t *ogsql_stmt)
{
    knl_trunc_def_t *def = (knl_trunc_def_t *)ogsql_stmt->context->entry;
    if (knl_truncate_table(&ogsql_stmt->session->knl_session, ogsql_stmt, def) == OG_ERROR) {
        sql_check_user_priv(ogsql_stmt, &def->owner);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_execute_flashback_table(sql_stmt_t *ogsql_stmt)
{
    knl_flashback_def_t *def = (knl_flashback_def_t *)ogsql_stmt->context->entry;

    if (def->type == FLASHBACK_TO_SCN) {
        if (sql_convert_to_scn(ogsql_stmt, def->expr, OG_TRUE, &def->scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (def->type == FLASHBACK_TO_TIMESTAMP) {
        if (sql_convert_to_scn(ogsql_stmt, def->expr, OG_FALSE, &def->scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    {
        return knl_flashback_table(&ogsql_stmt->session->knl_session, def);
    }
}

static status_t sql_execute_purge(sql_stmt_t *ogsql_stmt)
{
    knl_purge_def_t *def = (knl_purge_def_t *)ogsql_stmt->context->entry;

    return knl_purge(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_drop_space(sql_stmt_t *ogsql_stmt)
{
    knl_drop_space_def_t *def = (knl_drop_space_def_t *)ogsql_stmt->context->entry;

    return knl_drop_space(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_execute_drop_sequence(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;

    return knl_drop_sequence(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_execute_alter_space(sql_stmt_t *ogsql_stmt)
{
    knl_altspace_def_t *def = (knl_altspace_def_t *)ogsql_stmt->context->entry;

    if (def->action == ALTSPACE_DROP_DATAFILE || def->action == ALTSPACE_RENAME_DATAFILE ||
        def->action == ALTSPACE_OFFLINE_DATAFILE) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "drop, rename or offline datafile when alter tablespace");
        return OG_ERROR;
    }

    return knl_alter_space(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

static status_t sql_execute_analyze_table(sql_stmt_t *ogsql_stmt)
{
    knl_analyze_tab_def_t *def = (knl_analyze_tab_def_t *)ogsql_stmt->context->entry;
    status_t status;

    if (!def->is_report) {
        def->sample_ratio = 0;
        def->sample_type = STATS_AUTO_SAMPLE;
    }

    OG_RETURN_IFERR(sql_check_trig_commit(ogsql_stmt));

    /* check privilage */
    if (!sql_check_stats_priv(ogsql_stmt->session, &def->owner)) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }

    sql_record_knl_stats_info(ogsql_stmt);
    status = knl_analyze_table(&ogsql_stmt->session->knl_session, def);
    sql_reset_knl_stats_info(ogsql_stmt, status);
    return status;
}

static status_t sql_execute_analyze_index(sql_stmt_t *ogsql_stmt)
{
    knl_analyze_index_def_t *def = (knl_analyze_index_def_t *)ogsql_stmt->context->entry;

    OG_RETURN_IFERR(sql_check_trig_commit(ogsql_stmt));

    /* check privilage */
    if (!sql_check_stats_priv(ogsql_stmt->session, &def->owner)) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }

    return knl_analyze_index(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_create_library(sql_stmt_t *ogsql_stmt)
{
    pl_library_def_t *def = (pl_library_def_t *)ogsql_stmt->context->entry;

    return pl_create_library(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_drop_library(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;

    return pl_drop_library(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_alter_sequence(sql_stmt_t *ogsql_stmt)
{
    knl_sequence_def_t *def = (knl_sequence_def_t *)ogsql_stmt->context->entry;

    return knl_alter_sequence(&ogsql_stmt->session->knl_session, ogsql_stmt, def);
}

#define MAX_KNL_NODE_HASH_RANGE 10000

static status_t sql_execute_comment_on(sql_stmt_t *ogsql_stmt)
{
    knl_comment_def_t *def = (knl_comment_def_t *)ogsql_stmt->context->entry;

    return knl_comment_on(KNL_SESSION(ogsql_stmt), ogsql_stmt, def);
}

static status_t sql_execute_create_profile(sql_stmt_t *ogsql_stmt)
{
    knl_profile_def_t *def = (knl_profile_def_t *)ogsql_stmt->context->entry;

    return knl_create_profile(KNL_SESSION(ogsql_stmt), def);
}

static status_t sql_execute_drop_profile(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;

    return knl_drop_profile(KNL_SESSION(ogsql_stmt), def);
}

static status_t sql_execute_create_directory(sql_stmt_t *ogsql_stmt)
{
    knl_directory_def_t *def = (knl_directory_def_t *)ogsql_stmt->context->entry;

    return knl_create_directory(KNL_SESSION(ogsql_stmt), def);
}

static status_t sql_execute_drop_directory(sql_stmt_t *ogsql_stmt)
{
    knl_drop_def_t *def = (knl_drop_def_t *)ogsql_stmt->context->entry;

    return knl_drop_directory(KNL_SESSION(ogsql_stmt), def);
}

static status_t sql_execute_create_ctrlfile(sql_stmt_t *ogsql_stmt)
{
    knl_rebuild_ctrlfile_def_t *def = (knl_rebuild_ctrlfile_def_t *)ogsql_stmt->context->entry;

    return knl_rebuild_ctrlfile(KNL_SESSION(ogsql_stmt), def);
}

static status_t sql_execute_alter_profile(sql_stmt_t *ogsql_stmt)
{
    knl_profile_def_t *def = (knl_profile_def_t *)ogsql_stmt->context->entry;

    OG_RETURN_IFERR(knl_alter_profile(KNL_SESSION(ogsql_stmt), def));
    OG_LOG_RUN_WAR("profile of %s has been changed successfully", T2S(&def->name));
    OG_LOG_ALARM(WARN_PROFILECHANGE, "profile : %s", T2S(&def->name));
    return OG_SUCCESS;
}


static status_t sql_execute_grant(sql_stmt_t *ogsql_stmt)
{
    ogsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;

    knl_grant_def_t *def = (knl_grant_def_t *)ogsql_stmt->context->entry;

    return knl_exec_grant_privs(&ogsql_stmt->session->knl_session, def);
}

static status_t sql_execute_revoke(sql_stmt_t *ogsql_stmt)
{
    ogsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;

    knl_revoke_def_t *def = (knl_revoke_def_t *)ogsql_stmt->context->entry;

    return knl_exec_revoke_privs(&ogsql_stmt->session->knl_session, def);
}

status_t sql_execute_ddl(sql_stmt_t *ogsql_stmt)
{
    status_t status;
    ogsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;
    if (pl_check_trig_and_udf(ogsql_stmt->parent_stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (knl_is_dist_ddl(KNL_SESSION(ogsql_stmt)) == OG_FALSE) {
        if (do_commit(ogsql_stmt->session) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    sql_set_scn(ogsql_stmt);
    sql_set_ssn(ogsql_stmt);

    switch (ogsql_stmt->context->type) {
        case OGSQL_TYPE_CREATE_DATABASE:
            status = sql_execute_create_database(ogsql_stmt, OG_FALSE);
            // 'create database ...' will execute multiple SQL by calling multiple sql_execute_directly
            ogsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;
            break;

        case OGSQL_TYPE_CREATE_CLUSTERED_DATABASE:
            status = sql_execute_create_database(ogsql_stmt, OG_TRUE);
            ogsql_stmt->session->sql_audit.audit_type = SQL_AUDIT_DDL;
            break;


        case OGSQL_TYPE_CREATE_SEQUENCE:
            status = sql_execute_create_sequence(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_TABLESPACE:
            status = sql_execute_create_space(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_TABLE:
            status = sql_execute_create_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_INDEX:
            status = sql_execute_create_index(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_INDEXES:
            status = sql_execute_create_indexes(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_USER:
            status = sql_execute_create_user(ogsql_stmt);
            OG_RETURN_IFERR(sql_clear_origin_sql(ogsql_stmt));
            break;
        case OGSQL_TYPE_CREATE_TENANT:
            status = sql_execute_create_tenant(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_ROLE:
            status = sql_execute_create_role(ogsql_stmt);
            OG_RETURN_IFERR(sql_clear_origin_sql(ogsql_stmt));
            break;
        case OGSQL_TYPE_CREATE_VIEW:
            status = sql_execute_create_view(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_SYNONYM:
            status = sql_execute_create_synonym(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_PROFILE:
            status = sql_execute_create_profile(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_DIRECTORY:
            status = sql_execute_create_directory(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_CTRLFILE:
            status = sql_execute_create_ctrlfile(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_LIBRARY:
            status = sql_execute_create_library(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_SEQUENCE:
            status = sql_execute_drop_sequence(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TABLESPACE:
            status = sql_execute_drop_space(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TABLE:
            status = sql_execute_drop_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_INDEX:
            status = sql_execute_drop_index(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_USER:
            status = sql_execute_drop_user(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_ROLE:
            status = sql_execute_drop_role(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_VIEW:
            status = sql_execute_drop_view(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_SYNONYM:
            status = sql_execute_drop_synonym(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_PROFILE:
            status = sql_execute_drop_profile(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_DIRECTORY:
            status = sql_execute_drop_directory(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_LIBRARY:
            status = sql_execute_drop_library(ogsql_stmt);
            break;

        case OGSQL_TYPE_TRUNCATE_TABLE:
            status = sql_execute_truncate_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_PURGE:
            status = sql_execute_purge(ogsql_stmt);
            break;
        case OGSQL_TYPE_COMMENT:
            status = sql_execute_comment_on(ogsql_stmt);
            break;
        case OGSQL_TYPE_FLASHBACK_TABLE:
            status = sql_execute_flashback_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_SEQUENCE:
            status = sql_execute_alter_sequence(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_TABLESPACE:
            status = sql_execute_alter_space(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_TABLE:
            status = sql_execute_alter_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_INDEX:
            status = sql_execute_alter_index(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_USER:
            status = sql_execute_alter_user(ogsql_stmt);
            OG_RETURN_IFERR(sql_clear_origin_sql(ogsql_stmt));
            break;
        case OGSQL_TYPE_ALTER_TENANT:
            status = sql_execute_alter_tenant(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TENANT:
            status = sql_execute_drop_tenant(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_DATABASE:
            status = sql_execute_alter_database(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_PROFILE:
            status = sql_execute_alter_profile(ogsql_stmt);
            break;
        case OGSQL_TYPE_ALTER_TRIGGER:
            status = pl_execute_alter_trigger(ogsql_stmt);
            break;
        case OGSQL_TYPE_ANALYSE_TABLE:
            status = sql_execute_analyze_table(ogsql_stmt);
            break;
        case OGSQL_TYPE_ANALYZE_INDEX:
            status = sql_execute_analyze_index(ogsql_stmt);
            break;
        case OGSQL_TYPE_GRANT:
            status = sql_execute_grant(ogsql_stmt);
            break;
        case OGSQL_TYPE_REVOKE:
            status = sql_execute_revoke(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_PROC:
        case OGSQL_TYPE_CREATE_FUNC:
            status = pl_execute_create_replace_procedure(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_PACK_SPEC:
            status = pl_execute_create_replace_package_spec(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_PACK_BODY:
            status = pl_execute_create_replace_package_body(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_TRIG:
            status = pl_execute_create_replace_trigger(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_TYPE_SPEC:
            status = pl_execute_create_replace_type_spec(ogsql_stmt);
            break;
        case OGSQL_TYPE_CREATE_TYPE_BODY:
            status = pl_execute_create_replace_type_body(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_PROC:
        case OGSQL_TYPE_DROP_FUNC:
            status = pl_execute_drop_procedure(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TRIG:
            status = pl_execute_drop_trigger(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_PACK_SPEC:
            status = pl_execute_drop_package_spec(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_PACK_BODY:
            status = pl_execute_drop_package_body(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TYPE_SPEC:
            status = pl_execute_drop_type_spec(ogsql_stmt);
            break;
        case OGSQL_TYPE_DROP_TYPE_BODY:
            status = pl_execute_drop_type_body(ogsql_stmt);
            break;
        default:
            ogsql_stmt->eof = OG_TRUE;
            OG_THROW_ERROR(ERR_INVALID_COMMAND, "ddl");
            return OG_ERROR;
    }

    if (status == OG_SUCCESS) {
        (void)do_commit(ogsql_stmt->session);
    } else {
        do_rollback(ogsql_stmt->session, NULL);
    }

    return status;
}


#ifdef __cplusplus
}
#endif
