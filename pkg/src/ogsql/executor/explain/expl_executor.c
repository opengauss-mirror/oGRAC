/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * expl_executor.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_executor.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_stmt.h"
#include "dml_executor.h"
#include "expl_explain_create.h"
#include "expl_plan.h"
#include "expl_executor.h"

#define EXPL_FMT_ALIGN_SIZE 3  // eg. "ID | Operation | ..."
#define EXPL_FMT_COL_OFFSET 2  // eg. '| '
#define EXPLAIN_PREDICATE_HEAD "Predicate Information (identified by id):"

static status_t expl_open_segment(sql_stmt_t *statement, sql_cursor_t *cursor)
{
    OG_RETURN_IFERR(mtrl_create_segment(&statement->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.rs.sid));
    OG_RETURN_IFERR(mtrl_open_segment(&statement->mtrl, cursor->mtrl.rs.sid));
    OG_RETURN_IFERR(mtrl_create_segment(&statement->mtrl, MTRL_SEGMENT_RS, NULL, &cursor->mtrl.predicate.sid));
    OG_RETURN_IFERR(mtrl_open_segment(&statement->mtrl, cursor->mtrl.predicate.sid));
    return OG_SUCCESS;
}

void expl_close_segment(sql_stmt_t *statement, sql_cursor_t *cursor)
{
    mtrl_close_segment(&statement->mtrl, cursor->mtrl.rs.sid);
    mtrl_close_segment(&statement->mtrl, cursor->mtrl.predicate.sid);
}

status_t expl_pre_execute(sql_stmt_t *statement, sql_cursor_t **cursor)
{
    if (statement->param_info.paramset_size == 0) {
        statement->param_info.paramset_size = 1;
    }
    statement->resource_inuse = OG_TRUE;

    OG_RETURN_IFERR(sql_alloc_cursor(statement, cursor));
    (*cursor)->is_open = true;
    if (SQL_CURSOR_PUSH(statement, *cursor) != OG_SUCCESS) {
        sql_free_cursor(statement, *cursor);
        return OG_ERROR;
    }

    status_t ret = expl_open_segment(statement, *cursor);
    if (ret != OG_SUCCESS) {
        sql_free_cursor(statement, *cursor);
        SQL_CURSOR_POP(statement);
    }
    return ret;
}

static status_t expl_send_explain_row(sql_stmt_t *statement,
                                      sql_cursor_t *cursor, char *row_buf, char *info, bool32 *is_full)
{
    row_assist_t ra;
    MEMS_RETURN_IFERR(memset_s(row_buf, OG_MAX_ROW_SIZE, 0, OG_MAX_ROW_SIZE));

    row_init(&ra, row_buf, OG_MAX_ROW_SIZE, 1);
    OG_RETURN_IFERR(row_put_str(&ra, info));
    OG_RETURN_IFERR(my_sender(statement)->send_row_data(statement, row_buf, is_full));

    sql_inc_rows(statement, cursor);
    return OG_SUCCESS;
}

static status_t expl_send_explain_text(text_t *plan_text, const char *buffer)
{
    uint32 buf_len = (uint32)strlen(buffer);
    uint32 remain_len = MIN(buf_len, plan_text->len);
    OG_RETVALUE_IFTRUE(remain_len == 0, OG_SUCCESS);

    MEMS_RETURN_IFERR(memcpy_s(plan_text->str, plan_text->len, buffer, remain_len));

    if (remain_len == plan_text->len) {
        plan_text->str[remain_len - 1] = '\0';
    } else {
        plan_text->str[remain_len++] = '\n';
    }

    CM_REMOVE_FIRST_N(plan_text, remain_len);
    return OG_SUCCESS;
}

static status_t expl_send_explain_data(sql_stmt_t *statement,
                                       sql_cursor_t *cursor, char *row_buf, char *info, bool32 *is_full,
                                       text_t *plan_text)
{
    if (plan_text != NULL) {
        return expl_send_explain_text(plan_text, info);
    } else {
        return expl_send_explain_row(statement, cursor, row_buf, info, is_full);
    }
}

static uint32 expl_get_explain_width(expl_helper_t *helper)
{
    uint32 width = 1;
    uint32 i = 0;
    while (i < EXPL_COL_TYPE_MAX) {
        if (OG_BIT_TEST(helper->display_option, OG_GET_MASK(i))) {
            width += helper->fmt_sizes[i] + EXPL_FMT_ALIGN_SIZE;
            i++;
        }
    }

    if (width > OG_MAX_ROW_SIZE - 1) {
        width = OG_MAX_ROW_SIZE - 1;
    }
    helper->width = width;

    return width;
}

static status_t expl_send_explain_divider(sql_stmt_t *statement, sql_cursor_t *cursor, uint32 width, bool32 *is_full,
                                          text_t *plan_text)
{
    char *row_buf = NULL;
    char *divider = NULL;

    OGSQL_SAVE_STACK(statement);
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&row_buf));
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&divider));

    MEMS_RETURN_IFERR(memset_s(divider, OG_MAX_ROW_SIZE, '-', width));
    divider[width] = '\0';

    OG_RETURN_IFERR(expl_send_explain_data(statement, cursor, row_buf, divider, is_full, plan_text));
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

static status_t expl_send_explain_head(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper)
{
    char *info = NULL;
    bool32 is_full = OG_FALSE;
    text_t *col_name = NULL;

    OGSQL_SAVE_STACK(statement);
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&info));
    uint32 width = expl_get_explain_width(helper);
    // send divider
    OG_RETURN_IFERR(expl_send_explain_divider(statement, cursor, width, &is_full, helper->plan_output));

    // send column info
    uint32 offset = 0;
    MEMS_RETURN_IFERR(memset_s(info, OG_MAX_ROW_SIZE, ' ', width - 1));
    info[offset++] = '|';
    for (int32 i = 0; i < EXPL_COL_TYPE_MAX; i++) {
        if (!OG_BIT_TEST(helper->display_option, OG_GET_MASK(i))) {
            continue;
        }
        offset++;
        if (offset + helper->fmt_sizes[i] >= OG_MAX_ROW_SIZE - 1) {
            break;
        }
        col_name = expl_get_explcol_name(i);
        MEMS_RETURN_IFERR(memcpy_s(&info[offset], OG_MAX_ROW_SIZE - offset, col_name->str, col_name->len));
        offset += helper->fmt_sizes[i] + 1;
        info[offset++] = '|';
    }
    info[offset] = '\0';
    OG_RETURN_IFERR(expl_send_explain_data(statement, cursor, helper->row_buf, info, &is_full, helper->plan_output));

    // send divider
    OG_RETURN_IFERR(expl_send_explain_divider(statement, cursor, width, &is_full, helper->plan_output));
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

static status_t expl_send_explain_tail(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper)
{
    bool32 is_full = OG_FALSE;

    OGSQL_SAVE_STACK(statement);
    // send divider
    OG_RETURN_IFERR(expl_send_explain_divider(statement, cursor, helper->width, &is_full, helper->plan_output));
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

#define VM_LIST_MIN_VALID_COUNT 2

static bool32 check_rs_page_in_segment(mtrl_context_t *mtrl, mtrl_segment_t *segment, uint32 vmid)
{
    if (segment->vm_list.count <= VM_LIST_MIN_VALID_COUNT) {
        return (vmid == segment->vm_list.first || vmid == segment->vm_list.last);
    }

    vm_ctrl_t *ctrl = NULL;
    uint32 cur_id = segment->vm_list.first;
    uint32 i = 2;
    while (i < segment->vm_list.count) {
        ctrl = vm_get_ctrl(mtrl->pool, cur_id);
        if (ctrl->next == vmid) {
            return OG_TRUE;
        }
        cur_id = ctrl->next;
        i++;
    }
    return OG_FALSE;
}

static status_t expl_fmt_column_content(mtrl_row_t *row, char *content, uint32 offset, uint16 fmt_size, uint32 col_id)
{
    uint16 col_len = row->lens[col_id];
    char *col_data = row->data + row->offsets[col_id];

    content[offset] = '|';
    if (col_len == OG_NULL_VALUE_LEN || col_len == 0) {
        return OG_SUCCESS;
    }
    col_len = (col_len > fmt_size) ? fmt_size : col_len;

    MEMS_RETURN_IFERR(memcpy_s(content + offset + EXPL_FMT_COL_OFFSET, fmt_size, col_data, col_len));
    return OG_SUCCESS;
}

#define EXPL_ROW_RESERVED_TAIL_SPACE 2

static status_t expl_fmt_plan_content(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper, char *content)
{
    uint32 offset = 0;
    uint32 *fmt_sizes = helper->fmt_sizes;
    mtrl_row_t *row = &cursor->mtrl.cursor.row;

    MEMS_RETURN_IFERR(memset_s(content, OG_MAX_ROW_SIZE, ' ', OG_MAX_ROW_SIZE));
    for (uint32 i = 0; i < EXPL_COL_TYPE_MAX; i++) {
        if (!OG_BIT_TEST(helper->display_option, OG_GET_MASK(i))) {
            continue;
        }
        if (offset + fmt_sizes[i] + EXPL_FMT_ALIGN_SIZE > OG_MAX_ROW_SIZE - EXPL_ROW_RESERVED_TAIL_SPACE) {
            break;
        }

        if (expl_fmt_column_content(row, content, offset, (uint16)fmt_sizes[i], i) != OG_SUCCESS) {
            break;
        }
        offset += fmt_sizes[i] + EXPL_FMT_ALIGN_SIZE;
    }
    content[offset] = '|';
    content[offset + 1] = '\0';

    return OG_SUCCESS;
}

static status_t expl_fmt_explain_content(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper,
                                  expl_fmt_func_t fmt_func)
{
    char *row_buf = NULL;
    char *content = NULL;
    bool32 is_full = OG_FALSE;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;

    OGSQL_SAVE_STACK(statement);
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&row_buf));
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&content));

    while (OG_TRUE) {
        OG_RETURN_IFERR(mtrl_fetch_rs(&statement->mtrl, mtrl_cursor, OG_TRUE));
        if (mtrl_cursor->eof) {
            break;
        }

        OG_RETURN_IFERR(fmt_func(statement, cursor, helper, content));
        OG_RETURN_IFERR(expl_send_explain_data(statement, cursor, row_buf, content, &is_full, helper->plan_output));
        if (is_full) {
            break;
        }
    }
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

static status_t expl_send_plan_info(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper)
{
    // header
    if (helper->first_fetch) {
        OG_RETURN_IFERR(mtrl_open_rs_cursor(&statement->mtrl, cursor->mtrl.rs.sid, &cursor->mtrl.cursor));
        OG_RETURN_IFERR(expl_send_explain_head(statement, cursor, helper));
    }

    if (!check_rs_page_in_segment(&statement->mtrl, statement->mtrl.segments[cursor->mtrl.rs.sid],
        cursor->mtrl.cursor.rs_vmid)) {
        return OG_SUCCESS;
    }
    // content
    OG_RETURN_IFERR(expl_fmt_explain_content(statement, cursor, helper, expl_fmt_plan_content));
    if (!cursor->mtrl.cursor.eof) {
        return OG_SUCCESS;
    }
    // tail
    OG_RETURN_IFERR(expl_send_explain_tail(statement, cursor, helper));
    return OG_SUCCESS;
}

static status_t expl_send_predicate_head(sql_stmt_t *statement, sql_cursor_t *cursor, pred_helper_t *helper)
{
    char *info = NULL;
    bool32 is_full = OG_FALSE;
    int32 width = strlen(EXPLAIN_PREDICATE_HEAD);

    OGSQL_SAVE_STACK(statement);
    // predicate header
    OG_RETURN_IFERR(sql_push(statement, width + 1, (void **)&info));
    MEMS_RETURN_IFERR(memcpy_s(info, width + 1, EXPLAIN_PREDICATE_HEAD, width));
    info[width] = '\0';
    OG_RETURN_IFERR(expl_send_explain_data(statement, cursor, helper->row_buf, info,
        &is_full, helper->parent->plan_output));

    // send divider
    OG_RETURN_IFERR(expl_send_explain_divider(statement, cursor, width, &is_full, helper->parent->plan_output));
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

static status_t expl_fmt_predicate_content(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper,
    char *content)
{
    mtrl_row_t *row = &cursor->mtrl.cursor.row;
    char *data = row->data + row->offsets[0];
    uint32 len = row->lens[0];

    MEMS_RETURN_IFERR(memcpy_s(content, OG_MAX_ROW_SIZE, data, len));
    content[len] = '\0';

    return OG_SUCCESS;
}

static bool32 if_should_skip_predicate_info(sql_stmt_t *statement, sql_cursor_t *cursor, const pred_helper_t *helper)
{
    if (!helper->is_enabled) {
        return OG_TRUE;
    }

    // segment of other expl helper
    if (!cursor->mtrl.cursor.eof &&
        !check_rs_page_in_segment(&statement->mtrl,
                                  statement->mtrl.segments[cursor->mtrl.predicate.sid],
                                  cursor->mtrl.cursor.rs_vmid)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t expl_send_predicate_info(sql_stmt_t *statement, sql_cursor_t *cursor, pred_helper_t *helper)
{
    if (if_should_skip_predicate_info(statement, cursor, helper)) {
        return OG_SUCCESS;
    }

    if (cursor->mtrl.cursor.eof) {
        OG_RETURN_IFERR(mtrl_open_rs_cursor(&statement->mtrl, cursor->mtrl.predicate.sid, &cursor->mtrl.cursor));
        if (cursor->mtrl.cursor.rs_page->rows != 0) {
            OG_RETURN_IFERR(expl_send_predicate_head(statement, cursor, helper));
        }
    }

    return expl_fmt_explain_content(statement, cursor, helper->parent, expl_fmt_predicate_content);
}

status_t expl_init_executors(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper,
    text_t * explain_text)
{
    OG_RETURN_IFERR(expl_helper_init(statement, helper, cursor->mtrl.rs.sid, explain_text));
    OG_RETURN_IFERR(expl_pred_helper_init(statement, &helper->pred_helper, cursor->mtrl.predicate.sid));
    helper->pred_helper.parent = helper;

    return OG_SUCCESS;
}

void expl_release_executors(expl_helper_t *helper)
{
    expl_pred_helper_release(&helper->pred_helper);
}

status_t expl_execute_executors(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan)
{
    return expl_format_plan_node(statement, helper, plan, 0);
}

status_t expl_send_explain_rows(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper)
{
    OG_RETURN_IFERR(expl_send_plan_info(statement, cursor, helper));
    OG_RETURN_IFERR(expl_send_predicate_info(statement, cursor, &helper->pred_helper));
    // how client<->server
    if (statement->batch_rows < statement->prefetch_rows) {
        statement->eof = OG_TRUE;
        cursor->eof = OG_TRUE;
    }
    return OG_SUCCESS;
}

// record max-formatted-size for next fetch
status_t expl_record_fmt_sizes(sql_cursor_t *cursor, expl_helper_t *helper)
{
    if (cursor->exec_data.expl_col_max_size == NULL) {
        OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, EXPL_COL_TYPE_MAX * sizeof(uint32),
            (void **)&cursor->exec_data.expl_col_max_size));
    }

    uint32 i = 0;
    while (i < EXPL_COL_TYPE_MAX) {
        cursor->exec_data.expl_col_max_size[i] = helper->fmt_sizes[i];
        i++;
    }

    return OG_SUCCESS;
}

// restore max-formatted-size for current fetch
static status_t expl_restore_fmt_sizes(sql_cursor_t *cursor, expl_helper_t *helper)
{
    if (cursor->exec_data.expl_col_max_size == NULL) {
        return OG_SUCCESS;
    }

    uint32 i = 0;
    while (i < EXPL_COL_TYPE_MAX) {
        helper->fmt_sizes[i] = cursor->exec_data.expl_col_max_size[i];
        i++;
    }

    return OG_SUCCESS;
}

static status_t expl_execute_explain_plan(sql_stmt_t *statement, sql_cursor_t *cursor,
    plan_node_t *plan, text_t *plan_text)
{
    status_t ret;
    expl_helper_t helper = {0};

    OGSQL_SAVE_STACK(statement);
    // explain-executors init
    OG_RETURN_IFERR(expl_init_executors(statement, cursor, &helper, plan_text));

    // explain-executors execute
    ret = expl_execute_executors(statement, &helper, plan);
    if (ret != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    expl_close_segment(statement, cursor);

    // record max-formatted-size for next fetch
    ret = expl_record_fmt_sizes(cursor, &helper);
    if (ret != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    // get explain result and write to response package
    ret = expl_send_explain_rows(statement, cursor, &helper);
    expl_release_executors(&helper);
    OGSQL_RESTORE_STACK(statement);

    return ret;
}

status_t expl_send_fetch_result(sql_stmt_t *statement, sql_cursor_t *cursor, text_t *plan_text)
{
    status_t ret;
    expl_helper_t helper = {0};

    OGSQL_SAVE_STACK(statement);
    // explain-executors init
    OG_RETURN_IFERR(expl_init_executors(statement, cursor, &helper, plan_text));
    ret = expl_restore_fmt_sizes(cursor, &helper);
    if (ret != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    // restore max-formatted-size for current fetch
    ret = expl_restore_fmt_sizes(cursor, &helper);
    if (ret != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    helper.first_fetch = OG_FALSE;
    ret = expl_send_explain_rows(statement, cursor, &helper);
    expl_release_executors(&helper);
    OGSQL_RESTORE_STACK(statement);

    return ret;
}

static status_t expl_fill_params(sql_stmt_t *statement)
{
    if (statement->is_sub_stmt) {
        return OG_SUCCESS;
    }

    if (CS_HAS_MORE(statement->session->recv_pack)) {
        OG_RETURN_IFERR(sql_read_params(statement));
    } else {
        OG_RETURN_IFERR(sql_fill_null_params(statement));
    }
    return OG_SUCCESS;
}

status_t expl_execute(sql_stmt_t *statement)
{
    if (is_explain_create_type(statement)) {
        return og_explain_create_plan(statement, NULL);
    }

    plan_node_t *node = (plan_node_t *)sql_get_plan(statement);
    OG_RETVALUE_IFTRUE(node == NULL, OG_ERRNO);

    if (!statement->is_sub_stmt && CS_HAS_MORE(statement->session->recv_pack)) {
        OG_RETURN_IFERR(sql_prepare_params(statement));
    }
    
    sql_cursor_t *cursor = NULL;
    OG_RETURN_IFERR(expl_pre_execute(statement, &cursor));
    OGSQL_SAVE_STACK(statement);
    uint32 i = 0;
    while (i < statement->param_info.paramset_size) {
        if (expl_fill_params(statement) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }

        if (i != statement->param_info.paramset_size - 1) {
            OGSQL_RESTORE_STACK(statement);
            i++;
            continue;
        }
        node = (plan_node_t *)sql_get_plan(statement);
        sql_init_ssa_cursor_maps(cursor, OG_MAX_SUBSELECT_EXPRS);
        if (expl_execute_explain_plan(statement, cursor, node, NULL) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }
        OGSQL_RESTORE_STACK(statement);
        i++;
    }
    
    return OG_SUCCESS;
}

static status_t expl_retrieve_plan_text(sql_stmt_t *statement, text_t *plan_output)
{
    plan_node_t *exec_plan = (plan_node_t *)sql_get_plan(statement);
    if (exec_plan == NULL) {
        return OG_ERROR;
    }

    sql_cursor_t *explain_cursor = NULL;
    OG_RETURN_IFERR(expl_pre_execute(statement, &explain_cursor));
    
    OGSQL_SAVE_STACK(statement);
    if (expl_execute_explain_plan(statement, explain_cursor, exec_plan, plan_output) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(statement);

    SQL_CURSOR_POP(statement);
    sql_free_cursor(statement, explain_cursor);

    return OG_SUCCESS;
}

status_t expl_get_explain_text(sql_stmt_t *statement, text_t *plan_output)
{
    status_t ret;

    OGSQL_SAVE_STACK(statement);
    ret = expl_retrieve_plan_text(statement, plan_output);
    OGSQL_RESTORE_STACK(statement);

    return ret;
}
