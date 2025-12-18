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
 * ogsql_hint_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_hint_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_hint_parser.h"
#include "gramparse.h"

extern yyscan_t hint_scanner_init(const char* str, hint_yy_extra_type* yyext, sql_stmt_t *stmt);
extern void hint_scanner_destroy(yyscan_t yyscanner);
void yyset_lineno(int line_number, yyscan_t yyscanner);

status_t og_alloc_hint(sql_stmt_t *statement, hint_info_t **hint_info)
{
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(hint_info_t), (void **)hint_info));
    MEMS_RETURN_IFERR(memset_s(*hint_info, sizeof(hint_info_t), 0, sizeof(hint_info_t)));
    return OG_SUCCESS;
}

static status_t og_parse_opt_param_comment(sql_stmt_t *statement, hint_info_t **hint_info)
{
    galist_t *hint_lst = (*hint_info)->items;
    hint_item_t *hint = NULL;
    uint32 i = hint_lst->count;
    while (i > 0) {
        hint = (hint_item_t *)cm_galist_get(hint_lst, i - 1);
        i--;

        if (statement->context->hint_info == NULL) {
            OG_RETURN_IFERR(og_alloc_hint(statement, &statement->context->hint_info));
            OG_RETURN_IFERR(sql_create_list(statement, &statement->context->hint_info->items));
            statement->context->hint_info->info = (*hint_info)->info;
        }

        OG_RETURN_IFERR(cm_galist_insert(statement->context->hint_info->items, hint));
        cm_galist_delete((*hint_info)->items, i);
    }

    if (hint_lst->count == 0) {
        *hint_info = NULL;
    }
    return OG_SUCCESS;
}

static status_t bison_parse_hint(sql_stmt_t *stmt, const char* hint_str, hint_info_t **hint_info)
{
    yyscan_t yyscanner;
    hint_yy_extra_type yyextra;

    /* initialize the flex scanner */
    yyscanner = hint_scanner_init(hint_str, &yyextra, stmt);

    yyset_lineno(1, yyscanner);

    /* we will go on whether yyparse is successful or not. */
    (void)yyparse(yyscanner);

    hint_scanner_destroy(yyscanner);

    if (yyextra.hint_lst != NULL) {
        if (*hint_info == NULL) {
            OG_RETURN_IFERR(og_alloc_hint(stmt, hint_info));
        }
        (*hint_info)->info.str = strdup(hint_str);
        (*hint_info)->info.len = strlen(hint_str);
        (*hint_info)->items = yyextra.hint_lst;
    }

    return OG_SUCCESS;
}

static char* get_hints_from_comment(sql_stmt_t *stmt, const char* comment_str)
{
    char* head = NULL;
    int len;
    int comment_len = strlen(comment_str);
    int hint_start_len = strlen(HINT_START);
    int start_position = 0;
    int end_position = 0;

    /* extract query head comment, hint string start with "\*+" */
    if (strncmp(comment_str, HINT_START, hint_start_len) != 0) {
        return NULL;
    }

    /* Find first is not space character. */
    for (start_position = hint_start_len; start_position < comment_len; start_position++) {
        if (comment_str[start_position] == '\n' || !isspace(comment_str[start_position])) {
            break;
        }
    }

    /* Find comment termination position. */
    for (end_position = comment_len - 1; end_position >= 0; end_position--) {
        if (comment_str[end_position] == '*') {
            break;
        }
    }

    /* Make a copy of hint. */
    len = end_position - start_position;

    if (len <= 0) {
        return NULL;
    }

    sql_alloc_mem(stmt->context, sizeof(char*) * (len + 1), (void**)&head);
    errno_t ret = memcpy_s(head, len, comment_str + start_position, len);
    knl_securec_check(ret);
    head[len] = '\0';

    return head;
}

void og_get_hint_info(sql_stmt_t *stmt, const char* hints, hint_info_t **hint_info)
{
    if (hints == NULL) {
        return;
    }

    char* hint_str = NULL;

    hint_str = get_hints_from_comment(stmt, hints);
    if (hint_str == NULL) {
        return;
    }

    bison_parse_hint(stmt, hint_str, hint_info);

    if (*hint_info != NULL) {
        og_parse_opt_param_comment(stmt, hint_info);
    }
}
