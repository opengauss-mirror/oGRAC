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
 * dml_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/dml_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_parser.h"
#include "cm_hash.h"
#include "ogsql_context.h"
#include "srv_instance.h"
#include "ogsql_parser.h"
#include "ogsql_transform.h"
#include "ogsql_plan.h"
#include "pl_common.h"
#include "pl_executor.h"
#include "pl_context.h"
#include "ogsql_dependency.h"
#include "plan_rbo.h"
#include "ogsql_serial.h"
#include "pl_compiler.h"
#include "ogsql_privilege.h"
#include "ogsql_json_table.h"
#include "pl_anonymous.h"
#include "pl_memory.h"
#include "base_compiler.h"
#include "ogsql_select_parser.h"
#include "ogsql_insert_parser.h"
#include "ogsql_update_parser.h"
#include "ogsql_delete_parser.h"
#include "ogsql_replace_parser.h"
#include "ogsql_merge_parser.h"
#include "ogsql_cache.h"
#include "gramparse.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_create_list(sql_stmt_t *stmt, galist_t **list)
{
    if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)list) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_galist_init((*list), stmt->context, sql_alloc_mem);
    return OG_SUCCESS;
}

static inline void get_next_token_without_yy(int *lookahead_len, struct base_yy_lookahead *lookaheads, int *next_token,
    int *next_yyleng, YYSTYPE *lvalp, YYLTYPE *llocp, yyscan_t yyscanner, char *scanbuf)
{
    if (*lookahead_len) {
        struct base_yy_lookahead lookahead = lookaheads[(*lookahead_len) - 1];
        *next_token = lookahead.token;
        *next_yyleng = lookahead.yyleng;
        lvalp->core_yystype = lookahead.yylval;
        *llocp = lookahead.yylloc;
        scanbuf[lookahead.prev_hold_char_loc] = lookahead.prev_hold_char;
        scanbuf[lookahead.yylloc.offset + lookahead.yyleng] = '\0';
        (*lookahead_len)--;
    } else {
        *next_token = core_yylex(&(lvalp->core_yystype), llocp, yyscanner);
        *next_yyleng = ct_yyget_leng(yyscanner);
    }
}

static inline void get_next_token(int *lookahead_len, struct base_yy_lookahead *lookaheads, int *next_token,
    int *next_yyleng, YYSTYPE *lvalp, YYLTYPE *llocp, yyscan_t yyscanner, char *scanbuf, core_YYSTYPE *cur_yylval,
    YYLTYPE *cur_yylloc)
{
    *cur_yylval = lvalp->core_yystype;
    *cur_yylloc = *llocp;
    get_next_token_without_yy(lookahead_len, lookaheads, next_token, next_yyleng, lvalp, llocp, yyscanner, scanbuf);
}

static inline void set_lookahead_token(int *lookahead_len, struct base_yy_lookahead *lookaheads, int *next_token,
    YYSTYPE *lvalp, YYLTYPE *llocp, int *next_yyleng, YYLTYPE *cur_yylloc, char *scanbuf, int cur_yyleng)
{
    *lookahead_len = 1;
    struct base_yy_lookahead* lookahead = &lookaheads[0];
    lookahead->token = *next_token;
    lookahead->yylval = lvalp->core_yystype;
    lookahead->yylloc = *llocp;
    lookahead->yyleng = *next_yyleng;
    lookahead->prev_hold_char_loc = cur_yylloc->offset + cur_yyleng;
    lookahead->prev_hold_char = scanbuf[cur_yylloc->offset + cur_yyleng];
}

int base_yylex(YYSTYPE* lvalp, YYLTYPE* llocp, core_yyscan_t yyscanner)
{
    base_yy_extra_type* yyextra = og_yyget_extra(yyscanner);
    char* scanbuf = yyextra->core_yy_extra.scanbuf;
    struct base_yy_lookahead* lookaheads = yyextra->lookaheads;
    int* lookahead_len = &yyextra->lookahead_len;
    int cur_token;
    int cur_yyleng = 0;
    int next_token;
    int next_yyleng = 0;
    core_YYSTYPE cur_yylval;
    YYLTYPE cur_yylloc = {{0, 0}, 0};

    /* Get next token --- we might already have it */
    if (yyextra->lookahead_len != 0) {
        const struct base_yy_lookahead lookahead = lookaheads[yyextra->lookahead_len - 1];
        cur_token = lookahead.token;
        lvalp->core_yystype = lookahead.yylval;
        *llocp = lookahead.yylloc;
        scanbuf[lookahead.prev_hold_char_loc] = lookahead.prev_hold_char;
        scanbuf[lookahead.yylloc.offset + lookahead.yyleng] = '\0';
        yyextra->lookahead_len--;
    } else {
        cur_token = core_yylex(&(lvalp->core_yystype), llocp, yyscanner);
    }

    /* Do we need to look ahead for a possible multiword token? */
    switch (cur_token) {
        case NULLS_P:
            /*
             * NULLS FIRST and NULLS LAST must be reduced to one token
             */
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case FIRST_P:
                    cur_token = NULLS_FIRST;
                    break;
                case LAST_P:
                    cur_token = NULLS_LAST;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case WITH:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case TIME:
                    cur_token = WITH_TIME;
                    break;
                case LOCAL:
                    cur_token = WITH_LOCAL;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case WITHOUT:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case TIME:
                    cur_token = WITHOUT_TIME;
                    break;
                case LOCAL:
                    cur_token = WITHOUT_LOCAL;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case PIVOT:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case '(':
                    cur_token = PIVOT_TOK;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case UNPIVOT:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case '(':
                    cur_token = UNPIVOT_TOK;
                    break;
                case INCLUDE:
                    cur_token = UNPIVOT_INC;
                    break;
                case EXCLUDE:
                    cur_token = UNPIVOT_EXC;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case CONNECT:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case BY:
                    cur_token = CONNECT_BY;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case START:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case WITH:
                    cur_token = START_WITH;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case PARTITION:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case FOR:
                    cur_token = PARTITION_FOR;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case SUBPARTITION:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case FOR:
                    cur_token = SUBPARTITION_FOR;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        case ORDER:
            get_next_token(lookahead_len, lookaheads, &next_token, &next_yyleng, lvalp, llocp, yyscanner, scanbuf,
                &cur_yylval, &cur_yylloc);
            switch (next_token) {
                case SIBLINGS:
                    cur_token = ORDER_SIBLINGS;
                    break;
                default:
                    /* save the lookahead token for next time */
                    set_lookahead_token(lookahead_len, lookaheads, &next_token, lvalp, llocp, &next_yyleng,
                        &cur_yylloc, scanbuf, cur_yyleng);
                    /* and back up the output info to cur_token */
                    lvalp->core_yystype = cur_yylval;
                    *llocp = cur_yylloc;
                    scanbuf[cur_yylloc.offset + cur_yyleng] = '\0';
                    break;
            }
            break;
        default:
            break;
    }
    return cur_token;
}

status_t raw_parser(sql_stmt_t *stmt, sql_text_t *sql, void **context)
{
    core_yyscan_t yyscanner;
    base_yy_extra_type yyextra;
    int yyresult;

    CM_SAVE_STACK(stmt->session->stack);

    /* initialize the flex scanner */
    yyscanner = scanner_init(sql, &yyextra.core_yy_extra, &ScanKeywords, ScanKeywordTokens, stmt);
    if (SECUREC_UNLIKELY(yyscanner == NULL)) {
        return OG_ERROR;
    }

    yyextra.lookahead_len = 0;

    /* initialize the bison parser */
    parser_init(&yyextra);

    /* Parse! */
    yyresult = base_yyparse(yyscanner);

    /* Clean up (release memory) */
    scanner_finish(yyscanner);

    if (SECUREC_UNLIKELY(yyresult)) { /* error */
        return OG_ERROR;
    }

    CM_RESTORE_STACK(stmt->session->stack);

    *context = yyextra.parsetree;
    return OG_SUCCESS;
}

static status_t sql_create_dml_context(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t key_wid)
{
    sql_context_t *ogx = stmt->context;

    // write dml sql into context
    OG_RETURN_IFERR(ogx_write_text(&ogx->ctrl, (text_t *)sql));

    OG_RETURN_IFERR(sql_create_list(stmt, &ogx->params));
    OG_RETURN_IFERR(sql_create_list(stmt, &ogx->csr_params));
    OG_RETURN_IFERR(sql_create_list(stmt, &ogx->ref_objects));
    OG_RETURN_IFERR(sql_create_list(stmt, &ogx->outlines));

    stmt->session->lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    switch (key_wid) {
        case KEY_WORD_SELECT:
        case KEY_WORD_WITH:
            stmt->context->type = OGSQL_TYPE_SELECT;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_select_context(stmt, sql, SELECT_AS_RESULT, (sql_select_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        case KEY_WORD_UPDATE:
            stmt->context->type = OGSQL_TYPE_UPDATE;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_update_context(stmt, sql, (sql_update_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        case KEY_WORD_INSERT:
            stmt->context->type = OGSQL_TYPE_INSERT;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_insert_context(stmt, sql, (sql_insert_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        case KEY_WORD_DELETE:
            stmt->context->type = OGSQL_TYPE_DELETE;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_delete_context(stmt, sql, (sql_delete_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        case KEY_WORD_MERGE:
            stmt->context->type = OGSQL_TYPE_MERGE;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_merge_context(stmt, sql, (sql_merge_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        case KEY_WORD_REPLACE:
            stmt->context->type = OGSQL_TYPE_REPLACE;
            if (!g_instance->sql.use_bison_parser) {
                return sql_create_replace_context(stmt, sql, (sql_replace_t **)&ogx->entry);
            } else {
                return raw_parser(stmt, sql, &ogx->entry);
            }

        default:
            OG_SRC_THROW_ERROR(sql->loc, ERR_SQL_SYNTAX_ERROR, "missing keyword");
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_create_dml(sql_stmt_t *stmt, sql_text_t *sql, key_wid_t key_wid)
{
    OG_RETURN_IFERR(sql_create_dml_context(stmt, sql, key_wid));
    OG_RETURN_IFERR(sql_verify(stmt));
    check_table_stats(stmt);
    OG_RETURN_IFERR(ogsql_optimize_logically(stmt));
    return sql_create_dml_plan(stmt);
}

status_t sql_create_dml_currently(sql_stmt_t *stmt, sql_text_t *sql_text, key_wid_t key_wid)
{
    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = sql_text->value;
    stmt->session->sql_id = stmt->context->ctrl.hash_value;
    cm_spin_unlock(&stmt->session->sess_lock);

    status_t ret = sql_create_dml(stmt, sql_text, key_wid);

    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->current_sql = CM_NULL_TEXT;
    stmt->session->sql_id = 0;
    cm_spin_unlock(&stmt->session->sess_lock);
    return ret;
}

bool32 sql_has_ltt(sql_stmt_t *stmt, text_t *sql_text)
{
    // simple scan sql_text to find name starts with `#`
    bool32 quote = OG_FALSE;
    for (uint32 i = 0; i < sql_text->len; i++) {
        if (sql_text->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        if (knl_is_llt_by_name2(sql_text->str[i]) && i > 0) {
            char c = sql_text->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                return OG_TRUE;
            }
        }
    }
    return OG_FALSE;
}

uint32 sql_has_special_word(sql_stmt_t *stmt, text_t *sql_text)
{
    // simple scan sql to find name starts with `#`
    bool32 quote = OG_FALSE;
    uint32 result = SQL_HAS_NONE;
    for (uint32 i = 0; i < sql_text->len; i++) {
        if (sql_text->str[i] == '\'') {
            quote = !quote;
        }

        if (quote) {
            continue;
        }

        // dblink
        if (sql_text->str[i] == '@') {
            result |= SQL_HAS_DBLINK;
        }

        // local temporary table
        if (knl_is_llt_by_name2(sql_text->str[i]) && i > 0) {
            char c = sql_text->str[i - 1];
            if (c == '`' || c == '"' || is_splitter(c)) {
                result |= SQL_HAS_LTT;
            }
        }
    }
    return result;
}

/* check ref function/procedures is valid or not */
bool32 sql_check_procedures(sql_stmt_t *stmt, galist_t *dc_lst)
{
    pl_dc_t *pl_dc = NULL;

    if (dc_lst != NULL) {
        for (uint32 i = 0; i < dc_lst->count; i++) {
            pl_dc = (pl_dc_t *)cm_galist_get(dc_lst, i);
            if (!pl_check_dc(pl_dc)) {
                return OG_FALSE;
            }
        }
    }

    return OG_TRUE;
}

static inline void sql_init_plan_count(sql_stmt_t *stmt)
{
    stmt->context->clause_info.union_all_count = 0;
}

void sql_parse_set_context_procinfo(sql_stmt_t *stmt)
{
    CM_POINTER2(stmt, stmt->context);
    /* for the ANONYMOUS BLOCK or CALL statement, there is no procedure oid */
    if ((stmt->pl_compiler != NULL) && ((pl_compiler_t *)stmt->pl_compiler)->proc_oid != 0) {
        stmt->context->stat.proc_oid = ((pl_compiler_t *)stmt->pl_compiler)->proc_oid;
        stmt->context->stat.proc_line = ((pl_compiler_t *)stmt->pl_compiler)->line_loc.line;
    }
}

status_t sql_parse_dml_directly(sql_stmt_t *stmt, key_wid_t key_wid, sql_text_t *sql_text)
{
    OG_RETURN_IFERR(sql_alloc_context(stmt));

    sql_context_uncacheable(stmt->context);
    ((context_ctrl_t *)stmt->context)->uid = stmt->session->knl_session.uid;
    sql_init_plan_count(stmt);

    timeval_t timeval_begin;
    (void)cm_gettimeofday(&timeval_begin);

    OG_RETURN_IFERR(sql_create_dml_currently(stmt, sql_text, key_wid));

    og_update_context_stat_uncached(stmt, &timeval_begin);
    return OG_SUCCESS;
}

void sql_prepare_context_ctrl(sql_stmt_t *stmt, uint32 hash_value, context_bucket_t *bucket)
{
    stmt->context->ctrl.uid = stmt->session->curr_schema_id;
    stmt->context->ctrl.hash_value = hash_value;
    stmt->context->ctrl.bucket = bucket;
    sql_init_plan_count(stmt);
}

static void sql_prepare_plc_desc(sql_stmt_t *stmt, uint32 type, plc_desc_t *desc)
{
    desc->proc_oid = 0;
    desc->type = type;
    desc->obj = NULL;
    desc->source_pages.curr_page_id = OG_INVALID_ID32;
    desc->source_pages.curr_page_pos = 0;
    desc->entity = (pl_entity_t *)stmt->pl_context;
}

static status_t sql_parse_anonymous_prepare(sql_stmt_t *stmt)
{
    pl_entity_t *pl_entity = NULL;

    if (sql_alloc_context(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }
    sql_context_uncacheable(stmt->context);
    stmt->context->type = OGSQL_TYPE_ANONYMOUS_BLOCK;
    if (sql_create_list(stmt, &stmt->context->params) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (pl_alloc_context(&pl_entity, stmt->context) != OG_SUCCESS) {
        return OG_ERROR;
    }
    SET_STMT_PL_CONTEXT(stmt, pl_entity);

    if (pl_alloc_mem((void *)pl_entity, sizeof(anonymous_t), (void **)&pl_entity->anonymous) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_anonymous_directly(sql_stmt_t *stmt, word_t *leader, sql_text_t *sql_text)
{
    timeval_t timeval_begin;
    timeval_t timeval_end;
    plc_desc_t desc;
    status_t status = OG_ERROR;

    do {
        OG_BREAK_IF_ERROR(sql_parse_anonymous_prepare(stmt));
        pl_entity_uncacheable(stmt->pl_context);
        sql_init_plan_count(stmt);
        (void)cm_gettimeofday(&timeval_begin);
        sql_prepare_plc_desc(stmt, PL_ANONYMOUS_BLOCK, &desc);
        OG_BREAK_IF_ERROR(pl_write_anony_desc(stmt, &sql_text->value, 0));
        OG_BREAK_IF_ERROR(plc_compile(stmt, &desc, leader));
        pl_set_entity_valid((pl_entity_t *)stmt->pl_context, OG_TRUE);
        status = OG_SUCCESS;
    } while (OG_FALSE);
    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }
    sql_init_context_stat(&stmt->context->stat);
    stmt->context->stat.parse_calls = 1;
    stmt->session->stat.hard_parses++;
    stmt->context->stat.last_load_time = g_timer()->now;
    (void)cm_gettimeofday(&timeval_end);
    stmt->context->stat.parse_time = (uint64)TIMEVAL_DIFF_US(&timeval_begin, &timeval_end);
    stmt->context->stat.last_active_time = stmt->context->stat.last_load_time;
    stmt->context->module_kind = SESSION_CLIENT_KIND(stmt->session);
    stmt->context->ctrl.ref_count = 0;
    if (stmt->context->ctrl.memory != NULL) {
        cm_atomic_add(&g_instance->library_cache_info[stmt->lang_type].pins,
                      (int64)stmt->context->ctrl.memory->pages.count);
        cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].reloads);
    }
    return OG_SUCCESS;
}

status_t sql_parse_dml(sql_stmt_t *stmt, key_wid_t key_wid)
{
    OG_LOG_DEBUG_INF("Begin parse DML, SQL = %s", T2S(&stmt->session->lex->text.value));
    cm_atomic_inc(&g_instance->library_cache_info[stmt->lang_type].hits);
    // maybe need load entity from proc$
    knl_set_session_scn(&stmt->session->knl_session, OG_INVALID_ID64);

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
    uint32 special_word = sql_has_special_word(stmt, &stmt->session->lex->text.value);
    if (SQL_HAS_NONE != special_word || stmt->session->disable_soft_parse || g_instance->sql.use_bison_parser) {
        OG_RETURN_IFERR(sql_parse_dml_directly(stmt, key_wid, &stmt->session->lex->text));
    } else {
        OG_RETURN_IFERR(og_find_then_parse_dml(stmt, key_wid, special_word));
    }
    stmt->context->has_ltt = (special_word & SQL_HAS_LTT);

    return OG_SUCCESS;
}

status_t sql_create_rowid_rs_column(sql_stmt_t *stmt, uint32 id, sql_table_type_t type, galist_t *list)
{
    rs_column_t *rs_column = NULL;

    OG_RETURN_IFERR(cm_galist_new(list, sizeof(rs_column_t), (pointer_t *)&rs_column));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&rs_column->expr));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&rs_column->expr->root));
    rs_column->expr->owner = stmt->context;
    rs_column->type = RS_COL_CALC;

    if (type != NORMAL_TABLE) {
        rs_column->expr->root->size = sizeof(uint32);
        rs_column->expr->root->type = EXPR_NODE_CONST;
        rs_column->expr->root->datatype = OG_TYPE_INTEGER;
        rs_column->expr->root->value.type = OG_TYPE_INTEGER;
        rs_column->expr->root->value.v_int = 0;
    } else {
        rs_column->expr->root->size = ROWID_LENGTH;
        rs_column->expr->root->type = EXPR_NODE_RESERVED;
        rs_column->expr->root->datatype = OG_TYPE_STRING;
        rs_column->expr->root->value.type = OG_TYPE_INTEGER;
        rs_column->expr->root->value.v_rid.res_id = RES_WORD_ROWID;
        rs_column->expr->root->value.v_rid.ancestor = 0;
    }
    rs_column->size = rs_column->expr->root->size;
    rs_column->datatype = rs_column->expr->root->datatype;
    rs_column->expr->root->value.v_rid.tab_id = id;
    return OG_SUCCESS;
}

bool32 sql_check_equal_join_cond(join_cond_t *join_cond)
{
    for (uint32 i = 0; i < join_cond->cmp_nodes.count; i++) {
        cmp_node_t *cmp_node = (cmp_node_t *)cm_galist_get(&join_cond->cmp_nodes, i);
        if (cmp_node->left->root->type == EXPR_NODE_COLUMN && cmp_node->right->root->type == EXPR_NODE_COLUMN &&
            cmp_node->type == CMP_TYPE_EQUAL) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

status_t sql_parse_view_subselect(sql_stmt_t *stmt, text_t *sql, sql_select_t **select_ctx, source_location_t *loc)
{
    sql_text_t sql_text;

    sql_text.value = *sql;
    sql_text.loc = *loc;

    if (sql_create_select_context(stmt, &sql_text, SELECT_AS_TABLE, select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * sql_set_schema
 *
 * set the stmt schema info
 */
status_t sql_set_schema(sql_stmt_t *stmt, text_t *set_schema, uint32 set_schema_id, char *save_schema,
                        uint32 save_schema_maxlen, uint32 *save_schema_id)
{
    uint32 len;

    if (set_schema == NULL || set_schema->len == 0) {
        return OG_ERROR;
    }

    len = (uint32)strlen(stmt->session->curr_schema);
    if (len != 0) {
        MEMS_RETURN_IFERR(strncpy_s(save_schema, save_schema_maxlen, stmt->session->curr_schema, len));
    }
    *save_schema_id = stmt->session->curr_schema_id;

    if (set_schema->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(stmt->session->curr_schema, OG_NAME_BUFFER_SIZE, set_schema->str, set_schema->len));
    }
    stmt->session->curr_schema[set_schema->len] = '\0';
    stmt->session->curr_schema_id = set_schema_id;

    return OG_SUCCESS;
}

static bool32 sql_get_view_object_addr(object_address_t *depended, knl_dictionary_t *view_dc, text_t *name)
{
    depended->uid = view_dc->uid;
    depended->oid = view_dc->oid;
    depended->tid = OBJ_TYPE_VIEW;
    depended->scn = view_dc->chg_scn;
    if (name->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(depended->name, OG_NAME_BUFFER_SIZE, name->str, name->len));
    }

    depended->name[name->len] = '\0';

    return OG_TRUE;
}

/* update the dependency info of this view in sys_dependency table */
static void sql_update_view_dependencies(sql_stmt_t *stmt, knl_dictionary_t *view_dc, galist_t *ref_list,
                                         object_address_t depender, bool32 *is_valid)
{
    bool32 is_successed = OG_FALSE;
    knl_session_t *session = KNL_SESSION(stmt);

    do {
        if (knl_delete_dependency(session, view_dc->uid, (int64)view_dc->oid, (uint32)OBJ_TYPE_VIEW) != OG_SUCCESS) {
            is_successed = OG_FALSE;
            break;
        }

        if (stmt->context == NULL) {
            is_successed = OG_TRUE;
            break;
        }

        if (sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&ref_list) != OG_SUCCESS) {
            is_successed = OG_FALSE;
            break;
        }

        cm_galist_init(ref_list, stmt->context, sql_alloc_mem);
        if (sql_append_references(ref_list, stmt->context) == OG_SUCCESS &&
            knl_insert_dependency_list(session, &depender, ref_list) == OG_SUCCESS) {
            is_successed = OG_TRUE;
        }
    } while (OG_FALSE);

    if (is_successed) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
        *is_valid = OG_FALSE;
    }
}

bool32 sql_compile_view_sql(sql_stmt_t *stmt, knl_dictionary_t *view_dc, text_t *owner)
{
    uint32 large_page_id = OG_INVALID_ID32;
    source_location_t loc = { 1, 1 };
    saved_schema_t schema;
    text_t sub_sql;
    status_t status;
    bool32 is_successed = OG_FALSE;
    knl_session_t *session = KNL_SESSION(stmt);

    if (knl_get_view_sub_sql(session, view_dc, &sub_sql, &large_page_id) != OG_SUCCESS) {
        return OG_FALSE;
    }

    do {
        status = sql_switch_schema_by_uid(stmt, view_dc->uid, &schema);
        OG_BREAK_IF_ERROR(status);
        if (sql_parse(stmt, &sub_sql, &loc) == OG_SUCCESS) {
            is_successed = OG_TRUE;
        }
        sql_restore_schema(stmt, &schema);
    } while (0);

    if (large_page_id != OG_INVALID_ID32) {
        mpool_free_page(session->kernel->attr.large_pool, large_page_id);
    }
    return is_successed;
}

/*
 * sql_compile_view
 *
 * This function is used to recompile a view.
 */
static bool32 sql_compile_view(sql_stmt_t *stmt, text_t *owner, text_t *name, knl_dictionary_t *view_dc,
                               bool32 update_dep)
{
    bool32 is_valid;
    object_address_t depender;
    galist_t *ref_list = NULL;
    lex_t *lex_bak = NULL;

    if (!sql_get_view_object_addr(&depender, view_dc, name)) {
        return OG_FALSE;
    }

    OGSQL_SAVE_PARSER(stmt);
    if (pl_save_lex(stmt, &lex_bak) != OG_SUCCESS) {
        SQL_RESTORE_PARSER(stmt);
        return OG_FALSE;
    }
    bool8 disable_soft_parse = stmt->session->disable_soft_parse;
    stmt->is_explain = OG_FALSE;
    SET_STMT_CONTEXT(stmt, NULL);
    SET_STMT_PL_CONTEXT(stmt, NULL);
    stmt->session->disable_soft_parse = OG_TRUE;
    is_valid = sql_compile_view_sql(stmt, view_dc, owner);

    if (update_dep) {
        sql_update_view_dependencies(stmt, view_dc, ref_list, depender, &is_valid);
    }

    sql_release_context(stmt);

    pl_restore_lex(stmt, lex_bak);
    SQL_RESTORE_PARSER(stmt);
    stmt->session->disable_soft_parse = disable_soft_parse;
    return is_valid;
}

static object_status_t sql_check_synonym_object_valid(sql_stmt_t *stmt, text_t *owner_name, text_t *table_name,
                                                      object_address_t *p_obj)
{
    object_status_t obj_status = OBJ_STATUS_VALID;
    knl_dictionary_t dc;
    errno_t errcode;

    if (dc_open(KNL_SESSION(stmt), owner_name, table_name, &dc) != OG_SUCCESS) {
        return OBJ_STATUS_INVALID;
    }

    if (dc.type == DICT_TYPE_VIEW) {
        obj_status =
            sql_compile_view(stmt, owner_name, table_name, &dc, OG_FALSE) ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID;
        cm_reset_error();
    } else {
        obj_status = OBJ_STATUS_VALID;
    }

    p_obj->uid = dc.uid;
    p_obj->oid = dc.oid;
    p_obj->scn = dc.chg_scn;
    p_obj->tid = knl_get_object_type(dc.type);
    errcode = memcpy_s(p_obj->name, OG_NAME_BUFFER_SIZE, table_name->str, table_name->len);
    if (errcode != EOK) {
        dc_close(&dc);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OBJ_STATUS_INVALID;
    }
    p_obj->name[table_name->len] = '\0';

    dc_close(&dc);

    return obj_status;
}

static object_status_t sql_check_pl_synonym_object_valid(sql_stmt_t *stmt, text_t *owner_name, text_t *table_name,
                                                         object_address_t *obj_addr, object_type_t syn_type)
{
    object_status_t obj_status = OBJ_STATUS_VALID;
    pl_dc_t dc = { 0 };
    bool32 exist = OG_FALSE;
    var_udo_t var_udo;
    errno_t errcode;
    uint32 type;
    pl_dc_assist_t assist = { 0 };

    sql_init_udo(&var_udo);
    var_udo.name = *table_name;
    var_udo.user = *owner_name;

    type = pl_get_obj_type(syn_type);
    pl_dc_open_prepare(&assist, stmt, owner_name, table_name, type);
    if (pl_dc_open(&assist, &dc, &exist) != OG_SUCCESS || !exist) {
        return OBJ_STATUS_INVALID;
    }

    obj_addr->uid = dc.uid;
    obj_addr->oid = (uint64)dc.oid;
    obj_addr->scn = dc.entry->desc.chg_scn;
    obj_addr->tid = syn_type;
    errcode = memcpy_s(obj_addr->name, OG_NAME_BUFFER_SIZE, table_name->str, table_name->len);
    if (errcode != EOK) {
        pl_dc_close(&dc);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OBJ_STATUS_INVALID;
    }
    obj_addr->name[table_name->len] = '\0';
    pl_dc_close(&dc);
    return obj_status;
}

static status_t sql_make_object_address(knl_cursor_t *cursor, object_address_t *d_obj, object_status_t *old_status)
{
    text_t tmp_text;

    *old_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_FLAG);
    d_obj->oid = (uint64)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID));
    d_obj->scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);
    tmp_text.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
    tmp_text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
    errno_t err = memcpy_s(d_obj->name, OG_NAME_BUFFER_SIZE, tmp_text.str, tmp_text.len);
    if (err != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return OG_ERROR;
    }

    if (tmp_text.len >= OG_NAME_BUFFER_SIZE) {
        OG_THROW_ERROR(ERR_SOURCE_SIZE_TOO_LARGE_FMT, tmp_text.len, OG_NAME_BUFFER_SIZE - 1);
        return OG_ERROR;
    }
    d_obj->name[tmp_text.len] = '\0';
    return OG_SUCCESS;
}

static status_t sql_check_current_synonym(sql_stmt_t *stmt, knl_session_t *session, knl_cursor_t *cursor,
                                          bool32 compile_all, uint32 uid)
{
    object_address_t d_obj;
    object_address_t p_obj;
    object_status_t old_status;
    object_status_t new_status;
    char owner_buf[OG_NAME_BUFFER_SIZE];
    char object_buf[OG_NAME_BUFFER_SIZE];
    text_t table_name;
    text_t owner_name;

    d_obj.uid = uid;
    OG_RETURN_IFERR(sql_make_object_address(cursor, &d_obj, &old_status));
    owner_name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
    owner_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
    OG_RETURN_IFERR(cm_text2str(&owner_name, owner_buf, OG_NAME_BUFFER_SIZE));
    owner_name.str = owner_buf;
    table_name.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);
    table_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
    OG_RETURN_IFERR(cm_text2str(&table_name, object_buf, OG_NAME_BUFFER_SIZE));
    table_name.str = object_buf;
    object_type_t syn_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);

    if (!compile_all && old_status == OBJ_STATUS_VALID) {
        return OG_SUCCESS;
    }
    /* check current synonym valid or not */
    if (IS_PL_SYN(syn_type)) {
        new_status = sql_check_pl_synonym_object_valid(stmt, &owner_name, &table_name, &p_obj, syn_type);
        d_obj.tid = OBJ_TYPE_PL_SYNONYM;
    } else {
        new_status = sql_check_synonym_object_valid(stmt, &owner_name, &table_name, &p_obj);
        d_obj.tid = OBJ_TYPE_SYNONYM;
    }

    if (knl_delete_dependency(session, d_obj.uid, (int64)d_obj.oid, d_obj.tid) != OG_SUCCESS) {
        return OG_SUCCESS;
    }
    if (new_status == OBJ_STATUS_VALID &&
        knl_insert_dependency((knl_handle_t *)session, &d_obj, &p_obj, 0) != OG_SUCCESS) {
        knl_rollback(session, NULL);
        return OG_SUCCESS;
    }
    if (old_status != new_status && sql_update_object_status(session, (obj_info_t *)&d_obj, new_status) != OG_SUCCESS) {
        knl_rollback(session, NULL);
        return OG_SUCCESS;
    }

    knl_commit(session);
    return OG_SUCCESS;
}

/*
 * sql_compile_synonym_by_user
 *
 * This function is used to recompile synonym and update the flag of this synonym.
 */
status_t sql_compile_synonym_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    knl_session_t *session = KNL_SESSION(stmt);

    /* check the schema name invalid or not */
    if (!knl_get_user_id(KNL_SESSION(stmt), schema_name, &uid)) {
        OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(schema_name));
        return OG_ERROR;
    }

    knl_set_session_scn(session, OG_INVALID_ID64);

    OGSQL_SAVE_STACK(stmt);

    if (sql_push_knl_cursor(session, &cursor) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, 0);
    knl_init_index_scan(cursor, OG_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, OG_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    while (1) {
        if (knl_fetch(session, cursor) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        if (sql_check_current_synonym(stmt, session, cursor, compile_all, uid) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    }

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_recompile_view(sql_stmt_t *stmt, text_t *owner_name, text_t *view_name, object_status_t old_status)
{
    knl_dictionary_t dc;
    object_address_t obj;
    object_status_t new_status = OBJ_STATUS_INVALID;

    /* recompile view */
    if (dc_open(KNL_SESSION(stmt), owner_name, view_name, &dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    obj.uid = dc.uid;
    obj.oid = dc.oid;
    obj.tid = OBJ_TYPE_VIEW;
    obj.scn = KNL_GET_SCN(&KNL_SESSION(stmt)->kernel->min_scn);
    errno_t err = memcpy_s(obj.name, OG_NAME_BUFFER_SIZE, view_name->str, view_name->len);
    if (err != EOK) {
        dc_close(&dc);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return OG_ERROR;
    }

    obj.name[view_name->len] = '\0';

    if (OG_TRUE != sql_compile_view(stmt, owner_name, view_name, &dc, OG_TRUE)) {
        new_status = OBJ_STATUS_INVALID;
    } else {
        new_status = OBJ_STATUS_VALID;
    }

    dc_close(&dc);

    /* update the status of view */
    if (old_status != new_status) {
        OG_RETURN_IFERR(sql_update_object_status(KNL_SESSION(stmt), (obj_info_t *)&obj, new_status));
    }

    knl_commit(KNL_SESSION(stmt));

    return OG_SUCCESS;
}

/*
 * sql_compile_view_by_user
 *
 * This function is used to recompile view and update the status of this synonym.
 */
status_t sql_compile_view_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all)
{
    knl_cursor_t *cursor = NULL;
    uint32 uid;
    char object_buf[OG_NAME_BUFFER_SIZE];
    text_t view_name;
    knl_session_t *session = KNL_SESSION(stmt);

    /* check the schema name invalid or not */
    if (!knl_get_user_id(KNL_SESSION(stmt), schema_name, &uid)) {
        OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(schema_name));
        return OG_ERROR;
    }

    knl_set_session_scn(session, OG_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, 0);
    knl_init_index_scan(cursor, OG_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, OG_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 1);

    if (knl_fetch(session, cursor) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    status_t status = OG_SUCCESS;
    while (!cursor->eof) {
        object_status_t old_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_FLAG);
        view_name.str = CURSOR_COLUMN_DATA(cursor, SYS_VIEW_NAME);
        view_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_VIEW_NAME);

        status = cm_text2str(&view_name, object_buf, OG_NAME_BUFFER_SIZE);
        OG_BREAK_IF_ERROR(status);
        view_name.str = object_buf;

        if (((compile_all == OG_FALSE && old_status != OBJ_STATUS_VALID) || compile_all == OG_TRUE) &&
            sql_recompile_view(stmt, schema_name, &view_name, old_status) != OG_SUCCESS) {
            cm_reset_error();
        }

        status = knl_fetch(session, cursor);
        OG_BREAK_IF_ERROR(status);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

#ifdef __cplusplus
}
#endif
