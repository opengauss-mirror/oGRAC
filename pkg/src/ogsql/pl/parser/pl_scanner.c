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
 * pl_scanner.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/pl_scanner.h
 *
 * -------------------------------------------------------------------------
 */
#include "pl_compiler.h"
#include "ogsql_expr_def.h"
#include "cm_text.h"
#include "expr_parser.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "pl_udt.h"
#include "trigger_decl_cl.h"

#include "pl_gram.h" /* must be after parser/scanner.h */

#include "gramparse.h"

#define LENGTH_OF_DOT_AND_STR_END 4
#define INT32_STRING_SIZE 12
#define MAX_PUSHBACKS 100
/*
 * A word about keywords:
 *
 * We keep reserved and unreserved keywords in separate headers.  Be careful
 * not to put the same word in both headers.  Also be sure that pl_gram.y's
 * unreserved_keyword production agrees with the unreserved header.  The
 * reserved keywords are passed to the core scanner, so they will be
 * recognized before (and instead of) any variable name.  Unreserved
 * words are checked for separately, after determining that the identifier
 * isn't a known variable name.  If plpgsql_IdentifierLookup is DECLARE then
 * no variable names will be recognized, so the unreserved words always work.
 * (Note in particular that this helps us avoid reserving keywords that are
 * only needed in DECLARE sections.)
 *
 * In certain contexts it is desirable to prefer recognizing an unreserved
 * keyword over recognizing a variable name.  Those cases are handled in
 * gram.y using tok_is_keyword().
 *
 * For the most part, the reserved keywords are those that start a PL/pgSQL
 * statement (and so would conflict with an assignment to a variable of the
 * same name).	We also don't sweat it much about reserving keywords that
 * are reserved in the core grammar.  Try to avoid reserving other words.
 */

/*
 * Lists of keyword (name, token-value, category) entries.
 *
 * !!WARNING!!: These lists must be sorted by ASCII name, because binary
 *		 search is used to locate entries.
 *
 * Be careful not to put the same word in both lists.  Also be sure that
 * gram.y's unreserved_keyword production agrees with the second list.
 */

/* ScanKeywordList lookup data for PL/pgSQL keywords */
#include "pl_reserved_kwlist_d.h"
#include "pl_unreserved_kwlist_d.h"

/* Token codes for PL/pgSQL keywords */
#define OG_KEYWORD(kwname, value) value,

static const uint16 ReservedPLKeywordTokens[] = {
#include "pl_reserved_kwlist.h"
};
static const uint16 UnreservedPLKeywordTokens[] = {
#include "pl_unreserved_kwlist.h"
};

#undef OG_KEYWORD

/* static const struct PlsqlKeywordValue keywordsValue = {
    .procedure = K_PROCEDURE,
    .function = K_FUNCTION,
    .begin = K_BEGIN,
    .select = K_SELECT,
    .update = K_UPDATE,
    .insert = K_INSERT,
    .Delete = K_DELETE,
    .merge = K_MERGE
}; */

/* Auxiliary data about a token (other than the token type) */
typedef struct {
    YYSTYPE lval; /* semantic information */
    YYLTYPE lloc; /* offset in scanbuf */
    int leng;     /* length in bytes */
    bool8 ident_quoted;
} TokenAuxData;

typedef struct {
    base_yy_extra_type base_yy_extra;
    int num_pushbacks;
    int pushback_token[MAX_PUSHBACKS];
    TokenAuxData pushback_auxdata[MAX_PUSHBACKS];
    TokenAuxData last_token;
} plsql_yy_extra_type;

static inline plsql_yy_extra_type *plsql_yyget_extra(core_yyscan_t yyscanner)
{
    return (plsql_yy_extra_type *)og_yyget_extra(yyscanner);
}

static void push_back_token(plsql_yy_extra_type *yyextra, int token, TokenAuxData* auxdata);

status_t pl_parser(sql_stmt_t *stmt, text_t *src)
{
    core_yyscan_t yyscanner;
    plsql_yy_extra_type yyextra;
    int parse_rc;
    sql_text_t sql_text = { 0 };
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    sql_text_t parser_text_bak = stmt->parser_text;
    bool32 parser_text_valid_bak = stmt->parser_text_valid;
    errno_t rc;

    rc = memset_s(&yyextra, sizeof(yyextra), 0, sizeof(yyextra));
    if (rc != EOK) {
        return OG_ERROR;
    }

    sql_text.value = *src;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    if (compiler != NULL) {
        sql_text.loc = compiler->line_loc;
    }
    sql_text.implicit = OG_FALSE;

    yyscanner = scanner_init(&sql_text, &yyextra.base_yy_extra.core_yy_extra, &ReservedPLKeywords,
        ReservedPLKeywordTokens, stmt);
    if (SECUREC_UNLIKELY(yyscanner == NULL)) {
        stmt->parser_text = parser_text_bak;
        stmt->parser_text_valid = parser_text_valid_bak;
        return OG_ERROR;
    }

    parse_rc = plsql_yyparse(yyscanner);

    scanner_finish(yyscanner);
    stmt->parser_text = parser_text_bak;
    stmt->parser_text_valid = parser_text_valid_bak;
    if (parse_rc != 0) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static int internal_yylex(TokenAuxData* auxdata, core_yyscan_t yyscanner)
{
    plsql_yy_extra_type *yyextra = plsql_yyget_extra(yyscanner);
    int token;

    errno_t rc = memset_s(auxdata, sizeof(TokenAuxData), 0, sizeof(TokenAuxData));
    knl_securec_check(rc);

    if (yyextra->num_pushbacks > 0) {
        yyextra->num_pushbacks--;
        token = yyextra->pushback_token[yyextra->num_pushbacks];
        *auxdata = yyextra->pushback_auxdata[yyextra->num_pushbacks];
    } else {
        token = core_yylex(&auxdata->lval.core_yystype, &auxdata->lloc, yyscanner);
        auxdata->leng = ct_yyget_leng(yyscanner);
        auxdata->ident_quoted = og_yyget_extra(yyscanner)->core_yy_extra.ident_quoted;
    }

    return token;
}

static status_t alloc_var_addr_expr(sql_stmt_t *stmt, plv_decl_t *decl, expr_node_t **out_expr)
{
    expr_node_t *expr = NULL;
    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;

    OG_RETURN_IFERR(sql_alloc_mem(compiler->stmt->context, sizeof(expr_node_t), (void **)&expr));
    expr->owner = NULL;
    expr->type = EXPR_NODE_PROC;
    expr->unary = UNARY_OPER_NONE;
    expr->word.func.user_func_first = OG_FALSE;

    OG_RETURN_IFERR(plc_build_var_address(stmt, decl, expr, UDT_STACK_ADDR));
    *out_expr = expr;
    return OG_SUCCESS;
}

static status_t parse_var_ident(sql_stmt_t *stmt, char *ident, expr_node_t **out_expr)
{
    text_t name;
    cm_str2text(ident, &name);
    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
    uint32 types = PLV_VARIANT_AND_CUR;
    plv_decl_t *decl = NULL;
    plc_variant_name_t variant_name;
    char block_name_buf[OG_NAME_BUFFER_SIZE];
    char name_buf[OG_NAME_BUFFER_SIZE];
    plc_var_type_t type;

    PLC_INIT_VARIANT_NAME(&variant_name, block_name_buf, name_buf, OG_FALSE, types);
    type = PLC_NORMAL_VAR;
    variant_name.block_name.len = 0;
    plc_concat_text_upper_by_type(&variant_name.name, OG_MAX_NAME_LEN, &name, WORD_TYPE_VARIANT);

    if (type == PLC_NORMAL_VAR || type == PLC_TRIGGER_VAR) {
        plc_find_block_decl(compiler, &variant_name, &decl);
    }

    if (decl == NULL) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(alloc_var_addr_expr(stmt, decl, out_expr));
    return OG_SUCCESS;
}

static status_t parse_trigger_var_word(sql_stmt_t *stmt, word_t *word, expr_node_t **out_expr)
{
    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
    plv_decl_t *decl = NULL;
    plc_var_type_t type;

    plc_find_decl_ex(compiler, word, PLV_VARIANT_AND_CUR, &type, &decl);
    if (decl == NULL) {
        OG_RETURN_IFERR(plc_add_trigger_decl(compiler, 0, word, PLV_VAR, &decl));
    }
    if (decl == NULL) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(alloc_var_addr_expr(stmt, decl, out_expr));
    return OG_SUCCESS;
}

static bool32 plsql_is_trigger_param(TokenAuxData *auxdata, core_yyscan_t yyscanner, word_type_t *word_type)
{
    text_t token_text;

    token_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + auxdata->lloc.offset;
    token_text.len = (uint32)auxdata->leng;
    if (cm_text_str_equal_ins(&token_text, ":new")) {
        *word_type = WORD_TYPE_PL_NEW_COL;
        return OG_TRUE;
    }
    if (cm_text_str_equal_ins(&token_text, ":old")) {
        *word_type = WORD_TYPE_PL_OLD_COL;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 plsql_is_identifier_like_token(TokenAuxData *auxdata, core_yyscan_t yyscanner)
{
    char *token_text = NULL;

    if (auxdata->leng <= 0) {
        return OG_FALSE;
    }

    token_text = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + auxdata->lloc.offset;
    return (bool32)(CM_IS_LETER(token_text[0]) || token_text[0] == '_');
}

static bool32 plsql_token_text_equal(TokenAuxData *auxdata, core_yyscan_t yyscanner, const char *expected)
{
    uint32 expected_len = (uint32)strlen(expected);
    char *token_text = NULL;

    if (auxdata->leng != (int)expected_len) {
        return OG_FALSE;
    }

    token_text = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + auxdata->lloc.offset;
    return (bool32)(memcmp(token_text, expected, expected_len) == 0);
}

static status_t plsql_copy_token_word(sql_stmt_t *stmt, TokenAuxData *auxdata, core_yyscan_t yyscanner)
{
    char *token_text = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + auxdata->lloc.offset;
    uint32 token_len = (uint32)auxdata->leng;
    char *ident = NULL;
    errno_t ret;

    if (sql_stack_alloc(stmt, token_len + 1, (void **)&ident) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ret = memcpy_s(ident, token_len + 1, token_text, token_len);
    if (ret != EOK) {
        return OG_ERROR;
    }
    ident[token_len] = '\0';

    auxdata->lval.word.ident = ident;
    auxdata->lval.word.quoted = auxdata->ident_quoted;
    return OG_SUCCESS;
}

static bool32 plsql_match_reserved_keyword(TokenAuxData *auxdata, int *token)
{
    int kwnum = ScanKeywordLookup(auxdata->lval.word.ident, &ReservedPLKeywords);
    if (kwnum < 0) {
        return OG_FALSE;
    }

    auxdata->lval.keyword = GetScanKeyword(kwnum, &ReservedPLKeywords);
    *token = ReservedPLKeywordTokens[kwnum];
    return OG_TRUE;
}

static bool32 plsql_match_unreserved_keyword(TokenAuxData *auxdata, int *token)
{
    int kwnum = ScanKeywordLookup(auxdata->lval.word.ident, &UnreservedPLKeywords);
    if (kwnum < 0) {
        return OG_FALSE;
    }

    auxdata->lval.keyword = GetScanKeyword(kwnum, &UnreservedPLKeywords);
    *token = UnreservedPLKeywordTokens[kwnum];
    return OG_TRUE;
}

static int plsql_remap_core_token(TokenAuxData *auxdata, core_yyscan_t yyscanner, int token)
{
    /*
     * core_yylex() is generated from the SQL grammar, so scanner-only tokens
     * have core grammar numbers.  The PL grammar declares the same token names,
     * but bison token values are not stable across the two generated parsers.
     * Remap scanner punctuation by lexeme instead of assuming a numeric offset.
     */
    if (plsql_token_text_equal(auxdata, yyscanner, "::")) {
        return TYPECAST;
    }
    if (plsql_token_text_equal(auxdata, yyscanner, "(+)")) {
        return ORA_JOINOP;
    }
    if (plsql_token_text_equal(auxdata, yyscanner, "..")) {
        return DOT_DOT;
    }
    if (plsql_token_text_equal(auxdata, yyscanner, ":=")) {
        return COLON_EQUALS;
    }
    if (plsql_token_text_equal(auxdata, yyscanner, "=>")) {
        return PARA_EQUALS;
    }
    return token;
}

static status_t plsql_try_read_trigger_var(sql_stmt_t *stmt, TokenAuxData *param_aux, core_yyscan_t yyscanner,
    bool32 *matched, expr_node_t **out_expr)
{
    plsql_yy_extra_type *yyextra = plsql_yyget_extra(yyscanner);
    TokenAuxData dot_aux;
    TokenAuxData ident_aux;
    word_type_t word_type;
    word_t word = { 0 };
    char *start = NULL;
    char *end = NULL;
    int dot_token;
    int ident_token;

    *matched = OG_FALSE;
    if (!plsql_is_trigger_param(param_aux, yyscanner, &word_type)) {
        return OG_SUCCESS;
    }

    dot_token = internal_yylex(&dot_aux, yyscanner);
    if (dot_token != '.') {
        push_back_token(yyextra, dot_token, &dot_aux);
        return OG_SUCCESS;
    }

    ident_token = internal_yylex(&ident_aux, yyscanner);
    if (ident_token != IDENT) {
        push_back_token(yyextra, ident_token, &ident_aux);
        push_back_token(yyextra, dot_token, &dot_aux);
        return OG_SUCCESS;
    }

    start = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + param_aux->lloc.offset;
    end = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + ident_aux.lloc.offset + ident_aux.leng;
    word.type = word_type;
    word.loc = param_aux->lloc.loc;
    word.text.value.str = start;
    word.text.value.len = (uint32)(end - start);
    word.text.loc = param_aux->lloc.loc;
    word.ex_count = 1;
    word.ex_words[0].type = ident_aux.ident_quoted ? WORD_TYPE_DQ_STRING : WORD_TYPE_VARIANT;
    word.ex_words[0].text.value.str = ident_aux.lval.word.ident;
    word.ex_words[0].text.value.len = (uint32)strlen(ident_aux.lval.word.ident);
    word.ex_words[0].text.loc = ident_aux.lloc.loc;

    OG_RETURN_IFERR(parse_trigger_var_word(stmt, &word, out_expr));
    *matched = OG_TRUE;
    return OG_SUCCESS;
}

int plsql_yylex(YYSTYPE *lvalp, YYLTYPE *llocp, core_yyscan_t yyscanner)
{
    int token;
    TokenAuxData aux;
    int kwnum;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    plsql_yy_extra_type *yyextra = plsql_yyget_extra(yyscanner);

    token = internal_yylex(&aux, yyscanner);
    token = plsql_remap_core_token(&aux, yyscanner, token);
    if (token == PARAM) {
        bool32 matched = OG_FALSE;
        if (plsql_try_read_trigger_var(stmt, &aux, yyscanner, &matched, &aux.lval.node) != OG_SUCCESS) {
            token = LEX_ERROR_TOKEN;
        } else if (matched) {
            token = T_DATUM;
        }
    } else if (token == IDENT) {
        if (parse_var_ident(stmt, aux.lval.word.ident, &aux.lval.node) == OG_SUCCESS) {
            token = T_DATUM;
        } else if ((kwnum = ScanKeywordLookup(aux.lval.word.ident, &UnreservedPLKeywords)) >= 0) {
            aux.lval.keyword = GetScanKeyword(kwnum, &UnreservedPLKeywords);
            token = UnreservedPLKeywordTokens[kwnum];
        } else {
            aux.lval.word.quoted = aux.ident_quoted;
            token = T_WORD;
        }
    } else if (plsql_is_identifier_like_token(&aux, yyscanner)) {
        /*
         * The shared SQL scanner can still return core SQL keyword tokens for
         * datatype names such as BINARY_INTEGER.  Those token numbers are not
         * part of the PL grammar, and they can overlap numerically with PL
         * token values.  Reclassify by lexeme instead of trusting the core
         * token number.
         */
        if (plsql_copy_token_word(stmt, &aux, yyscanner) != OG_SUCCESS) {
            token = LEX_ERROR_TOKEN;
        } else if (parse_var_ident(stmt, aux.lval.word.ident, &aux.lval.node) == OG_SUCCESS) {
            token = T_DATUM;
        } else if (plsql_match_reserved_keyword(&aux, &token)) {
            /* token set by plsql_match_reserved_keyword */
        } else if (plsql_match_unreserved_keyword(&aux, &token)) {
            /* token set by plsql_match_unreserved_keyword */
        } else {
            token = T_WORD;
        }
    }

    *lvalp = aux.lval;
    *llocp = aux.lloc;
    yyextra->last_token = aux;
    return token;
}

YYSTYPE *plsql_last_yylval(core_yyscan_t yyscanner)
{
    return &plsql_yyget_extra(yyscanner)->last_token.lval;
}

YYLTYPE *plsql_last_yylloc(core_yyscan_t yyscanner)
{
    return &plsql_yyget_extra(yyscanner)->last_token.lloc;
}

int plsql_last_yyleng(core_yyscan_t yyscanner)
{
    return plsql_yyget_extra(yyscanner)->last_token.leng;
}

/*
 * Push back a token to be re-read by next internal_yylex() call.
 */
static void push_back_token(plsql_yy_extra_type *yyextra, int token, TokenAuxData* auxdata)
{
    if (yyextra->num_pushbacks >= MAX_PUSHBACKS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "too many tokens %d pushed back, max push back token is: %d",
            yyextra->num_pushbacks, MAX_PUSHBACKS);
    }
    yyextra->pushback_token[yyextra->num_pushbacks] = token;
    yyextra->pushback_auxdata[yyextra->num_pushbacks] = *auxdata;
    yyextra->num_pushbacks++;
}

/*
 * Push back the last PL token to be re-read by next plsql_yylex() call.
 * It is not a good idea to push back a token code other than what you read.
 */
void plsql_push_back_token(int token, core_yyscan_t yyscanner)
{
    plsql_yy_extra_type *yyextra = plsql_yyget_extra(yyscanner);

    push_back_token(yyextra, token, &yyextra->last_token);
}
