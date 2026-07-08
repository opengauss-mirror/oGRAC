/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of the License at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * ogsql_completion.c
 *
 * -------------------------------------------------------------------------
 */
#include <string.h>
#include "cm_error.h"
#include "keywords.h"
#include "kwlookup.h"
#include "ogsql_common.h"
#include "ogsql_completion.h"

typedef struct OgsqlSchemaCompletionRequestT {
    const char *schema;
    uint32 schemaLen;
    const char *prefix;
    uint32 prefixLen;
} OgsqlSchemaCompletionRequestT;

typedef struct OgsqlCompletionFetchCtxT {
    ogconn_stmt_t stmt;
    const char *prefix;
    uint32 prefixLen;
    uint32 maxCount;
} OgsqlCompletionFetchCtxT;
static const char *g_sqlCompletionWords[] = {
    "alter",
    "analyze",
    "and",
    "as",
    "asc",
    "begin",
    "between",
    "by",
    "commit",
    "create",
    "declare",
    "delete",
    "desc",
    "describe",
    "distinct",
    "drop",
    "explain",
    "from",
    "full",
    "function",
    "grant",
    "group",
    "having",
    "in",
    "index",
    "inner",
    "insert",
    "into",
    "join",
    "left",
    "like",
    "limit",
    "not",
    "offset",
    "on",
    "or",
    "order",
    "outer",
    "package",
    "procedure",
    "revoke",
    "right",
    "rollback",
    "role",
    "select",
    "sequence",
    "set",
    "show",
    "table",
    "trigger",
    "type",
    "union",
    "update",
    "user",
    "values",
    "view",
    "where",
    /* High-frequency keywords that the kernel classifies as UNRESERVED_KEYWORD
       (so they are skipped by the ScanKeywords loop above) but users still
       expect them in completion. Kept here as a supplemental source so the
       de-duplication logic in ogsql_add_completion_match handles overlap. */
    "after",        /* CREATE TRIGGER ... AFTER                 */
    "before",       /* CREATE TRIGGER ... BEFORE                */
    "body",         /* CREATE PACKAGE BODY                      */
    "cache",        /* CREATE SEQUENCE ... CACHE                */
    "call",         /* CALL procedure                           */
    "cascade",      /* DROP ... CASCADE                         */
    "cluster",      /* CLUSTER ...                              */
    "close",        /* CLOSE cursor                             */
    "comment",      /* COMMENT ON ...                           */
    "copy",         /* COPY ...                                 */
    "cross",        /* CROSS JOIN                               */
    "cursor",       /* CURSOR declarations                      */
    "cycle",        /* CREATE SEQUENCE ... CYCLE                */
    "database",     /* CREATE/ALTER/DROP DATABASE               */
    "directory",    /* CREATE DIRECTORY                         */
    "disable",      /* ALTER ... DISABLE                        */
    "enable",       /* ALTER ... ENABLE                         */
    "escape",       /* LIKE '...' ESCAPE '...'                  */
    "exec",         /* EXEC procedure                           */
    "execute",      /* EXECUTE statement/procedure              */
    "foreign",      /* FOREIGN KEY                              */
    "global",       /* GLOBAL TEMPORARY TABLE                   */
    "instead",      /* CREATE TRIGGER ... INSTEAD OF           */
    "language",     /* CREATE LANGUAGE                         */
    "local",        /* LOCAL TEMPORARY TABLE                    */
    "lock",         /* LOCK TABLE                               */
    "materialized", /* CREATE MATERIALIZED VIEW                 */
    "merge",        /* MERGE INTO                               */
    "nocache",      /* CREATE SEQUENCE ... NOCACHE              */
    "novalidate",   /* ALTER ... NOVALIDATE                     */
    "partition",    /* PARTITION syntax                         */
    "primary",      /* PRIMARY KEY                              */
    "profile",      /* CREATE PROFILE                           */
    "public",       /* CREATE PUBLIC SYNONYM                    */
    "rename",       /* RENAME                                   */
    "replace",      /* CREATE OR REPLACE                        */
    "return",       /* PL/SQL RETURN                            */
    "row",          /* FOR EACH ROW                             */
    "savepoint",    /* SAVEPOINT                                */
    "schema",       /* CREATE SCHEMA                            */
    "statement",    /* FOR EACH STATEMENT                       */
    "synonym",      /* CREATE SYNONYM                           */
    "tablespace",   /* CREATE/ALTER TABLESPACE                  */
    "temporary",    /* CREATE TEMPORARY TABLE                   */
    "tenant",       /* CREATE TENANT                            */
    "truncate",     /* TRUNCATE TABLE                           */
    "validate",     /* ALTER ... VALIDATE                       */
};
#define OGSQL_SQL_COMPLETION_WORD_COUNT (sizeof(g_sqlCompletionWords) / sizeof(char *))

/* Builtin SQL functions that are not stored in SYS.MY_PROCEDURES. */
static const char *g_builtinFunctions[] = {
    "ABS",
    "AVG",
    "CAST",
    "CEIL",
    "COALESCE",
    "CONCAT",
    "COUNT",
    "DECODE",
    "EXTRACT",
    "FLOOR",
    "GREATEST",
    "INSTR",
    "LEAST",
    "LENGTH",
    "LOWER",
    "LPAD",
    "LTRIM",
    "MAX",
    "MIN",
    "MOD",
    "NVL",
    "NVL2",
    "POWER",
    "REGEXP_REPLACE",
    "REGEXP_SUBSTR",
    "REPLACE",
    "ROUND",
    "RPAD",
    "RTRIM",
    "SUBSTR",
    "SUM",
    "SYSDATE",
    "SYSTIMESTAMP",
    "TO_CHAR",
    "TO_DATE",
    "TO_NUMBER",
    "TRIM",
    "TRUNC",
    "UPPER",
    "USER"
};
#define OGSQL_BUILTIN_FUNC_COUNT (sizeof(g_builtinFunctions) / sizeof(char *))

static bool32 ogsql_is_completion_token_char(char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
        ch == '_' || ch == '$' || ch == '#') ? OG_TRUE : OG_FALSE;
}

static bool32 ogsql_is_completion_statement_boundary(char ch)
{
    return (ch == ';') ? OG_TRUE : OG_FALSE;
}

static char OgsqlCompletionLowerChar(char ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
}

static char OgsqlCompletionUpperChar(char ch)
{
    return (ch >= 'a' && ch <= 'z') ? (char)(ch - 'a' + 'A') : ch;
}

status_t ogsql_completion_find_token(char *cmdBuf, uint32 cursor_pos, uint32 *token_start,
    uint32 *token_len)
{
    uint32 pos = cursor_pos;

    while (pos > 0 && ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
        pos--;
    }

    *token_start = pos;
    *token_len = cursor_pos - pos;
    return OG_SUCCESS;
}

static bool32 ogsql_get_completion_schema_prefix(const char *cmdBuf, uint32 token_start, uint32 *schema_start,
    uint32 *schema_len)
{
    uint32 pos;

    if (token_start < OGSQL_CMD_BUF_RESET_TAIL_LEN || cmdBuf[token_start - 1] != '.') {
        return OG_FALSE;
    }

    pos = token_start - 1;
    while (pos > 0 && ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
        pos--;
    }
    if (pos == token_start - 1) {
        return OG_FALSE;
    }

    *schema_start = pos;
    *schema_len = token_start - 1 - pos;
    return OG_TRUE;
}

static bool32 ogsql_completion_prefix_is_upper(const char *prefix, uint32 prefix_len)
{
    bool32 has_upper = OG_FALSE;

    for (uint32 i = 0; i < prefix_len; i++) {
        if (prefix[i] >= 'a' && prefix[i] <= 'z') {
            return OG_FALSE;
        }
        if (prefix[i] >= 'A' && prefix[i] <= 'Z') {
            has_upper = OG_TRUE;
        }
    }

    return has_upper;
}

static bool32 ogsql_completion_word_matches(const char *word, const char *prefix, uint32 prefix_len)
{
    for (uint32 i = 0; i < prefix_len; i++) {
        if (word[i] == '\0') {
            return OG_FALSE;
        }
        if (OgsqlCompletionLowerChar(word[i]) != OgsqlCompletionLowerChar(prefix[i])) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 ogsql_completion_word_equal(const char *left, const char *right)
{
    uint32 pos = 0;

    while (left[pos] != '\0' && right[pos] != '\0') {
        if (OgsqlCompletionLowerChar(left[pos]) != OgsqlCompletionLowerChar(right[pos])) {
            return OG_FALSE;
        }
        pos++;
    }

    return (left[pos] == '\0' && right[pos] == '\0') ? OG_TRUE : OG_FALSE;
}

static bool32 ogsql_completion_word_exists(const char **matches, uint32 match_count, const char *word)
{
    for (uint32 i = 0; i < match_count; i++) {
        if (ogsql_completion_word_equal(matches[i], word)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static void ogsql_add_completion_match(const char **matches, uint32 *match_count, const char *word)
{
    if (word == NULL || !ogsql_is_completion_token_char(word[0])) {
        return;
    }
    if (*match_count >= OGSQL_MAX_COMPLETION_MATCHES || ogsql_completion_word_exists(matches, *match_count, word)) {
        return;
    }

    matches[*match_count] = word;
    (*match_count)++;
}

/* ==================== Dynamic object completion ==================== */

static uint32 ogsql_get_completion_query_limit(void)
{
    uint32 limit = g_local_config.completion_max_records;

    if (limit == 0) {
        limit = OGSQL_DEFAULT_COMPLETION_RECORDS;
    }
    return (limit > OGSQL_MAX_COMPLETION_RECORDS) ? OGSQL_MAX_COMPLETION_RECORDS : limit;
}

static status_t ogsql_make_limited_completion_sql(char *sql_buf, uint32 sql_buf_size, const char *base_sql)
{
    uint32 limit;
    int32 ret;

    if (sql_buf == NULL || sql_buf_size == 0 || base_sql == NULL) {
        return OG_ERROR;
    }

    limit = ogsql_get_completion_query_limit();
    ret = snprintf_s(sql_buf, sql_buf_size, sql_buf_size - 1, "%s LIMIT %u", base_sql, limit);
    return (ret < 0) ? OG_ERROR : OG_SUCCESS;
}

static void OgsqlResetCompletionError(void)
{
    if (IS_CONN && CONN != NULL) {
        clt_reset_error((clt_conn_t *)CONN);
    } else {
        cm_reset_error();
    }
}

static void OgsqlAddDynamicCompletionMatch(OgsqlCompletionStoreT *store, const char *word)
{
    errno_t rc;

    if (store == NULL || store->matches == NULL || store->matchCount == NULL || store->dynamicWords == NULL ||
        store->dynamicCount == NULL || word == NULL || !ogsql_is_completion_token_char(word[0])) {
        return;
    }

    if (*store->matchCount >= OGSQL_MAX_COMPLETION_MATCHES ||
        *store->dynamicCount >= OGSQL_MAX_COMPLETION_MATCHES ||
        ogsql_completion_word_exists(store->matches, *store->matchCount, word)) {
        return;
    }

    rc = strncpy_s(store->dynamicWords[*store->dynamicCount], OGSQL_OBJ_NAME_LEN, word, strlen(word));
    if (rc != EOK) {
        return;
    }
    store->matches[*store->matchCount] = store->dynamicWords[*store->dynamicCount];
    (*store->dynamicCount)++;
    (*store->matchCount)++;
}

static void OgsqlRestoreCompletionCounts(OgsqlCompletionStoreT *store, uint32 startMatchCount,
    uint32 startDynamicCount)
{
    *store->matchCount = startMatchCount;
    *store->dynamicCount = startDynamicCount;
}

static status_t OgsqlFetchCompletionRows(const OgsqlCompletionFetchCtxT *fetchCtx, OgsqlCompletionStoreT *store)
{
    uint32 rows = 0;
    uint32 fetched = 0;
    char str_buf[OGSQL_OBJ_NAME_LEN];

    if (fetchCtx == NULL) {
        return OG_ERROR;
    }
    while (fetched < fetchCtx->maxCount) {
        if (ogconn_fetch(fetchCtx->stmt, &rows) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (rows == 0) {
            break;
        }
        if (ogconn_column_as_string(fetchCtx->stmt, 0, str_buf, sizeof(str_buf)) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (ogsql_completion_word_matches(str_buf, fetchCtx->prefix, fetchCtx->prefixLen)) {
            OgsqlAddDynamicCompletionMatch(store, str_buf);
        }
        fetched++;
    }
    return OG_SUCCESS;
}

/* Run a fresh completion query. Any failure is hidden from the command line so
   Tab completion never leaks backend errors into normal interactive editing. */
static status_t OgsqlQueryCompletionMatches(const char *baseSql, const char *prefix, uint32 prefixLen,
    OgsqlCompletionStoreT *store)
{
    uint32 startMatchCount;
    uint32 startDynamicCount;
    char sqlBuf[OGSQL_MAX_TEMP_SQL + 1];
    ogconn_stmt_t completionStmt = NULL;
    OgsqlCompletionFetchCtxT fetchCtx;

    if (!IS_CONN || CONN == NULL || baseSql == NULL || store == NULL || store->matches == NULL ||
        store->matchCount == NULL || store->dynamicWords == NULL || store->dynamicCount == NULL) {
        return OG_ERROR;
    }
    if (ogsql_make_limited_completion_sql(sqlBuf, sizeof(sqlBuf), baseSql) != OG_SUCCESS) {
        return OG_ERROR;
    }
    startMatchCount = *store->matchCount;
    startDynamicCount = *store->dynamicCount;

    if (ogconn_alloc_stmt(CONN, &completionStmt) != OG_SUCCESS) {
        OgsqlResetCompletionError();
        return OG_ERROR;
    }
    fetchCtx = (OgsqlCompletionFetchCtxT){ completionStmt, prefix, prefixLen, ogsql_get_completion_query_limit() };
    if (ogconn_prepare(completionStmt, sqlBuf) != OG_SUCCESS || ogconn_execute(completionStmt) != OG_SUCCESS ||
        OgsqlFetchCompletionRows(&fetchCtx, store) != OG_SUCCESS) {
        OgsqlRestoreCompletionCounts(store, startMatchCount, startDynamicCount);
        ogconn_free_stmt(completionStmt);
        OgsqlResetCompletionError();
        return OG_ERROR;
    }
    ogconn_free_stmt(completionStmt);
    return OG_SUCCESS;
}

static status_t OgsqlCollectSchemaTableMatches(const OgsqlSchemaCompletionRequestT *request,
    OgsqlCompletionStoreT *store)
{
    char schema_buf[OGSQL_OBJ_NAME_LEN];
    char sql_buf[OGSQL_MAX_TEMP_SQL + 1];
    uint32 copy_len;
    errno_t rc;
    int ret;

    if (request == NULL || request->schema == NULL || request->schemaLen == 0 ||
        request->schemaLen >= OGSQL_OBJ_NAME_LEN) {
        return OG_ERROR;
    }

    copy_len = (request->schemaLen < OGSQL_OBJ_NAME_LEN - 1) ? request->schemaLen : (OGSQL_OBJ_NAME_LEN - 1);
    rc = memcpy_s(schema_buf, sizeof(schema_buf), request->schema, copy_len);
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return OG_ERROR;
    }
    schema_buf[copy_len] = '\0';

    ret = snprintf_s(sql_buf, sizeof(sql_buf), sizeof(sql_buf) - 1,
        "SELECT T.NAME FROM SYS.SYS_TABLES T, SYS.SYS_USERS U "
        "WHERE T.USER# = U.ID AND T.RECYCLED = 0 AND UPPER(U.NAME) = UPPER('%s') "
        "UNION SELECT V.NAME FROM SYS.SYS_VIEWS V, SYS.SYS_USERS U "
        "WHERE V.USER# = U.ID AND UPPER(U.NAME) = UPPER('%s')",
        schema_buf, schema_buf);
    if (ret < 0) {
        return OG_ERROR;
    }

    return OgsqlQueryCompletionMatches(sql_buf, request->prefix, request->prefixLen, store);
}

static bool32 ogsql_get_lower_completion_word_before(const char *cmdBuf, uint32 pos, char *lower_word,
    uint32 word_size, uint32 *word_start)
{
    uint32 word_end;
    uint32 word_len;

    if (word_size == 0) {
        return OG_FALSE;
    }

    while (pos > 0 && !ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
        if (ogsql_is_completion_statement_boundary(cmdBuf[pos - 1])) {
            lower_word[0] = '\0';
            return OG_FALSE;
        }
        pos--;
    }
    word_end = pos;
    while (pos > 0 && ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
        pos--;
    }
    word_len = word_end - pos;
    if (word_len == 0 || word_len >= word_size) {
        lower_word[0] = '\0';
        return OG_FALSE;
    }

    for (uint32 i = 0; i < word_len; i++) {
        lower_word[i] = OgsqlCompletionLowerChar(cmdBuf[pos + i]);
    }
    lower_word[word_len] = '\0';
    if (word_start != NULL) {
        *word_start = pos;
    }
    return OG_TRUE;
}

static bool32 ogsql_completion_word_is_drop_alter(const char *word)
{
    return (strcmp(word, "drop") == 0 || strcmp(word, "alter") == 0) ? OG_TRUE : OG_FALSE;
}

static bool32 ogsql_completion_word_is_table_command(const char *word)
{
    return (strcmp(word, "drop") == 0 || strcmp(word, "alter") == 0 || strcmp(word, "truncate") == 0 ||
        strcmp(word, "lock") == 0) ? OG_TRUE : OG_FALSE;
}

static bool32 ogsql_completion_ctx_allows_sql_words(OgsqlCompletionCtxT ctx)
{
    return (ctx == OGSQL_COMPLETION_CTX_DEFAULT || ctx == OGSQL_COMPLETION_CTX_COLUMN) ? OG_TRUE : OG_FALSE;
}

static uint32 OgsqlCompletionContextScanStart(const char *cmdBuf, uint32 cursorPos, bool32 hasCurrentToken,
    bool32 *separatedBeforeContext)
{
    uint32 pos = cursorPos;

    while (pos > 0 && (cmdBuf[pos - 1] == ' ' || cmdBuf[pos - 1] == '\t')) {
        pos--;
    }
    if (hasCurrentToken) {
        while (pos > 0 && ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
            pos--;
        }
        while (pos > 0 && (cmdBuf[pos - 1] == ' ' || cmdBuf[pos - 1] == '\t')) {
            pos--;
        }
    }
    if (separatedBeforeContext != NULL && pos > 0 && !ogsql_is_completion_token_char(cmdBuf[pos - 1])) {
        *separatedBeforeContext = OG_TRUE;
    }
    return pos;
}

static OgsqlCompletionCtxT OgsqlClassifyCompletionWord(const char *lowerWord, const char *priorWord)
{
    if (strcmp(lowerWord, "from") == 0 || strcmp(lowerWord, "join") == 0 ||
        strcmp(lowerWord, "into") == 0 || strcmp(lowerWord, "update") == 0 ||
        strcmp(lowerWord, "desc") == 0 || strcmp(lowerWord, "describe") == 0) {
        return OGSQL_COMPLETION_CTX_TABLE;
    }
    if (strcmp(lowerWord, "select") == 0 || strcmp(lowerWord, "where") == 0 ||
        strcmp(lowerWord, "by") == 0 || strcmp(lowerWord, "having") == 0 ||
        strcmp(lowerWord, "set") == 0 || strcmp(lowerWord, "and") == 0 ||
        strcmp(lowerWord, "or") == 0 || strcmp(lowerWord, "on") == 0 ||
        strcmp(lowerWord, "using") == 0) {
        return OGSQL_COMPLETION_CTX_COLUMN;
    }
    if (strcmp(lowerWord, "call") == 0 || strcmp(lowerWord, "exec") == 0 ||
        strcmp(lowerWord, "execute") == 0) {
        return OGSQL_COMPLETION_CTX_PROCEDURE;
    }
    if ((strcmp(lowerWord, "table") == 0 || strcmp(lowerWord, "view") == 0) &&
        ogsql_completion_word_is_table_command(priorWord)) {
        return OGSQL_COMPLETION_CTX_TABLE;
    }
    if ((strcmp(lowerWord, "procedure") == 0 || strcmp(lowerWord, "function") == 0) &&
        ogsql_completion_word_is_drop_alter(priorWord)) {
        return OGSQL_COMPLETION_CTX_PROCEDURE;
    }
    if (strcmp(lowerWord, "sequence") == 0 && ogsql_completion_word_is_drop_alter(priorWord)) {
        return OGSQL_COMPLETION_CTX_SEQUENCE;
    }
    return OGSQL_COMPLETION_CTX_DEFAULT;
}

/* Classify the completion context by scanning the last SQL keyword before the
   cursor. Falls back to DEFAULT when no known keyword is found. */
static OgsqlCompletionCtxT OgsqlClassifyCompletionContext(const char *cmdBuf, uint32 cursorPos,
    bool32 hasCurrentToken)
{
    uint32 pos;
    uint32 wordStart = 0;
    bool32 firstWord = OG_TRUE;
    bool32 separatedBeforeContext = OG_FALSE;
    OgsqlCompletionCtxT ctx;
    char lowerWord[OGSQL_MAX_COMPLETION_WORD_LEN];
    char priorWord[OGSQL_MAX_COMPLETION_WORD_LEN] = { 0 };

    pos = OgsqlCompletionContextScanStart(cmdBuf, cursorPos, hasCurrentToken, &separatedBeforeContext);
    while (ogsql_get_lower_completion_word_before(cmdBuf, pos, lowerWord, sizeof(lowerWord), &wordStart)) {
        priorWord[0] = '\0';
        (void)ogsql_get_lower_completion_word_before(cmdBuf, wordStart, priorWord, sizeof(priorWord), NULL);
        ctx = OgsqlClassifyCompletionWord(lowerWord, priorWord);
        if (ctx != OGSQL_COMPLETION_CTX_DEFAULT) {
            return ctx;
        }
        if (firstWord && !separatedBeforeContext) {
            break;
        }
        firstWord = OG_FALSE;
        if (wordStart == 0) {
            break;
        }
        pos = wordStart;
    }
    return OGSQL_COMPLETION_CTX_DEFAULT;
}

static void ogsql_collect_kernel_keyword_matches(const char *prefix, uint32 prefix_len, const char **matches,
    uint32 *match_count)
{
    if (prefix_len == 0 || ScanKeywords.num_keywords <= 0) {
        return;
    }
    for (int i = 0; i < ScanKeywords.num_keywords; i++) {
        uint8 cat = ScanKeywordCategories[i];
        if (cat != RESERVED_KEYWORD && cat != COL_NAME_KEYWORD) {
            continue;
        }
        const char *word = GetScanKeyword(i, &ScanKeywords);
        if (ogsql_completion_word_matches(word, prefix, prefix_len)) {
            ogsql_add_completion_match(matches, match_count, word);
        }
    }
}

static void ogsql_collect_supplement_keyword_matches(const char *prefix, uint32 prefix_len, const char **matches,
    uint32 *match_count)
{
    if (prefix_len == 0) {
        return;
    }
    for (uint32 i = 0; i < OGSQL_SQL_COMPLETION_WORD_COUNT; i++) {
        if (ogsql_completion_word_matches(g_sqlCompletionWords[i], prefix, prefix_len)) {
            ogsql_add_completion_match(matches, match_count, g_sqlCompletionWords[i]);
        }
    }
}

static void ogsql_collect_command_matches(const char *prefix, uint32 prefixLen,
    const ogsql_cmd_def_t *commandDefs, uint32 commandCount, const char **matches, uint32 *matchCount)
{
    if (prefixLen == 0 || commandDefs == NULL) {
        return;
    }
    for (uint32 i = 0; i < commandCount; i++) {
        if (ogsql_completion_word_matches(commandDefs[i].str, prefix, prefixLen)) {
            ogsql_add_completion_match(matches, matchCount, commandDefs[i].str);
        }
    }
}
static void ogsql_collect_builtin_function_matches(const char *prefix, uint32 prefix_len, const char **matches,
    uint32 *match_count)
{
    for (uint32 i = 0; i < OGSQL_BUILTIN_FUNC_COUNT; i++) {
        if (ogsql_completion_word_matches(g_builtinFunctions[i], prefix, prefix_len)) {
            ogsql_add_completion_match(matches, match_count, g_builtinFunctions[i]);
        }
    }
}

static void ogsql_collect_static_completion_matches(OgsqlCompletionCtxT ctx, const char *prefix, uint32 prefix_len,
    const ogsql_cmd_def_t *commandDefs, uint32 commandCount, const char **matches, uint32 *match_count)
{
    if (matches == NULL || match_count == NULL || prefix == NULL) {
        return;
    }
    if (ogsql_completion_ctx_allows_sql_words(ctx)) {
        ogsql_collect_kernel_keyword_matches(prefix, prefix_len, matches, match_count);
        ogsql_collect_supplement_keyword_matches(prefix, prefix_len, matches, match_count);
    }
    ogsql_collect_command_matches(prefix, prefix_len, commandDefs, commandCount, matches, match_count);
    if (ctx == OGSQL_COMPLETION_CTX_COLUMN || ctx == OGSQL_COMPLETION_CTX_DEFAULT) {
        ogsql_collect_builtin_function_matches(prefix, prefix_len, matches, match_count);
    }
}

static bool32 ogsql_completion_ctx_is_dynamic(OgsqlCompletionCtxT ctx)
{
    return (ctx == OGSQL_COMPLETION_CTX_TABLE || ctx == OGSQL_COMPLETION_CTX_COLUMN ||
        ctx == OGSQL_COMPLETION_CTX_PROCEDURE || ctx == OGSQL_COMPLETION_CTX_SEQUENCE) ? OG_TRUE : OG_FALSE;
}

static status_t OgsqlCollectDynamicMatches(OgsqlCompletionCtxT ctx, const char *prefix, uint32 prefixLen,
    OgsqlCompletionStoreT *store)
{
    const char *sql = NULL;

    switch (ctx) {
        case OGSQL_COMPLETION_CTX_TABLE:
            sql = "SELECT NAME FROM SYS.SYS_TABLES T, SYS.DV_ME M "
                "WHERE T.USER# = M.USER_ID AND T.RECYCLED = 0 "
                "UNION SELECT NAME FROM SYS.SYS_VIEWS V, SYS.DV_ME M WHERE V.USER# = M.USER_ID";
            break;
        case OGSQL_COMPLETION_CTX_COLUMN:
            sql = "SELECT C.NAME FROM SYS.SYS_TABLES T, SYS.DV_ME M, SYS.SYS_COLUMNS C "
                "WHERE T.USER# = M.USER_ID AND C.USER# = T.USER# AND C.TABLE# = T.ID AND T.RECYCLED = 0 "
                "UNION SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES WHERE OBJECT_TYPE = 'FUNCTION'";
            break;
        case OGSQL_COMPLETION_CTX_PROCEDURE:
            sql = "SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES WHERE OBJECT_TYPE = 'PROCEDURE' "
                "UNION SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES WHERE OBJECT_TYPE = 'FUNCTION'";
            break;
        case OGSQL_COMPLETION_CTX_SEQUENCE:
            sql = "SELECT NAME FROM SYS.SYS_SEQUENCES S, SYS.DV_ME M WHERE S.UID = M.USER_ID";
            break;
        case OGSQL_COMPLETION_CTX_DEFAULT:
        case OGSQL_COMPLETION_CTX_SCHEMA_TABLE:
        default:
            return OG_ERROR;
    }

    return OgsqlQueryCompletionMatches(sql, prefix, prefixLen, store);
}

uint32 ogsql_completion_collect(const OgsqlCompletionRequestT *request, OgsqlCompletionStoreT *store)
{
    OgsqlCompletionCtxT ctx;
    OgsqlSchemaCompletionRequestT schemaRequest;
    uint32 schema_start = 0;
    uint32 schema_len = 0;

    if (request == NULL || store == NULL || store->matchCount == NULL || store->dynamicCount == NULL) {
        return 0;
    }
    *store->matchCount = 0;
    *store->dynamicCount = 0;
    if (ogsql_get_completion_schema_prefix(request->cmdBuf, request->tokenStart, &schema_start, &schema_len)) {
        schemaRequest = (OgsqlSchemaCompletionRequestT){ request->cmdBuf + schema_start, schema_len,
            request->prefix, request->prefixLen };
        if (OgsqlCollectSchemaTableMatches(&schemaRequest, store) == OG_SUCCESS && *store->matchCount > 0) {
            return *store->matchCount;
        }
        return 0;
    }

    ctx = OgsqlClassifyCompletionContext(request->cmdBuf, request->cursorPos, request->prefixLen > 0);
    if (request->prefixLen == 0 && ctx == OGSQL_COMPLETION_CTX_DEFAULT) {
        return 0;
    }

    if (ogsql_completion_ctx_is_dynamic(ctx) == OG_TRUE &&
        OgsqlCollectDynamicMatches(ctx, request->prefix, request->prefixLen, store) == OG_SUCCESS &&
        *store->matchCount > 0) {
        return *store->matchCount;
    }

    *store->matchCount = 0;
    ogsql_collect_static_completion_matches(ctx, request->prefix, request->prefixLen, request->commandDefs,
        request->commandCount, store->matches, store->matchCount);
    return *store->matchCount;
}

uint32 ogsql_completion_common_prefix(const char **matches, uint32 match_count, char *common,
    uint32 common_size)
{
    uint32 common_len;

    if (match_count == 0 || common_size == 0) {
        return 0;
    }

    common_len = (uint32)strlen(matches[0]);
    if (common_len >= common_size) {
        common_len = common_size - 1;
    }
    for (uint32 i = 0; i < common_len; i++) {
        common[i] = matches[0][i];
    }
    common[common_len] = '\0';

    for (uint32 i = 1; i < match_count; i++) {
        uint32 pos = 0;

        while (pos < common_len && matches[i][pos] != '\0' &&
            OgsqlCompletionLowerChar(common[pos]) == OgsqlCompletionLowerChar(matches[i][pos])) {
            pos++;
        }
        common_len = pos;
        common[common_len] = '\0';
    }

    return common_len;
}

uint32 ogsql_completion_make_suffix(const char *word, const char *token, uint32 token_len, char *suffix,
    uint32 suffix_size)
{
    uint32 word_len = (uint32)strlen(word);
    uint32 suffix_len;
    bool32 use_upper;

    if (word_len <= token_len || suffix_size == 0) {
        return 0;
    }

    suffix_len = word_len - token_len;
    if (suffix_len >= suffix_size) {
        suffix_len = suffix_size - 1;
    }

    use_upper = ogsql_completion_prefix_is_upper(token, token_len);
    for (uint32 i = 0; i < suffix_len; i++) {
        if (token_len == 0) {
            suffix[i] = word[token_len + i];
        } else {
            suffix[i] = use_upper ? OgsqlCompletionUpperChar(word[token_len + i]) :
                OgsqlCompletionLowerChar(word[token_len + i]);
        }
    }
    suffix[suffix_len] = '\0';

    return suffix_len;
}
