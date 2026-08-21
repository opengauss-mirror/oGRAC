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
#include "ogsql_option.h"

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

#define OGSQL_MAX_COMPLETION_TOKENS 256
#define OGSQL_MAX_COMPLETION_SOURCES 8

typedef enum EnOgsqlCompletionTokenKindT {
    OGSQL_COMPLETION_TOKEN_WORD,
    OGSQL_COMPLETION_TOKEN_DOT,
    OGSQL_COMPLETION_TOKEN_COMMA,
    OGSQL_COMPLETION_TOKEN_LEFT_PAREN,
    OGSQL_COMPLETION_TOKEN_RIGHT_PAREN
} OgsqlCompletionTokenKindT;

typedef struct OgsqlCompletionTokenT {
    OgsqlCompletionTokenKindT kind;
    char text[OGSQL_OBJ_NAME_LEN];
} OgsqlCompletionTokenT;

typedef struct OgsqlCompletionSourceT {
    char schema[OGSQL_OBJ_NAME_LEN];
    char table[OGSQL_OBJ_NAME_LEN];
    char alias[OGSQL_OBJ_NAME_LEN];
} OgsqlCompletionSourceT;

typedef struct OgsqlCompletionSqlContextT {
    OgsqlCompletionSourceT sources[OGSQL_MAX_COMPLETION_SOURCES];
    uint32 sourceCount;
    bool32 insertColumnContext;
} OgsqlCompletionSqlContextT;
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
    "identified",
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
    "resource",
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
    "flashback",    /* FLASHBACK TABLE/DATABASE                 */
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
    "rebuild",      /* ALTER INDEX ... REBUILD                  */
    "rename",       /* RENAME                                   */
    "replace",      /* CREATE OR REPLACE                        */
    "return",       /* PL/SQL RETURN                            */
    "row",          /* FOR EACH ROW                             */
    "savepoint",    /* SAVEPOINT                                */
    "schema",       /* CREATE SCHEMA                            */
    "session",      /* ALTER/GRANT ... SESSION                  */
    "statement",    /* FOR EACH STATEMENT                       */
    "synonym",      /* CREATE SYNONYM                           */
    "system",       /* ALTER SYSTEM                             */
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
    "GS_DECRYPT",
    "GS_DECRYPT_AES128",
    "GS_ENCRYPT",
    "GS_ENCRYPT_AES128",
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

static const char *g_createTableCompletionWords[] = {
    "auto_increment",
    "text",
    "unsigned"
};
#define OGSQL_CREATE_TABLE_COMPLETION_WORD_COUNT \
    (sizeof(g_createTableCompletionWords) / sizeof(g_createTableCompletionWords[0]))

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

static bool32 OgsqlCompletionWordAt(const char *cmdBuf, uint32 limit, uint32 *pos, const char *expected)
{
    uint32 start;
    uint32 length;

    while (*pos < limit && (cmdBuf[*pos] == ' ' || cmdBuf[*pos] == '\t' ||
        cmdBuf[*pos] == '\r' || cmdBuf[*pos] == '\n')) {
        (*pos)++;
    }
    start = *pos;
    while (*pos < limit && ogsql_is_completion_token_char(cmdBuf[*pos])) {
        (*pos)++;
    }
    length = *pos - start;
    return (length == (uint32)strlen(expected) &&
        ogsql_completion_word_matches(expected, cmdBuf + start, length)) ? OG_TRUE : OG_FALSE;
}

static void OgsqlCompletionSkipSpace(const char *cmdBuf, uint32 limit, uint32 *pos)
{
    while (*pos < limit && (cmdBuf[*pos] == ' ' || cmdBuf[*pos] == '\t' ||
        cmdBuf[*pos] == '\r' || cmdBuf[*pos] == '\n')) {
        (*pos)++;
    }
}

static bool32 OgsqlCompletionSkipIdentifier(const char *cmdBuf, uint32 limit, uint32 *pos)
{
    bool32 hasCharacter = OG_FALSE;

    if (*pos < limit && cmdBuf[*pos] == '"') {
        (*pos)++;
        while (*pos < limit) {
            if (cmdBuf[*pos] == '"') {
                if (*pos + 1 < limit && cmdBuf[*pos + 1] == '"') {
                    *pos += 2;
                    hasCharacter = OG_TRUE;
                    continue;
                }
                (*pos)++;
                return hasCharacter;
            }
            (*pos)++;
            hasCharacter = OG_TRUE;
        }
        return OG_FALSE;
    }
    while (*pos < limit && ogsql_is_completion_token_char(cmdBuf[*pos])) {
        (*pos)++;
        hasCharacter = OG_TRUE;
    }
    return hasCharacter;
}

/* Keep type-name candidates scoped to an unfinished CREATE TABLE column list. */
static bool32 OgsqlCompletionIsCreateTableDefinitionContext(const OgsqlCompletionRequestT *request)
{
    uint32 statementStart = 0;
    uint32 pos;
    uint32 depth = 0;
    char quote = '\0';

    for (pos = 0; pos < request->tokenStart; pos++) {
        if (request->cmdBuf[pos] == ';') {
            statementStart = pos + 1;
        }
    }
    pos = statementStart;
    if (!OgsqlCompletionWordAt(request->cmdBuf, request->tokenStart, &pos, "create") ||
        !OgsqlCompletionWordAt(request->cmdBuf, request->tokenStart, &pos, "table")) {
        return OG_FALSE;
    }

    OgsqlCompletionSkipSpace(request->cmdBuf, request->tokenStart, &pos);
    if (!OgsqlCompletionSkipIdentifier(request->cmdBuf, request->tokenStart, &pos)) {
        return OG_FALSE;
    }
    OgsqlCompletionSkipSpace(request->cmdBuf, request->tokenStart, &pos);
    if (pos < request->tokenStart && request->cmdBuf[pos] == '.') {
        pos++;
        OgsqlCompletionSkipSpace(request->cmdBuf, request->tokenStart, &pos);
        if (!OgsqlCompletionSkipIdentifier(request->cmdBuf, request->tokenStart, &pos)) {
            return OG_FALSE;
        }
        OgsqlCompletionSkipSpace(request->cmdBuf, request->tokenStart, &pos);
    }
    if (pos >= request->tokenStart || request->cmdBuf[pos] != '(') {
        return OG_FALSE;
    }

    for (; pos < request->tokenStart; pos++) {
        char current = request->cmdBuf[pos];

        if (quote != '\0') {
            if (current == quote) {
                if (pos + 1 < request->tokenStart && request->cmdBuf[pos + 1] == quote) {
                    pos++;
                } else {
                    quote = '\0';
                }
            }
            continue;
        }
        if (current == '\'' || current == '"') {
            quote = current;
        } else if (current == '(') {
            depth++;
        } else if (current == ')') {
            if (depth == 0) {
                return OG_FALSE;
            }
            depth--;
            if (depth == 0) {
                return OG_FALSE;
            }
        }
    }
    return (depth > 0) ? OG_TRUE : OG_FALSE;
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

static status_t OgsqlCopyCompletionToken(const char *token, uint32 tokenLen, char *buffer, uint32 bufferSize)
{
    errno_t rc;

    if (token == NULL || buffer == NULL || bufferSize == 0 || tokenLen >= bufferSize) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < tokenLen; i++) {
        if (!ogsql_is_completion_token_char(token[i])) {
            return OG_ERROR;
        }
    }
    rc = memcpy_s(buffer, bufferSize, token, tokenLen);
    if (rc != EOK) {
        return OG_ERROR;
    }
    buffer[tokenLen] = '\0';
    return OG_SUCCESS;
}

static status_t OgsqlCollectSchemaTableMatches(const OgsqlSchemaCompletionRequestT *request,
    OgsqlCompletionStoreT *store)
{
    char schema_buf[OGSQL_OBJ_NAME_LEN];
    char prefix_buf[OGSQL_OBJ_NAME_LEN];
    char sql_buf[OGSQL_MAX_TEMP_SQL + 1];
    int ret;

    if (request == NULL || request->schema == NULL || request->schemaLen == 0 ||
        OgsqlCopyCompletionToken(request->schema, request->schemaLen, schema_buf, sizeof(schema_buf)) != OG_SUCCESS ||
        OgsqlCopyCompletionToken(request->prefix, request->prefixLen, prefix_buf, sizeof(prefix_buf)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (request->prefixLen == 0) {
        ret = snprintf_s(sql_buf, sizeof(sql_buf), sizeof(sql_buf) - 1,
            "SELECT TABLE_NAME FROM SYS.DB_TABLES WHERE UPPER(OWNER) = UPPER('%s') "
            "UNION SELECT VIEW_NAME FROM SYS.DB_VIEWS WHERE UPPER(OWNER) = UPPER('%s') ORDER BY 1",
            schema_buf, schema_buf);
    } else {
        ret = snprintf_s(sql_buf, sizeof(sql_buf), sizeof(sql_buf) - 1,
            "SELECT TABLE_NAME FROM SYS.DB_TABLES WHERE UPPER(OWNER) = UPPER('%s') "
            "AND SUBSTR(UPPER(TABLE_NAME), 1, %u) = UPPER('%s') "
            "UNION SELECT VIEW_NAME FROM SYS.DB_VIEWS WHERE UPPER(OWNER) = UPPER('%s') "
            "AND SUBSTR(UPPER(VIEW_NAME), 1, %u) = UPPER('%s') ORDER BY 1",
            schema_buf, request->prefixLen, prefix_buf, schema_buf, request->prefixLen, prefix_buf);
    }
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

static bool32 ogsql_completion_has_words_before(const OgsqlCompletionRequestT *request, const char *nearest,
    const char *second, const char *third)
{
    uint32 wordStart = request->tokenStart;
    char word[OGSQL_MAX_COMPLETION_WORD_LEN];
    const char *expected[] = { nearest, second, third };

    for (uint32 i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        if (expected[i] == NULL) {
            return OG_TRUE;
        }
        if (!ogsql_get_lower_completion_word_before(request->cmdBuf, wordStart, word, sizeof(word), &wordStart) ||
            strcmp(word, expected[i]) != 0) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 ogsql_completion_has_ordered_words_before(const OgsqlCompletionRequestT *request,
    const char *nearest, const char *earlier)
{
    uint32 wordStart = request->tokenStart;
    bool32 foundNearest = OG_FALSE;
    char word[OGSQL_MAX_COMPLETION_WORD_LEN];

    while (ogsql_get_lower_completion_word_before(request->cmdBuf, wordStart, word, sizeof(word), &wordStart)) {
        if (foundNearest == OG_TRUE && strcmp(word, earlier) == 0) {
            return OG_TRUE;
        }
        if (strcmp(word, nearest) == 0) {
            foundNearest = OG_TRUE;
        }
        if (wordStart == 0) {
            break;
        }
    }
    return OG_FALSE;
}

static bool32 ogsql_completion_has_word_before(const OgsqlCompletionRequestT *request, const char *expected)
{
    uint32 wordStart = request->tokenStart;
    char word[OGSQL_MAX_COMPLETION_WORD_LEN];

    while (ogsql_get_lower_completion_word_before(request->cmdBuf, wordStart, word, sizeof(word), &wordStart)) {
        if (strcmp(word, expected) == 0) {
            return OG_TRUE;
        }
        if (wordStart == 0) {
            break;
        }
    }
    return OG_FALSE;
}

static void ogsql_add_preferred_keyword_match(const OgsqlCompletionRequestT *request, const char *word,
    const char **matches, uint32 *matchCount)
{
    if (request->prefixLen > 0 && ogsql_completion_word_matches(word, request->prefix, request->prefixLen)) {
        ogsql_add_completion_match(matches, matchCount, word);
    }
}

/* Keep the #289 DDL keyword fixes with the object-context implementation. */
static void ogsql_collect_issue289_keyword_matches(const OgsqlCompletionRequestT *request,
    const char **matches, uint32 *matchCount)
{
    if (ogsql_completion_has_words_before(request, "create", NULL, NULL)) {
        ogsql_add_preferred_keyword_match(request, "global", matches, matchCount);
    }
    if (ogsql_completion_has_words_before(request, "alter", NULL, NULL)) {
        ogsql_add_preferred_keyword_match(request, "system", matches, matchCount);
    }
    if (ogsql_completion_has_ordered_words_before(request, "index", "alter")) {
        ogsql_add_preferred_keyword_match(request, "rebuild", matches, matchCount);
    }
    if (request->tokenStart == 0) {
        ogsql_add_preferred_keyword_match(request, "flashback", matches, matchCount);
    }
}

static void ogsql_collect_preferred_keyword_matches(const OgsqlCompletionRequestT *request,
    const char **matches, uint32 *matchCount)
{
    if (ogsql_completion_has_words_before(request, "select", NULL, NULL)) {
        ogsql_add_preferred_keyword_match(request, "distinct", matches, matchCount);
    }
    if (ogsql_completion_has_words_before(request, "alter", NULL, NULL)) {
        ogsql_add_preferred_keyword_match(request, "session", matches, matchCount);
    }
    if (ogsql_completion_has_ordered_words_before(request, "user", "create")) {
        ogsql_add_preferred_keyword_match(request, "identified", matches, matchCount);
    }
    if (ogsql_completion_has_words_before(request, "grant", NULL, NULL)) {
        ogsql_add_preferred_keyword_match(request, "resource", matches, matchCount);
    }
    if (ogsql_completion_has_words_before(request, "create", "grant", NULL)) {
        ogsql_add_preferred_keyword_match(request, "session", matches, matchCount);
    }
    if (ogsql_completion_has_word_before(request, "select")) {
        ogsql_add_preferred_keyword_match(request, "from", matches, matchCount);
    }
}

static bool32 OgsqlCompletionTokenIsWord(const OgsqlCompletionTokenT *token, const char *word)
{
    return (token != NULL && token->kind == OGSQL_COMPLETION_TOKEN_WORD && strcmp(token->text, word) == 0) ?
        OG_TRUE : OG_FALSE;
}

static void OgsqlAddCompletionToken(OgsqlCompletionTokenT *tokens, uint32 *tokenCount,
    OgsqlCompletionTokenKindT kind, const char *text, uint32 textLen)
{
    OgsqlCompletionTokenT *token;

    if (*tokenCount >= OGSQL_MAX_COMPLETION_TOKENS || textLen >= OGSQL_OBJ_NAME_LEN) {
        return;
    }
    token = &tokens[*tokenCount];
    token->kind = kind;
    token->text[0] = '\0';
    for (uint32 i = 0; i < textLen; i++) {
        token->text[i] = OgsqlCompletionLowerChar(text[i]);
    }
    token->text[textLen] = '\0';
    (*tokenCount)++;
}

static uint32 OgsqlTokenizeCompletionSql(const char *cmdBuf, uint32 endPos, OgsqlCompletionTokenT *tokens)
{
    uint32 tokenCount = 0;
    uint32 pos = 0;

    while (pos < endPos) {
        if (cmdBuf[pos] == '-' && pos + 1 < endPos && cmdBuf[pos + 1] == '-') {
            pos += 2;
            while (pos < endPos && cmdBuf[pos] != '\n') {
                pos++;
            }
            continue;
        }
        if (cmdBuf[pos] == '/' && pos + 1 < endPos && cmdBuf[pos + 1] == '*') {
            pos += 2;
            while (pos + 1 < endPos && !(cmdBuf[pos] == '*' && cmdBuf[pos + 1] == '/')) {
                pos++;
            }
            pos = (pos + 1 < endPos) ? pos + 2 : endPos;
            continue;
        }
        if (cmdBuf[pos] == '\'' || cmdBuf[pos] == '"') {
            char quote = cmdBuf[pos++];

            while (pos < endPos) {
                if (cmdBuf[pos] != quote) {
                    pos++;
                    continue;
                }
                if (pos + 1 < endPos && cmdBuf[pos + 1] == quote) {
                    pos += 2;
                    continue;
                }
                pos++;
                break;
            }
            continue;
        }
        if (cmdBuf[pos] == ';') {
            tokenCount = 0;
            pos++;
            continue;
        }
        if (ogsql_is_completion_token_char(cmdBuf[pos])) {
            uint32 wordStart = pos;

            while (pos < endPos && ogsql_is_completion_token_char(cmdBuf[pos])) {
                pos++;
            }
            OgsqlAddCompletionToken(tokens, &tokenCount, OGSQL_COMPLETION_TOKEN_WORD,
                cmdBuf + wordStart, pos - wordStart);
            continue;
        }
        switch (cmdBuf[pos]) {
            case '.':
                OgsqlAddCompletionToken(tokens, &tokenCount, OGSQL_COMPLETION_TOKEN_DOT, NULL, 0);
                break;
            case ',':
                OgsqlAddCompletionToken(tokens, &tokenCount, OGSQL_COMPLETION_TOKEN_COMMA, NULL, 0);
                break;
            case '(':
                OgsqlAddCompletionToken(tokens, &tokenCount, OGSQL_COMPLETION_TOKEN_LEFT_PAREN, NULL, 0);
                break;
            case ')':
                OgsqlAddCompletionToken(tokens, &tokenCount, OGSQL_COMPLETION_TOKEN_RIGHT_PAREN, NULL, 0);
                break;
            default:
                break;
        }
        pos++;
    }
    return tokenCount;
}

static bool32 OgsqlCompletionIsSourceBoundary(const OgsqlCompletionTokenT *token)
{
    static const char *boundaries[] = {
        "where", "join", "inner", "left", "right", "full", "cross", "on", "using", "group", "order",
        "having", "set", "values", "returning", "union", "minus", "except", "intersect", "connect", "start"
    };

    if (token == NULL || token->kind != OGSQL_COMPLETION_TOKEN_WORD) {
        return OG_TRUE;
    }
    for (uint32 i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
        if (strcmp(token->text, boundaries[i]) == 0) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static void OgsqlCopyParsedName(char *destination, const char *source)
{
    if (source != NULL) {
        (void)strncpy_s(destination, OGSQL_OBJ_NAME_LEN, source, strlen(source));
    }
}

static bool32 OgsqlCompletionSourceExists(const OgsqlCompletionSqlContextT *context,
    const OgsqlCompletionSourceT *candidate)
{
    for (uint32 i = 0; i < context->sourceCount; i++) {
        const OgsqlCompletionSourceT *source = &context->sources[i];

        if (ogsql_completion_word_equal(source->schema, candidate->schema) &&
            ogsql_completion_word_equal(source->table, candidate->table) &&
            ogsql_completion_word_equal(source->alias, candidate->alias)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static uint32 OgsqlParseCompletionSource(const OgsqlCompletionTokenT *tokens, uint32 tokenCount,
    uint32 sourceIndex, OgsqlCompletionSqlContextT *context, uint32 *objectEnd)
{
    OgsqlCompletionSourceT *source;
    uint32 next = sourceIndex;

    if (sourceIndex >= tokenCount || tokens[sourceIndex].kind != OGSQL_COMPLETION_TOKEN_WORD ||
        context->sourceCount >= OGSQL_MAX_COMPLETION_SOURCES) {
        return sourceIndex;
    }
    if (sourceIndex + 1 < tokenCount && tokens[sourceIndex + 1].kind == OGSQL_COMPLETION_TOKEN_DOT &&
        (sourceIndex + 2 >= tokenCount || tokens[sourceIndex + 2].kind != OGSQL_COMPLETION_TOKEN_WORD)) {
        return sourceIndex + 2;
    }
    source = &context->sources[context->sourceCount];
    (void)memset_s(source, sizeof(*source), 0, sizeof(*source));
    if (sourceIndex + 2 < tokenCount && tokens[sourceIndex + 1].kind == OGSQL_COMPLETION_TOKEN_DOT &&
        tokens[sourceIndex + 2].kind == OGSQL_COMPLETION_TOKEN_WORD) {
        OgsqlCopyParsedName(source->schema, tokens[sourceIndex].text);
        OgsqlCopyParsedName(source->table, tokens[sourceIndex + 2].text);
        next = sourceIndex + 3;
    } else {
        OgsqlCopyParsedName(source->table, tokens[sourceIndex].text);
        next = sourceIndex + 1;
    }
    if (objectEnd != NULL) {
        *objectEnd = next;
    }
    if (next + 1 < tokenCount && OgsqlCompletionTokenIsWord(&tokens[next], "as") &&
        tokens[next + 1].kind == OGSQL_COMPLETION_TOKEN_WORD) {
        OgsqlCopyParsedName(source->alias, tokens[next + 1].text);
        next += 2;
    } else if (next < tokenCount && tokens[next].kind == OGSQL_COMPLETION_TOKEN_WORD &&
        !OgsqlCompletionIsSourceBoundary(&tokens[next])) {
        OgsqlCopyParsedName(source->alias, tokens[next].text);
        next++;
    }
    if (OgsqlCompletionSourceExists(context, source) == OG_FALSE) {
        context->sourceCount++;
    }
    return next;
}

static bool32 OgsqlCompletionEndsSourceList(const OgsqlCompletionTokenT *token)
{
    return (OgsqlCompletionTokenIsWord(token, "where") || OgsqlCompletionTokenIsWord(token, "group") ||
        OgsqlCompletionTokenIsWord(token, "order") || OgsqlCompletionTokenIsWord(token, "having") ||
        OgsqlCompletionTokenIsWord(token, "on") || OgsqlCompletionTokenIsWord(token, "using") ||
        OgsqlCompletionTokenIsWord(token, "union") || OgsqlCompletionTokenIsWord(token, "minus") ||
        OgsqlCompletionTokenIsWord(token, "except") || OgsqlCompletionTokenIsWord(token, "intersect") ||
        OgsqlCompletionTokenIsWord(token, "connect") || OgsqlCompletionTokenIsWord(token, "start")) ?
        OG_TRUE : OG_FALSE;
}

static bool32 OgsqlCompletionParenthesisIsOpen(const OgsqlCompletionTokenT *tokens, uint32 tokenCount,
    uint32 leftParenthesis)
{
    uint32 depth = 0;

    for (uint32 i = leftParenthesis; i < tokenCount; i++) {
        if (tokens[i].kind == OGSQL_COMPLETION_TOKEN_LEFT_PAREN) {
            depth++;
        } else if (tokens[i].kind == OGSQL_COMPLETION_TOKEN_RIGHT_PAREN && depth > 0) {
            depth--;
            if (depth == 0) {
                return OG_FALSE;
            }
        }
    }
    return (depth > 0) ? OG_TRUE : OG_FALSE;
}

static void OgsqlParseCompletionSqlContext(const OgsqlCompletionRequestT *request,
    OgsqlCompletionSqlContextT *context)
{
    OgsqlCompletionTokenT tokens[OGSQL_MAX_COMPLETION_TOKENS];
    uint32 tokenCount;
    uint32 parenthesisDepth = 0;
    bool32 inSourceList = OG_FALSE;

    (void)memset_s(context, sizeof(*context), 0, sizeof(*context));
    tokenCount = OgsqlTokenizeCompletionSql(request->cmdBuf, request->tokenStart, tokens);
    for (uint32 i = 0; i < tokenCount;) {
        uint32 objectEnd = 0;

        if (tokens[i].kind == OGSQL_COMPLETION_TOKEN_LEFT_PAREN) {
            parenthesisDepth++;
            i++;
            continue;
        }
        if (tokens[i].kind == OGSQL_COMPLETION_TOKEN_RIGHT_PAREN) {
            if (parenthesisDepth > 0) {
                parenthesisDepth--;
            }
            i++;
            continue;
        }
        if (parenthesisDepth > 0) {
            i++;
            continue;
        }
        if (OgsqlCompletionTokenIsWord(&tokens[i], "insert") && i + 1 < tokenCount &&
            OgsqlCompletionTokenIsWord(&tokens[i + 1], "into")) {
            i = OgsqlParseCompletionSource(tokens, tokenCount, i + 2, context, &objectEnd);
            if (objectEnd < tokenCount && tokens[objectEnd].kind == OGSQL_COMPLETION_TOKEN_LEFT_PAREN &&
                OgsqlCompletionParenthesisIsOpen(tokens, tokenCount, objectEnd)) {
                context->insertColumnContext = OG_TRUE;
            }
            continue;
        }
        if (OgsqlCompletionTokenIsWord(&tokens[i], "update")) {
            i = OgsqlParseCompletionSource(tokens, tokenCount, i + 1, context, NULL);
            continue;
        }
        if (OgsqlCompletionTokenIsWord(&tokens[i], "from") || OgsqlCompletionTokenIsWord(&tokens[i], "join")) {
            inSourceList = OG_TRUE;
            i = OgsqlParseCompletionSource(tokens, tokenCount, i + 1, context, NULL);
            continue;
        }
        if (inSourceList == OG_TRUE && tokens[i].kind == OGSQL_COMPLETION_TOKEN_COMMA) {
            i = OgsqlParseCompletionSource(tokens, tokenCount, i + 1, context, NULL);
            continue;
        }
        if (OgsqlCompletionEndsSourceList(&tokens[i])) {
            inSourceList = OG_FALSE;
        }
        i++;
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

static void ogsql_collect_static_completion_matches(OgsqlCompletionCtxT ctx, const char *prefix,
    uint32 prefix_len, const ogsql_cmd_def_t *commandDefs, uint32 commandCount,
    const char **matches, uint32 *match_count)
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

static void OgsqlCollectCreateTableWordMatches(const char *prefix, uint32 prefixLen,
    const char **matches, uint32 *matchCount)
{
    if (prefixLen == 0) {
        return;
    }
    for (uint32 i = 0; i < OGSQL_CREATE_TABLE_COMPLETION_WORD_COUNT; i++) {
        if (ogsql_completion_word_matches(g_createTableCompletionWords[i], prefix, prefixLen)) {
            ogsql_add_completion_match(matches, matchCount, g_createTableCompletionWords[i]);
        }
    }
}

static bool32 OgsqlCompletionGetClientOptionMode(const OgsqlCompletionRequestT *request, bool32 *forSet)
{
    uint32 priorStart = 0;
    char priorWord[OGSQL_MAX_COMPLETION_WORD_LEN];
    char leadingWord[OGSQL_MAX_COMPLETION_WORD_LEN];

    if (request == NULL || forSet == NULL ||
        !ogsql_get_lower_completion_word_before(request->cmdBuf, request->tokenStart, priorWord,
        sizeof(priorWord), &priorStart)) {
        return OG_FALSE;
    }
    if (strcmp(priorWord, "set") != 0 && strcmp(priorWord, "show") != 0) {
        return OG_FALSE;
    }
    if (ogsql_get_lower_completion_word_before(request->cmdBuf, priorStart, leadingWord, sizeof(leadingWord), NULL)) {
        return OG_FALSE;
    }
    *forSet = (strcmp(priorWord, "set") == 0) ? OG_TRUE : OG_FALSE;
    return OG_TRUE;
}

static void ogsql_collect_option_matches(const char *prefix, uint32 prefixLen, bool32 forSet,
    const char **matches, uint32 *matchCount)
{
    uint32 optionCount = ogsql_option_count();

    for (uint32 i = 0; i < optionCount; i++) {
        const char *name = ogsql_option_name(i, forSet);

        if (name != NULL && ogsql_completion_word_matches(name, prefix, prefixLen)) {
            ogsql_add_completion_match(matches, matchCount, name);
        }
    }
}

static bool32 ogsql_completion_ctx_is_dynamic(OgsqlCompletionCtxT ctx)
{
    return (ctx == OGSQL_COMPLETION_CTX_TABLE || ctx == OGSQL_COMPLETION_CTX_COLUMN ||
        ctx == OGSQL_COMPLETION_CTX_INDEX || ctx == OGSQL_COMPLETION_CTX_PROCEDURE ||
        ctx == OGSQL_COMPLETION_CTX_SEQUENCE) ? OG_TRUE : OG_FALSE;
}

static bool32 OgsqlCompletionIsIndexNameContext(const OgsqlCompletionRequestT *request)
{
    return ogsql_completion_has_words_before(request, "index", "alter", NULL) ||
        ogsql_completion_has_words_before(request, "index", "drop", NULL) ||
        ogsql_completion_has_words_before(request, "index", "analyze", NULL);
}

static const OgsqlCompletionSourceT *OgsqlFindCompletionSource(const OgsqlCompletionSqlContextT *context,
    const char *qualifier, uint32 qualifierLen)
{
    char qualifierBuf[OGSQL_OBJ_NAME_LEN];

    if (qualifier == NULL ||
        OgsqlCopyCompletionToken(qualifier, qualifierLen, qualifierBuf, sizeof(qualifierBuf)) != OG_SUCCESS) {
        return NULL;
    }
    for (uint32 i = 0; i < context->sourceCount; i++) {
        const OgsqlCompletionSourceT *source = &context->sources[i];

        if ((source->alias[0] != '\0' && ogsql_completion_word_equal(source->alias, qualifierBuf)) ||
            ogsql_completion_word_equal(source->table, qualifierBuf)) {
            return source;
        }
    }
    return NULL;
}

static status_t OgsqlAppendColumnSourceSql(char *sqlBuf, uint32 sqlBufSize,
    const OgsqlCompletionSourceT *source, const char *prefix, uint32 prefixLen, bool32 addUnion)
{
    char fragment[512];
    int ret;
    errno_t rc;

    if (source->schema[0] == '\0') {
        if (prefixLen == 0) {
            ret = snprintf_s(fragment, sizeof(fragment), sizeof(fragment) - 1,
                "%sSELECT COLUMN_NAME FROM SYS.MY_TAB_COLUMNS WHERE UPPER(TABLE_NAME) = UPPER('%s') ",
                addUnion == OG_TRUE ? "UNION " : "", source->table);
        } else {
            ret = snprintf_s(fragment, sizeof(fragment), sizeof(fragment) - 1,
                "%sSELECT COLUMN_NAME FROM SYS.MY_TAB_COLUMNS WHERE UPPER(TABLE_NAME) = UPPER('%s') "
                "AND SUBSTR(UPPER(COLUMN_NAME), 1, %u) = UPPER('%s') ",
                addUnion == OG_TRUE ? "UNION " : "", source->table, prefixLen, prefix);
        }
    } else {
        if (prefixLen == 0) {
            ret = snprintf_s(fragment, sizeof(fragment), sizeof(fragment) - 1,
                "%sSELECT COLUMN_NAME FROM SYS.DB_TAB_COLUMNS WHERE UPPER(OWNER) = UPPER('%s') "
                "AND UPPER(TABLE_NAME) = UPPER('%s') ",
                addUnion == OG_TRUE ? "UNION " : "", source->schema, source->table);
        } else {
            ret = snprintf_s(fragment, sizeof(fragment), sizeof(fragment) - 1,
                "%sSELECT COLUMN_NAME FROM SYS.DB_TAB_COLUMNS WHERE UPPER(OWNER) = UPPER('%s') "
                "AND UPPER(TABLE_NAME) = UPPER('%s') "
                "AND SUBSTR(UPPER(COLUMN_NAME), 1, %u) = UPPER('%s') ",
                addUnion == OG_TRUE ? "UNION " : "", source->schema, source->table, prefixLen, prefix);
        }
    }
    if (ret < 0) {
        return OG_ERROR;
    }
    rc = strcat_s(sqlBuf, sqlBufSize, fragment);
    return (rc == EOK) ? OG_SUCCESS : OG_ERROR;
}

static status_t OgsqlCollectColumnMatches(const OgsqlCompletionSqlContextT *context,
    const OgsqlCompletionSourceT *qualifiedSource, const char *prefix, uint32 prefixLen,
    OgsqlCompletionStoreT *store)
{
    char prefixBuf[OGSQL_OBJ_NAME_LEN];
    char sqlBuf[OGSQL_MAX_TEMP_SQL + 1] = { 0 };
    bool32 addUnion = OG_FALSE;

    if (OgsqlCopyCompletionToken(prefix, prefixLen, prefixBuf, sizeof(prefixBuf)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < context->sourceCount; i++) {
        const OgsqlCompletionSourceT *source = &context->sources[i];

        if (qualifiedSource != NULL && source != qualifiedSource) {
            continue;
        }
        if (OgsqlAppendColumnSourceSql(sqlBuf, sizeof(sqlBuf), source, prefixBuf, prefixLen,
            addUnion) != OG_SUCCESS) {
            return OG_ERROR;
        }
        addUnion = OG_TRUE;
    }
    if (addUnion == OG_FALSE || strcat_s(sqlBuf, sizeof(sqlBuf), "ORDER BY 1") != EOK) {
        return OG_ERROR;
    }
    return OgsqlQueryCompletionMatches(sqlBuf, prefix, prefixLen, store);
}

static status_t OgsqlCollectDynamicMatches(OgsqlCompletionCtxT ctx, const char *prefix, uint32 prefixLen,
    const OgsqlCompletionSqlContextT *sqlContext, const OgsqlCompletionSourceT *qualifiedSource,
    OgsqlCompletionStoreT *store)
{
    char prefixBuf[OGSQL_OBJ_NAME_LEN];
    char sql[OGSQL_MAX_TEMP_SQL + 1];
    int ret;

    if (ctx == OGSQL_COMPLETION_CTX_COLUMN) {
        return OgsqlCollectColumnMatches(sqlContext, qualifiedSource, prefix, prefixLen, store);
    }
    if (OgsqlCopyCompletionToken(prefix, prefixLen, prefixBuf, sizeof(prefixBuf)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch (ctx) {
        case OGSQL_COMPLETION_CTX_TABLE:
            if (prefixLen == 0) {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT TABLE_NAME FROM SYS.MY_TABLES UNION SELECT VIEW_NAME FROM SYS.MY_VIEWS ORDER BY 1");
            } else {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT TABLE_NAME FROM SYS.MY_TABLES "
                    "WHERE SUBSTR(UPPER(TABLE_NAME), 1, %u) = UPPER('%s') "
                    "UNION SELECT VIEW_NAME FROM SYS.MY_VIEWS "
                    "WHERE SUBSTR(UPPER(VIEW_NAME), 1, %u) = UPPER('%s') ORDER BY 1",
                    prefixLen, prefixBuf, prefixLen, prefixBuf);
            }
            break;
        case OGSQL_COMPLETION_CTX_INDEX:
            if (prefixLen == 0) {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT INDEX_NAME FROM SYS.MY_INDEXES ORDER BY 1");
            } else {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT INDEX_NAME FROM SYS.MY_INDEXES "
                    "WHERE SUBSTR(UPPER(INDEX_NAME), 1, %u) = UPPER('%s') ORDER BY 1",
                    prefixLen, prefixBuf);
            }
            break;
        case OGSQL_COMPLETION_CTX_PROCEDURE:
            if (prefixLen == 0) {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES "
                    "WHERE OBJECT_TYPE IN ('PROCEDURE', 'FUNCTION') ORDER BY 1");
            } else {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES WHERE OBJECT_TYPE IN ('PROCEDURE', 'FUNCTION') "
                    "AND SUBSTR(UPPER(OBJECT_NAME), 1, %u) = UPPER('%s') ORDER BY 1", prefixLen, prefixBuf);
            }
            break;
        case OGSQL_COMPLETION_CTX_SEQUENCE:
            if (prefixLen == 0) {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT SEQUENCE_NAME FROM SYS.MY_SEQUENCES ORDER BY 1");
            } else {
                ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
                    "SELECT SEQUENCE_NAME FROM SYS.MY_SEQUENCES "
                    "WHERE SUBSTR(UPPER(SEQUENCE_NAME), 1, %u) = UPPER('%s') ORDER BY 1", prefixLen, prefixBuf);
            }
            break;
        case OGSQL_COMPLETION_CTX_COLUMN:
        case OGSQL_COMPLETION_CTX_DEFAULT:
        case OGSQL_COMPLETION_CTX_SCHEMA_TABLE:
        default:
            return OG_ERROR;
    }
    if (ret < 0) {
        return OG_ERROR;
    }
    return OgsqlQueryCompletionMatches(sql, prefix, prefixLen, store);
}

static void OgsqlCollectExpressionObjectMatches(const char *prefix, uint32 prefixLen,
    OgsqlCompletionStoreT *store)
{
    char prefixBuf[OGSQL_OBJ_NAME_LEN];
    char sql[OGSQL_MAX_TEMP_SQL + 1];
    int ret;

    if (prefixLen == 0 ||
        OgsqlCopyCompletionToken(prefix, prefixLen, prefixBuf, sizeof(prefixBuf)) != OG_SUCCESS) {
        return;
    }
    ret = snprintf_s(sql, sizeof(sql), sizeof(sql) - 1,
        "SELECT OBJECT_NAME FROM SYS.MY_PROCEDURES WHERE OBJECT_TYPE = 'FUNCTION' "
        "AND SUBSTR(UPPER(OBJECT_NAME), 1, %u) = UPPER('%s') "
        "UNION SELECT SEQUENCE_NAME FROM SYS.MY_SEQUENCES "
        "WHERE SUBSTR(UPPER(SEQUENCE_NAME), 1, %u) = UPPER('%s') ORDER BY 1",
        prefixLen, prefixBuf, prefixLen, prefixBuf);
    if (ret >= 0) {
        (void)OgsqlQueryCompletionMatches(sql, prefix, prefixLen, store);
    }
}

uint32 ogsql_completion_collect(const OgsqlCompletionRequestT *request, OgsqlCompletionStoreT *store)
{
    OgsqlCompletionCtxT ctx;
    OgsqlCompletionSqlContextT sqlContext;
    const OgsqlCompletionSourceT *qualifiedSource = NULL;
    OgsqlSchemaCompletionRequestT schemaRequest;
    uint32 schema_start = 0;
    uint32 schema_len = 0;
    bool32 hasDotPrefix = OG_FALSE;
    bool32 forSet = OG_FALSE;

    if (request == NULL || store == NULL || store->matchCount == NULL || store->dynamicCount == NULL) {
        return 0;
    }
    *store->matchCount = 0;
    *store->dynamicCount = 0;
    hasDotPrefix = ogsql_get_completion_schema_prefix(request->cmdBuf, request->tokenStart,
        &schema_start, &schema_len);

    if (OgsqlCompletionGetClientOptionMode(request, &forSet)) {
        ogsql_collect_option_matches(request->prefix, request->prefixLen, forSet, store->matches,
            store->matchCount);
        return *store->matchCount;
    }

    ctx = OgsqlClassifyCompletionContext(request->cmdBuf, request->cursorPos, request->prefixLen > 0);
    if (OgsqlCompletionIsIndexNameContext(request)) {
        ctx = OGSQL_COMPLETION_CTX_INDEX;
    }
    OgsqlParseCompletionSqlContext(request, &sqlContext);
    if (sqlContext.insertColumnContext == OG_TRUE) {
        ctx = OGSQL_COMPLETION_CTX_COLUMN;
    }
    if (OgsqlCompletionIsCreateTableDefinitionContext(request)) {
        OgsqlCollectCreateTableWordMatches(request->prefix, request->prefixLen, store->matches,
            store->matchCount);
        if (*store->matchCount > 0) {
            return *store->matchCount;
        }
    }
    if (hasDotPrefix == OG_TRUE) {
        qualifiedSource = OgsqlFindCompletionSource(&sqlContext, request->cmdBuf + schema_start, schema_len);
        if (qualifiedSource == NULL) {
            if (ctx != OGSQL_COMPLETION_CTX_TABLE) {
                return 0;
            }
            schemaRequest = (OgsqlSchemaCompletionRequestT){ request->cmdBuf + schema_start, schema_len,
                request->prefix, request->prefixLen };
            (void)OgsqlCollectSchemaTableMatches(&schemaRequest, store);
            return *store->matchCount;
        }
        ctx = OGSQL_COMPLETION_CTX_COLUMN;
    }
    if (request->prefixLen == 0 && ctx == OGSQL_COMPLETION_CTX_DEFAULT) {
        return 0;
    }

    if (ogsql_completion_ctx_allows_sql_words(ctx)) {
        ogsql_collect_preferred_keyword_matches(request, store->matches, store->matchCount);
        ogsql_collect_issue289_keyword_matches(request, store->matches, store->matchCount);
        if (*store->matchCount > 0) {
            return *store->matchCount;
        }
    }

    if (ogsql_completion_ctx_is_dynamic(ctx) == OG_TRUE &&
        OgsqlCollectDynamicMatches(ctx, request->prefix, request->prefixLen, &sqlContext,
        qualifiedSource, store) == OG_SUCCESS && *store->matchCount > 0) {
        return *store->matchCount;
    }

    *store->matchCount = 0;
    ogsql_collect_static_completion_matches(ctx, request->prefix, request->prefixLen,
        request->commandDefs, request->commandCount, store->matches, store->matchCount);
    if (ctx == OGSQL_COMPLETION_CTX_COLUMN || ctx == OGSQL_COMPLETION_CTX_DEFAULT) {
        OgsqlCollectExpressionObjectMatches(request->prefix, request->prefixLen, store);
    }
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
