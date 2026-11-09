/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * openGauss is licensed under Mulan PSL v2.
 * See http://license.coscl.org.cn/MulanPSL2 for the license terms.
 */
#ifndef BISON_SYNTAX_ERROR_H
#define BISON_SYNTAX_ERROR_H

#include "cm_defs.h"

#define BISON_DIAG_TOKEN_SIZE 64
#define BISON_DIAG_MESSAGE_SIZE 512
#define BISON_DIAG_MAX_EXPECTED 4

typedef struct st_bison_keyword_name {
    const char *symbol;
    const char *keyword;
} bison_keyword_name_t;

static const bison_keyword_name_t g_bison_diag_aliases[] = {
    {"$end", "end of input"}, {"end of file", "end of input"},
    {"\"end of file\"", "end of input"},
    {"IDENT", "identifier"}, {"T_WORD", "identifier"}, {"T_DATUM", "variable"},
    {"BEGIN_NON_ANOYBLOCK", "BEGIN"},
    {"ICONST", "number"}, {"I64CONST", "number"}, {"FCONST", "number"},
    {"FCONST_F", "number"}, {"FCONST_D", "number"},
    {"SCONST", "string"}, {"XCONST", "hexadecimal string"}, {"PARAM", "parameter"},
    {"Op", "operator"}, {"CmpOp", "comparison operator"},
    {"TYPECAST", "'::'"}, {"ORA_JOINOP", "'(+)'"}, {"DOT_DOT", "'..'"},
    {"COLON_EQUALS", "':='"}, {"PARA_EQUALS", "'=>'"},
    {"OPER_CAT", "'||'"}, {"OPER_LSHIFT", "'<<'"}, {"OPER_RSHIFT", "'>>'"},
    {"WITH_TIME", "WITH"}, {"WITH_LOCAL", "WITH"},
    {"WITHOUT_TIME", "WITHOUT"}, {"WITHOUT_LOCAL", "WITHOUT"},
    {"PIVOT_TOK", "PIVOT"}, {"UNPIVOT_TOK", "UNPIVOT"},
    {"UNPIVOT_INC", "UNPIVOT"}, {"UNPIVOT_EXC", "UNPIVOT"},
    {"CONNECT_BY", "CONNECT BY"}, {"START_WITH", "START WITH"},
    {"CONNECT_BY_ROOT", "CONNECT_BY_ROOT"},
    {"PARTITION_FOR", "PARTITION"}, {"SUBPARTITION_FOR", "SUBPARTITION"},
    {"ORDER_SIBLINGS", "ORDER SIBLINGS"}, {"ABSENT_ON", "ABSENT"},
    {"INNER_JOIN", "INNER JOIN"}, {"JOIN_KEY", "JOIN"}, {"LEFT_KEY", "LEFT"},
    {"RIGHT_KEY", "RIGHT"}, {"FULL_KEY", "FULL"}, {"CROSS_JOIN", "CROSS JOIN"},
    {"PRIMARY_KEY", "PRIMARY KEY"}, {"FOREIGN_KEY", "FOREIGN KEY"},
    {"EXECUTE_ON_DIRECTORY", "EXECUTE"}, {"EXECUTE_KEY", "EXECUTE"},
    {"READ_ON_DIRECTORY", "READ"}, {"READ_KEY", "READ"},
    {"NULLS_FIRST", "NULLS FIRST"}, {"NULLS_LAST", "NULLS LAST"},
    {"OVER_ALIAS", "OVER"}, {"WITHIN_ALIAS", "WITHIN"},
    {"ERROR_ON_EMPTY", "ERROR ON EMPTY"}, {"ERROR_ON_ERROR_P", "ERROR ON ERROR"},
    {"NULL_ON_EMPTY", "NULL ON EMPTY"}, {"NULL_ON_ERROR_P", "NULL ON ERROR"},
    {"EMPTY_ON_EMPTY", "EMPTY ON EMPTY"}, {"EMPTY_ON_ERROR_P", "EMPTY ON ERROR"},
    {"EMPTY_ARRAY_ON_EMPTY", "EMPTY ARRAY ON EMPTY"},
    {"EMPTY_ARRAY_ON_ERROR_P", "EMPTY ARRAY ON ERROR"},
    {"EMPTY_OBJECT_P_ON_EMPTY", "EMPTY OBJECT ON EMPTY"},
    {"EMPTY_OBJECT_P_ON_ERROR_P", "EMPTY OBJECT ON ERROR"},
    {"ALTER_SYSTEM_VALUE", "parameter value"}, {"SET_IDENT", "identifier"},
    {"SET_USER_IDENT", "identifier"}, {"COMMENTSTRING", "comment"},
    {"SET_IDENT_SESSION", "SESSION"}, {"SET_IDENT_GLOBAL", "GLOBAL"},
    {"UNDERSCORE_CHARSET", "character set"},
    {"SIZE_B", "B"}, {"SIZE_KB", "K"}, {"SIZE_MB", "M"}, {"SIZE_GB", "G"},
    {"SIZE_TB", "T"}, {"SIZE_PB", "P"}, {"SIZE_EB", "E"}
};

static const char *bison_diag_find_name(const char *symbol, const bison_keyword_name_t *names, uint32 count)
{
    for (uint32 i = 0; i < count; i++) {
        if (strcmp(symbol, names[i].symbol) == 0) {
            return names[i].keyword;
        }
    }
    return NULL;
}

static bool32 bison_diag_copy_label(const char *name, bool32 uppercase, char label[BISON_DIAG_TOKEN_SIZE])
{
    if (name == NULL || strlen(name) >= BISON_DIAG_TOKEN_SIZE) {
        return OG_FALSE;
    }
    uint32 i = 0;
    for (; name[i] != '\0'; i++) {
        char ch = name[i];
        label[i] = uppercase && ch >= 'a' && ch <= 'z' ? ch - 'a' + 'A' : ch;
    }
    label[i] = '\0';
    return OG_TRUE;
}

/* Only grammar symbols are used here, never user supplied token contents. */
static bool32 bison_diag_token_label(const char *symbol,
    const bison_keyword_name_t *keywords, uint32 keyword_count, char label[BISON_DIAG_TOKEN_SIZE])
{
    if (symbol == NULL) {
        return OG_FALSE;
    }
    /* Internal grammar aliases may also appear in a generated keyword table. */
    const char *name = bison_diag_find_name(symbol, g_bison_diag_aliases, ELEMENT_COUNT(g_bison_diag_aliases));
    bool32 uppercase = OG_FALSE;
    if (name == NULL) {
        name = bison_diag_find_name(symbol, keywords, keyword_count);
        uppercase = OG_TRUE;
    }
    if (name == NULL && symbol[0] == '\'') {
        name = symbol;
        uppercase = OG_FALSE;
    }
    /* Unmapped symbols are internal sentinels or precedence-only tokens. */
    return bison_diag_copy_label(name, uppercase, label);
}

static inline void bison_diag_append(char message[BISON_DIAG_MESSAGE_SIZE], const char *text)
{
    uint32 used = (uint32)strlen(message);
    while (*text != '\0' && used + 1 < BISON_DIAG_MESSAGE_SIZE) {
        message[used++] = *text++;
    }
    message[used] = '\0';
}

static void bison_diag_message(char message[BISON_DIAG_MESSAGE_SIZE], const char *unexpected,
    const char *const *expected, uint32 expected_count)
{
    message[0] = '\0';
    /* ERR_SQL_SYNTAX_ERROR supplies the syntax-error prefix. */
    if (expected_count == 0) {
        bison_diag_append(message, "unexpected ");
        bison_diag_append(message, unexpected == NULL ? "token" : unexpected);
        return;
    }
    /* Five labels of at most 63 bytes plus separators fit in this buffer. */
    for (uint32 i = 0; i < expected_count && i < BISON_DIAG_MAX_EXPECTED; i++) {
        if (i != 0) {
            bison_diag_append(message, " or ");
        }
        bison_diag_append(message, expected[i]);
    }
    bison_diag_append(message, " expected but ");
    bison_diag_append(message, unexpected == NULL ? "token" : unexpected);
    bison_diag_append(message, " found");
}

#endif
