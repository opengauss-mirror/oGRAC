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
 * ogsql_completion.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_COMPLETION_H
#define OGSQL_COMPLETION_H

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OgsqlCompletionStoreT {
    const char **matches;
    uint32 *matchCount;
    char (*dynamicWords)[OGSQL_OBJ_NAME_LEN];
    uint32 *dynamicCount;
} OgsqlCompletionStoreT;

typedef struct OgsqlCompletionRequestT {
    const char *cmdBuf;
    uint32 cursorPos;
    uint32 tokenStart;
    const char *prefix;
    uint32 prefixLen;
    const ogsql_cmd_def_t *commandDefs;
    uint32 commandCount;
} OgsqlCompletionRequestT;

status_t ogsql_completion_find_token(char *cmdBuf, uint32 cursorPos, uint32 *tokenStart, uint32 *tokenLen);
uint32 ogsql_completion_collect(const OgsqlCompletionRequestT *request, OgsqlCompletionStoreT *store);
uint32 ogsql_completion_common_prefix(const char **matches, uint32 matchCount, char *common, uint32 commonSize);
uint32 ogsql_completion_make_suffix(const char *word, const char *token, uint32 tokenLen, char *suffix,
    uint32 suffixSize);

#ifdef __cplusplus
}
#endif

#endif
