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
 * ogsql_history.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_HISTORY_H
#define OGSQL_HISTORY_H

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OgsqlPendingHistoryT {
    char buf[OGSQL_HISTORY_BUF_SIZE];
    uint32 len;
    bool32 overflow;
} OgsqlPendingHistoryT;

uint32 ogsql_history_text_limit(void);
void ogsql_history_reset(void);
status_t ogsql_history_save_draft(const char *text, uint32 nbytes, uint32 nwidths);
const ogsql_cmd_history_list_t *ogsql_history_get_draft(void);
const ogsql_cmd_history_list_t *ogsql_history_get(int histCount, uint32 logicalIndex);
bool32 ogsql_history_find_ranked(int histCount, const char *query, uint32 queryLen, uint32 afterIndex,
    uint32 *matchIndex);

void ogsql_history_pending_reset(OgsqlPendingHistoryT *pending);
void ogsql_history_pending_append(OgsqlPendingHistoryT *pending, const char *line, uint32 lineLen);
void ogsql_history_pending_restore(OgsqlPendingHistoryT *pending, uint32 len, bool32 overflow);
void ogsql_history_pending_commit(OgsqlPendingHistoryT *pending, int *histCount, uint32 displayWidth);

#ifdef __cplusplus
}
#endif

#endif
