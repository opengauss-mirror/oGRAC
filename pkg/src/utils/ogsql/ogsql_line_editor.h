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
 * ogsql_line_editor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_LINE_EDITOR_H
#define OGSQL_LINE_EDITOR_H

#include "ogsql.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OgsqlRenderCtxT {
    const char *welcomeBuf;
    uint32 welcomeWidth;
    uint32 wsCol;
    const bool8 *endspace;
} OgsqlRenderCtxT;

typedef struct OgsqlLineEditStateT {
    char *cmdBuf;
    uint32 maxLen;
    uint32 nbytes;
    uint32 nwidths;
    uint32 cursorPos;
    uint32 cursorWidth;
    uint32 spacenum;
    bool8 *endspace;
} OgsqlLineEditStateT;

typedef enum EnOgsqlReadlineResultT {
    OGSQL_READLINE_RESULT_OK,
    OGSQL_READLINE_RESULT_STOP,
    OGSQL_READLINE_RESULT_FALLBACK
} OgsqlReadlineResultT;

typedef struct OgsqlReadlineCtxT {
    int *histCount;
    int *listNum;
    bool32 allowAbortLine;
    uint32 preloadLen;
    bool32 *abortLine;
    uint32 *acceptedInputLen;
    uint32 *acceptedRenderRows;
    const ogsql_cmd_def_t *commandDefs;
    uint32 commandCount;
} OgsqlReadlineCtxT;

static inline OgsqlRenderCtxT OgsqlMakeRenderCtx(const char *welcomeBuf, uint32 welcomeWidth, uint32 wsCol,
    const bool8 *endspace)
{
    OgsqlRenderCtxT ctx = { welcomeBuf, welcomeWidth, wsCol, endspace };

    return ctx;
}

uint32 ogsql_text_display_width(const char *text, uint32 len);
void ogsql_clear_previous_input_line(char *cmdBuf, uint32 nbytes, uint32 promptWidth, uint32 lineWidth,
    uint32 recordedRows);
OgsqlReadlineResultT ogsql_line_editor_read(OgsqlLineEditStateT *state, OgsqlRenderCtxT *baseRenderCtx,
    OgsqlReadlineCtxT *readlineCtx);
bool32 ogsql_line_editor_should_use(FILE *in, bool32 isFile);

#ifdef __cplusplus
}
#endif

#endif
