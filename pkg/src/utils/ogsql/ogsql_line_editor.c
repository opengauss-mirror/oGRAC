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
 * ogsql_line_editor.c
 *
 * -------------------------------------------------------------------------
 */
#include <errno.h>
#include <wchar.h>
#include "ogsql_common.h"
#include "ogsql_completion.h"
#include "ogsql_history.h"
#include "ogsql_line_editor.h"

#ifdef WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#define OGSQL_WIDE_CHAR_WIDTH 2
#define OGSQL_ANSI_SEQ_LEN 3
#define OGSQL_ANSI_CLEAR_SEQ_LEN 4
#define OGSQL_TERMINAL_WRAP_HINT_LEN 2
#define OGSQL_TERMINAL_CRLF_LEN 2
#define OGSQL_DEFAULT_TERMINAL_COLUMNS 80
#define OGSQL_MSEC_PER_SEC 1000
#define OGSQL_USEC_PER_MSEC 1000
#define OGSQL_SELECT_RETRY_TIMEOUT_MS 200
#define OGSQL_CLEAR_SCREEN_SEQ_LEN 7
#define OGSQL_COMPLETION_COLUMN_COUNT 4
#define OGSQL_COMPLETION_INDENT_LEN 4
#define OGSQL_REVERSE_RENDER_BUF_FACTOR 2
#define OGSQL_CURSOR_MOVE_BUF_SIZE 64

typedef struct OgsqlRenderPositionT {
    uint32 row;
    uint32 col;
} OgsqlRenderPositionT;

typedef struct OgsqlEndspaceRequestT {
    const char *text;
    uint32 nbytes;
    uint32 *spacenum;
    bool8 *endspace;
} OgsqlEndspaceRequestT;

typedef struct OgsqlCursorT {
    uint32 pos;
    uint32 width;
} OgsqlCursorT;

typedef struct OgsqlCompletionPrintCtxT {
    const char **matches;
    uint32 matchCount;
    OgsqlLineEditStateT *state;
    const OgsqlRenderCtxT *renderCtx;
    uint32 *displayBaseRows;
} OgsqlCompletionPrintCtxT;

typedef struct OgsqlCompletionRedrawCtxT {
    OgsqlCursorT oldCursor;
    uint32 oldNwidths;
    uint32 oldRow;
} OgsqlCompletionRedrawCtxT;

typedef struct OgsqlCompletionRowsT {
    uint32 wsCol;
    uint32 row;
    uint32 col;
    uint32 maxRow;
} OgsqlCompletionRowsT;

typedef struct OgsqlReverseRenderRequestT {
    const char *query;
    uint32 queryLen;
    const ogsql_cmd_history_list_t *match;
    bool32 failed;
} OgsqlReverseRenderRequestT;

typedef struct OgsqlReverseSearchStateT {
    int histCount;
    int *listNum;
    int originalListNum;
    char *query;
    uint32 queryLen;
    uint32 currentMatch;
    bool32 failed;
    OgsqlLineEditStateT *lineState;
    const OgsqlRenderCtxT *renderCtx;
    OgsqlLineEditStateT *displayState;
    const OgsqlLineEditStateT *originalState;
} OgsqlReverseSearchStateT;

typedef struct OgsqlReadlineLoopT {
    int *histCount;
    int *listNum;
    char *cmdBuf;
    uint32 maxLen;
    const char *welcomeBuf;
    uint32 welcomeWidth;
    uint32 *wsCol;
    uint32 *nbytes;
    uint32 *nwidths;
    uint32 *cursorPos;
    uint32 *cursorWidth;
    uint32 *spacenum;
    bool8 *endspace;
    uint32 *displayBaseRows;
    bool32 allowAbortLine;
    bool32 *lineAborted;
    OgsqlReadlineResultT *readResult;
    char *chr;
    uint32 *cursorRenderTotal;
    bool32 *cursorRenderTotalValid;
    const ogsql_cmd_def_t *commandDefs;
    uint32 commandCount;
} OgsqlReadlineLoopT;

typedef struct OgsqlReadlineSessionT {
    OgsqlLineEditStateT *state;
    OgsqlRenderCtxT *baseRenderCtx;
    OgsqlReadlineCtxT *readlineCtx;
    int32 keyChar;
    uint32 nbytes;
    uint32 nwidths;
    uint32 spacenum;
    bool8 endspace[OGSQL_HISTORY_BUF_SIZE];
    char chr[OGSQL_UTF8_CHR_SIZE];
    uint32 wsCol;
    uint32 cursorPos;
    uint32 cursorWidth;
    uint32 cursorRenderTotal;
    uint32 displayBaseRows;
    bool32 lineAborted;
    bool32 cursorRenderTotalValid;
    OgsqlReadlineResultT readResult;
    OgsqlRenderCtxT renderCtx;
    OgsqlLineEditStateT editState;
    OgsqlReadlineLoopT loop;
#ifndef WIN32
    struct termios oldt;
    bool32 terminalRawEnabled;
#endif
} OgsqlReadlineSessionT;
static uint32 ogsql_utf8_chr_widths(char *chr, uint32 c_bytes)
{
    wchar_t wchr = 0;
    uint32 c_widths = 0;
    if (mbtowc(&wchr, chr, c_bytes) <= 0) {
        return OG_INVALID_ID32;
    }
#ifndef WIN32
    c_widths = (uint32)wcwidth(wchr);
#endif
    return c_widths;
}

static void ogsql_terminal_write(uint32 len, const char *buf)
{
    (void)fwrite(buf, 1, len, stdout);
    (void)fflush(stdout);
}

/* Compute the cumulative number of padding spaces added before the cursor position.
   When a CJK character (width 2) would land on the last column of a physical line,
   a padding space is inserted to push it to the next line (spacenum++). These
   padding spaces occupy physical columns but are NOT counted in cursor_width,
   so the physical column of the cursor is:
       (cursor_width + welcome_width + acc_spacenum) % ws_col
   The previous term_col calculation omitted acc_spacenum, causing the cursor to
   drift by 1 column per padding line. With N padding lines, the drift accumulates
   to N columns (e.g. 4 padding lines -> 4 columns drift, matching W-03 symptom). */
static uint32 ogsql_acc_spacenum_at(uint32 cursor_width, uint32 welcome_width, uint32 ws_col, const bool8 *endspace)
{
    uint32 acc = 0;
    uint32 pos;
    uint32 line;

    if (ws_col == 0) {
        return 0;
    }
    pos = cursor_width + welcome_width;
    line = 1;
    while (pos >= ws_col) {
        if (endspace != NULL && line < OGSQL_HISTORY_BUF_SIZE && endspace[line]) {
            acc++;
            pos++;
        }
        pos -= ws_col;
        line++;
    }
    return acc;
}

static void ogsql_cmd_move_left(uint32 widths, uint32 cursor_width, uint32 welcome_width, uint32 ws_col,
    const bool8 *endspace)
{
    while (widths > 0) {
        uint32 acc_space = ogsql_acc_spacenum_at(cursor_width, welcome_width, ws_col, endspace);
        uint32 term_col = (ws_col > 0) ? ((cursor_width + welcome_width + acc_space) % ws_col) : 1;
        if (ws_col > 0 && term_col == 0 && cursor_width > 0) {
            /* Cursor is at the start of a wrapped line. \b does not wrap to the
               previous line, so use \r (carriage return) + \033[A (cursor up) +
               move right to the last column of the previous physical line.
               If the previous line has a padding space (endspace[line-1]==TRUE),
               the last content character is at col ws_col-2 (the padding space
               occupies col ws_col-1), so move to ws_col-2 instead of ws_col-1. */
            uint32 prev_line = (cursor_width + welcome_width + acc_space) / ws_col;
            uint32 target_col = (ws_col > 1) ? (ws_col - 1) : 0;
            uint32 i;
            if (endspace != NULL && prev_line >= 1 && prev_line < OGSQL_HISTORY_BUF_SIZE && endspace[prev_line]) {
                target_col = (target_col > 0) ? (target_col - 1) : 0;
            }
            ogsql_terminal_write(1, "\r");
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[A");
            for (i = 0; i < target_col; i++) {
                ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[C");
            }
        } else {
            ogsql_terminal_write(1, "\b");
        }
        cursor_width--;
        widths--;
    }
}

static void ogsql_cmd_move_right(uint32 widths, uint32 cursor_width, uint32 welcome_width, uint32 ws_col,
    const bool8 *endspace)
{
    const char ansiRight[] = "\033[C";
    while (widths > 0) {
        uint32 acc_space = ogsql_acc_spacenum_at(cursor_width, welcome_width, ws_col, endspace);
        uint32 term_col = (ws_col > 0) ? ((cursor_width + welcome_width + acc_space) % ws_col) : 0;
        if (ws_col > 0 && term_col == ws_col - 1) {
            /* Cursor is at the last terminal column (pending-wrap state).
               \033[C does not wrap at line end, so use \r\n to move to the next line. */
            ogsql_terminal_write(OGSQL_TERMINAL_CRLF_LEN, "\r\n");
        } else {
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, ansiRight);
        }
        cursor_width++;
        widths--;
    }
}

static void ogsql_cmd_write_spaces(uint32 widths)
{
    while (widths--) {
        ogsql_terminal_write(1, " ");
    }
}

static void OgsqlWriteWrappedText(const char *text, uint32 len, uint32 startTotal,
    const OgsqlRenderCtxT *renderCtx)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 total = startTotal;

    if (len == 0 || renderCtx == NULL) {
        return;
    }
    if (renderCtx->wsCol == 0) {
        ogsql_terminal_write(len, text);
        return;
    }

    while (offset < len) {
        if (text[offset] == '\n') {
            ogsql_terminal_write(OGSQL_TERMINAL_CRLF_LEN, "\r\n");
            total = (total / renderCtx->wsCol + 1) * renderCtx->wsCol + renderCtx->welcomeWidth;
            ogsql_cmd_write_spaces(renderCtx->welcomeWidth);
            offset++;
            continue;
        }
        if (cm_utf8_chr_bytes((uint8)text[offset], &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
            offset + c_bytes > len || c_bytes > OGSQL_UTF8_CHR_SIZE) {
            c_bytes = 1;
            c_widths = 1;
        } else {
            c_widths = ogsql_utf8_chr_widths((char *)text + offset, c_bytes);
            if (c_widths == OG_INVALID_ID32) {
                c_bytes = 1;
                c_widths = 1;
            }
        }

        if (c_widths == OGSQL_WIDE_CHAR_WIDTH && total % renderCtx->wsCol == renderCtx->wsCol - 1) {
            ogsql_terminal_write(1, " ");
            total++;
        }

        ogsql_terminal_write(c_bytes, text + offset);
        total += c_widths;
        offset += c_bytes;

        if (total > 0 && total % renderCtx->wsCol == 0) {
            ogsql_terminal_write(OGSQL_TERMINAL_WRAP_HINT_LEN, " \b");
        }
    }
}

static status_t ogsql_get_prev_char(char *cmdBuf, uint32 cursor_pos, uint32 *c_bytes, uint32 *c_widths)
{
    uint32 pos;
    uint32 expected_bytes = 0;

    if (cursor_pos == 0) {
        return OG_ERROR;
    }
    if (cmdBuf[cursor_pos - 1] == '\n') {
        *c_bytes = 1;
        *c_widths = 0;
        return OG_SUCCESS;
    }

    pos = cursor_pos - 1;
    while (pos > 0 && IS_VALID_UTF8_CHAR((uint8)cmdBuf[pos])) {
        pos--;
    }

    *c_bytes = cursor_pos - pos;
    if (*c_bytes == 0 || *c_bytes > OGSQL_UTF8_CHR_SIZE ||
        cm_utf8_chr_bytes((uint8)cmdBuf[pos], &expected_bytes) != OG_SUCCESS ||
        expected_bytes != *c_bytes) {
        return OG_ERROR;
    }

    *c_widths = ogsql_utf8_chr_widths(cmdBuf + pos, *c_bytes);
    return (*c_widths == OG_INVALID_ID32) ? OG_ERROR : OG_SUCCESS;
}

static void ogsql_cmd_clean_line(uint32 line_widths)
{
    uint32 line_wid = line_widths;
    while (line_wid--) {
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\b \b");
    }
}

/* Calculate the position and total number of spaces used to space at the end of a line. */
static void OgsqlSetEndspaceByText(const OgsqlEndspaceRequestT *request, const OgsqlRenderCtxT *renderCtx)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 space_num = 0;
    uint32 total;

    if (request == NULL || request->spacenum == NULL || request->endspace == NULL) {
        return;
    }
    if (renderCtx == NULL || renderCtx->wsCol == 0) {
        *request->spacenum = 0;
        OGSQL_CHECK_MEMS_SECURE(memset_s(request->endspace, OGSQL_HISTORY_BUF_SIZE, 0, OGSQL_HISTORY_BUF_SIZE));
        return;
    }
    OGSQL_CHECK_MEMS_SECURE(memset_s(request->endspace, OGSQL_HISTORY_BUF_SIZE, 0, OGSQL_HISTORY_BUF_SIZE));
    total = renderCtx->welcomeWidth;
    while (offset < request->nbytes) {
        if (request->text[offset] == '\n') {
            total = (total / renderCtx->wsCol + 1) * renderCtx->wsCol + renderCtx->welcomeWidth;
            offset++;
            continue;
        }
        if (cm_utf8_chr_bytes((uint8)request->text[offset], &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
            offset + c_bytes > request->nbytes || c_bytes > OGSQL_UTF8_CHR_SIZE) {
            c_bytes = 1;
            c_widths = 1;
        } else {
            c_widths = ogsql_utf8_chr_widths((char *)request->text + offset, c_bytes);
            if (c_widths == OG_INVALID_ID32) {
                c_bytes = 1;
                c_widths = 1;
            }
        }
        offset += c_bytes;

        if (c_widths == OGSQL_WIDE_CHAR_WIDTH && total % renderCtx->wsCol == renderCtx->wsCol - 1) {
            space_num++;
            uint32 line = total / renderCtx->wsCol + 1;
            if (line < OGSQL_HISTORY_BUF_SIZE) {
                request->endspace[line] = OG_TRUE;
            }
            total++;
        }
        total += c_widths;
    }
    *request->spacenum = space_num;
}

static void ogsql_set_endspace(ogsql_cmd_history_list_t hist_list, uint32 ws_col, uint32 welcome_width,
    uint32 *spacenum, bool8 *endspace)
{
    OgsqlRenderCtxT renderCtx = OgsqlMakeRenderCtx(NULL, welcome_width, ws_col, endspace);
    OgsqlEndspaceRequestT request = { hist_list.hist_buf, hist_list.nbytes, spacenum, endspace };

    OgsqlSetEndspaceByText(&request, &renderCtx);
}

static void OgsqlRefreshCurrentEndspace(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *renderCtx)
{
    OgsqlEndspaceRequestT request;

    if (state == NULL || renderCtx == NULL) {
        return;
    }
    request = (OgsqlEndspaceRequestT){ state->cmdBuf, state->nbytes, &state->spacenum, state->endspace };
    OgsqlSetEndspaceByText(&request, renderCtx);
}

static uint32 OgsqlRenderTotalAtCursor(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *renderCtx,
    OgsqlCursorT cursor);
static void ogsql_move_cursor_between_render_totals(uint32 from_total, uint32 to_total, uint32 ws_col);

/* Clear the current input display across all physical lines.
   Unlike ogsql_cmd_clean_line (which uses \b \b and cannot cross line
   boundaries), this moves the cursor to the start of the input (right after
   the prompt) and uses \033[J to clear from there to the end of the screen.
   This correctly erases multi-line content when recalling history items
   (W-09/W-10). The cursor is assumed to be at the end of the current input. */
static void ogsql_clear_input_display(uint32 nwidths, uint32 spacenum, uint32 welcome_width, uint32 ws_col)
{
    uint32 total_cols;
    uint32 lines_up;
    uint32 i;

    if (ws_col == 0 || nwidths == 0) {
        ogsql_cmd_clean_line(nwidths + spacenum);
        return;
    }
    total_cols = nwidths + spacenum + welcome_width;
    lines_up = total_cols / ws_col;
    for (i = 0; i < lines_up; i++) {
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[A");
    }
    ogsql_terminal_write(1, "\r");
    for (i = 0; i < welcome_width; i++) {
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[C");
    }
    ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");
}

static void OgsqlClearEditInputDisplay(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    uint32 endTotal;

    if (state == NULL || ctx == NULL) {
        return;
    }
    if (ctx->wsCol == 0) {
        ogsql_clear_input_display(state->nwidths, state->spacenum, ctx->welcomeWidth, ctx->wsCol);
        return;
    }
    endTotal = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->nbytes, state->nwidths });
    ogsql_move_cursor_between_render_totals(endTotal, ctx->welcomeWidth, ctx->wsCol);
    ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");
}

static bool32 OgsqlHistoryEntryFitsEditBuffer(const ogsql_cmd_history_list_t *entry,
    const OgsqlLineEditStateT *state)
{
    if (entry == NULL || state == NULL || state->cmdBuf == NULL ||
        state->maxLen < OGSQL_CMD_BUF_RESET_TAIL_LEN) {
        return OG_FALSE;
    }
    return (entry->nbytes <= ogsql_history_text_limit() &&
        entry->nbytes <= state->maxLen - OGSQL_CMD_BUF_RESET_TAIL_LEN) ? OG_TRUE : OG_FALSE;
}

static status_t OgsqlCopyHistoryEntryToCmd(const ogsql_cmd_history_list_t *entry, OgsqlLineEditStateT *state)
{
    errno_t rc;

    if (OgsqlHistoryEntryFitsEditBuffer(entry, state) != OG_TRUE) {
        return OG_ERROR;
    }
    rc = memcpy_s(state->cmdBuf, state->maxLen, entry->hist_buf, entry->nbytes);
    if (rc != EOK) {
        return OG_ERROR;
    }
    state->cmdBuf[entry->nbytes] = '\0';
    state->nbytes = entry->nbytes;
    state->nwidths = entry->nwidths;
    state->cursorPos = state->nbytes;
    state->cursorWidth = state->nwidths;
    return OG_SUCCESS;
}

static void OgsqlHistTurnUp(const int *histCount, int *listNum, OgsqlLineEditStateT *state,
    const OgsqlRenderCtxT *ctx)
{
    const ogsql_cmd_history_list_t *targetEntry;
    int targetListNum;

    if (histCount == NULL || listNum == NULL || state == NULL || ctx == NULL ||
        *histCount <= 0 || *listNum >= *histCount) {
        return;
    }
    if (*listNum == 0) {
        if (ogsql_history_save_draft(state->cmdBuf, state->nbytes, state->nwidths) != OG_SUCCESS) {
            return;
        }
    }
    targetListNum = *listNum + 1;
    targetEntry = ogsql_history_get(*histCount, (uint32)targetListNum);
    while (targetListNum <= *histCount && OgsqlHistoryEntryFitsEditBuffer(targetEntry, state) != OG_TRUE) {
        targetListNum++;
        targetEntry = ogsql_history_get(*histCount, (uint32)targetListNum);
    }
    if (targetListNum > *histCount || targetEntry == NULL) {
        return;
    }

    OgsqlClearEditInputDisplay(state, ctx);
    if (OgsqlCopyHistoryEntryToCmd(targetEntry, state) != OG_SUCCESS) {
        return;
    }
    *listNum = targetListNum;
    ogsql_set_endspace(*targetEntry, ctx->wsCol, ctx->welcomeWidth, &state->spacenum, state->endspace);
    OgsqlWriteWrappedText(targetEntry->hist_buf, state->nbytes, ctx->welcomeWidth, ctx);
}

static void OgsqlHistTurnDown(const int *histCount, int *listNum, OgsqlLineEditStateT *state,
    const OgsqlRenderCtxT *ctx)
{
    const ogsql_cmd_history_list_t *targetEntry;
    int targetListNum;

    if (histCount == NULL || listNum == NULL || state == NULL || ctx == NULL || *listNum < 1) {
        return;
    }
    targetListNum = *listNum - 1;
    targetEntry = (targetListNum == 0) ? ogsql_history_get_draft() :
        ogsql_history_get(*histCount, (uint32)targetListNum);
    while (targetListNum >= 0 && OgsqlHistoryEntryFitsEditBuffer(targetEntry, state) != OG_TRUE) {
        targetListNum--;
        targetEntry = (targetListNum == 0) ? ogsql_history_get_draft() :
            ogsql_history_get(*histCount, (uint32)targetListNum);
    }
    if (targetListNum < 0 || targetEntry == NULL) {
        return;
    }

    OgsqlClearEditInputDisplay(state, ctx);
    if (OgsqlCopyHistoryEntryToCmd(targetEntry, state) != OG_SUCCESS) {
        return;
    }
    *listNum = targetListNum;
    ogsql_set_endspace(*targetEntry, ctx->wsCol, ctx->welcomeWidth, &state->spacenum, state->endspace);
    OgsqlWriteWrappedText(targetEntry->hist_buf, state->nbytes, ctx->welcomeWidth, ctx);
}

uint32 ogsql_text_display_width(const char *text, uint32 len)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 total_widths = 0;

    while (offset < len) {
        if (text[offset] == '\n') {
            offset++;
            continue;
        }
        if (cm_utf8_chr_bytes((uint8)text[offset], &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
            c_bytes > OGSQL_UTF8_CHR_SIZE || offset + c_bytes > len) {
            break;
        }
        c_widths = ogsql_utf8_chr_widths((char *)text + offset, c_bytes);
        if (c_widths == OG_INVALID_ID32) {
            break;
        }
        total_widths += c_widths;
        offset += c_bytes;
    }

    return total_widths;
}

static uint32 ogsql_render_padding_before_cursor(char *cmdBuf, uint32 nbytes, uint32 cursor_pos,
    uint32 welcome_width, uint32 ws_col)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 logical_width = 0;
    uint32 space_num = 0;

    if (ws_col == 0) {
        return 0;
    }

    while (offset < cursor_pos && offset < nbytes) {
        if (cm_utf8_chr_bytes((uint8)cmdBuf[offset], &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
            offset + c_bytes > nbytes || offset + c_bytes > cursor_pos || c_bytes > OGSQL_UTF8_CHR_SIZE) {
            c_bytes = 1;
            c_widths = 1;
        } else {
            c_widths = ogsql_utf8_chr_widths(cmdBuf + offset, c_bytes);
            if (c_widths == OG_INVALID_ID32) {
                c_bytes = 1;
                c_widths = 1;
            }
        }

        if (c_widths == OGSQL_WIDE_CHAR_WIDTH && (logical_width + space_num + welcome_width + 1) % ws_col == 0) {
            space_num++;
        }
        logical_width += c_widths;
        offset += c_bytes;
    }

    if (cursor_pos < nbytes && offset == cursor_pos) {
        if (cm_utf8_chr_bytes((uint8)cmdBuf[cursor_pos], &c_bytes) == OG_SUCCESS && c_bytes > 0 &&
            cursor_pos + c_bytes <= nbytes && c_bytes <= OGSQL_UTF8_CHR_SIZE) {
            c_widths = ogsql_utf8_chr_widths(cmdBuf + cursor_pos, c_bytes);
            if (c_widths == OGSQL_WIDE_CHAR_WIDTH && (logical_width + space_num + welcome_width + 1) % ws_col == 0) {
                space_num++;
            }
        }
    }

    return space_num;
}

static OgsqlRenderPositionT ogsql_render_position_at(const char *text, uint32 nbytes, uint32 cursorPos,
    uint32 welcomeWidth, uint32 wsCol)
{
    OgsqlRenderPositionT position;
    uint32 offset = 0;
    uint32 cBytes = 0;
    uint32 cWidths = 0;
    uint32 total;

    if (wsCol == 0) {
        position.row = 0;
        position.col = welcomeWidth + ogsql_text_display_width(text, (cursorPos < nbytes) ? cursorPos : nbytes);
        return position;
    }

    total = welcomeWidth;
    while (offset < cursorPos && offset < nbytes) {
        if (text[offset] == '\n') {
            total = (total / wsCol + 1) * wsCol + welcomeWidth;
            offset++;
            continue;
        }
        if (cm_utf8_chr_bytes((uint8)text[offset], &cBytes) != OG_SUCCESS || cBytes == 0 ||
            cBytes > OGSQL_UTF8_CHR_SIZE || offset + cBytes > nbytes || offset + cBytes > cursorPos) {
            cBytes = 1;
            cWidths = 1;
        } else {
            cWidths = ogsql_utf8_chr_widths((char *)text + offset, cBytes);
            if (cWidths == OG_INVALID_ID32) {
                cBytes = 1;
                cWidths = 1;
            }
        }
        if (cWidths == OGSQL_WIDE_CHAR_WIDTH && total % wsCol == wsCol - 1) {
            total++;
        }
        total += cWidths;
        offset += cBytes;
    }

    position.row = total / wsCol;
    position.col = total % wsCol;
    return position;
}

static uint32 ogsql_render_total_at(const char *text, uint32 nbytes, uint32 cursorPos, uint32 welcomeWidth,
    uint32 wsCol)
{
    OgsqlRenderPositionT position = ogsql_render_position_at(text, nbytes, cursorPos, welcomeWidth, wsCol);

    return position.row * wsCol + position.col;
}

static uint32 ogsql_input_render_rows(char *cmdBuf, uint32 nbytes, uint32 nwidths, uint32 welcome_width,
    uint32 ws_col)
{
    OgsqlRenderPositionT position;

    if (ws_col == 0) {
        ws_col = OGSQL_DEFAULT_TERMINAL_COLUMNS;
    }
    (void)nwidths;
    position = ogsql_render_position_at(cmdBuf, nbytes, nbytes, welcome_width, ws_col);
    return position.row + 1;
}

static uint32 OgsqlRenderRowAtCursor(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *renderCtx)
{
    if (state == NULL || renderCtx == NULL || renderCtx->wsCol == 0) {
        return 0;
    }
    return ogsql_render_position_at(state->cmdBuf, state->nbytes, state->cursorPos, renderCtx->welcomeWidth,
        renderCtx->wsCol).row;
}

static uint32 OgsqlRenderTotalAtCursor(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *renderCtx,
    OgsqlCursorT cursor)
{
    if (state == NULL || renderCtx == NULL || renderCtx->wsCol == 0) {
        return cursor.width + ((renderCtx == NULL) ? 0 : renderCtx->welcomeWidth);
    }
    return ogsql_render_total_at(state->cmdBuf, state->nbytes, cursor.pos, renderCtx->welcomeWidth,
        renderCtx->wsCol);
}

static void ogsql_move_cursor_between_render_totals(uint32 from_total, uint32 to_total, uint32 ws_col)
{
    uint32 from_row;
    uint32 to_row;
    uint32 from_col;
    uint32 to_col;
    uint32 row_distance;
    char row_direction;
    char line_direction;
    char move_sequence[OGSQL_CURSOR_MOVE_BUF_SIZE];
    int32 move_sequence_len;

    if (ws_col == 0 || from_total == to_total) {
        return;
    }

    from_row = from_total / ws_col;
    to_row = to_total / ws_col;
    from_col = from_total % ws_col;
    to_col = to_total % ws_col;

    if (from_row == to_row) {
        while (from_col > to_col) {
            ogsql_terminal_write(1, "\b");
            from_col--;
        }
        while (from_col < to_col) {
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[C");
            from_col++;
        }
        return;
    }

    if (from_row > to_row) {
        row_distance = from_row - to_row;
        row_direction = 'A';
        line_direction = 'F';
    } else {
        row_distance = to_row - from_row;
        row_direction = 'B';
        line_direction = 'E';
    }
    if (from_col == to_col) {
        move_sequence_len = snprintf_s(move_sequence, sizeof(move_sequence), sizeof(move_sequence) - 1,
            "\033[%u%c", row_distance, row_direction);
    } else if (to_col == 0) {
        move_sequence_len = snprintf_s(move_sequence, sizeof(move_sequence), sizeof(move_sequence) - 1,
            "\033[%u%c", row_distance, line_direction);
    } else {
        move_sequence_len = snprintf_s(move_sequence, sizeof(move_sequence), sizeof(move_sequence) - 1,
            "\033[%u%c\033[%uG", row_distance, line_direction, to_col + 1);
    }
    if (move_sequence_len > 0) {
        ogsql_terminal_write((uint32)move_sequence_len, move_sequence);
    }
}

/* Move by rendered row/column instead of logical width. This is required at the
   one-column gap before a full-width character: the cursor is physically after
   the padding cell, while inserting an ASCII character can remove that padding. */
static void OgsqlMoveCursorToRenderPos(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *renderCtx,
    OgsqlCursorT fromCursor, OgsqlCursorT toCursor)
{
    uint32 from_total;
    uint32 to_total;

    if (renderCtx == NULL || renderCtx->wsCol == 0) {
        return;
    }

    from_total = OgsqlRenderTotalAtCursor(state, renderCtx, fromCursor);
    to_total = OgsqlRenderTotalAtCursor(state, renderCtx, toCursor);
    ogsql_move_cursor_between_render_totals(from_total, to_total, renderCtx->wsCol);
}

static status_t ogsql_get_current_char(char *cmdBuf, uint32 cursor_pos, uint32 nbytes, uint32 *c_bytes,
    uint32 *c_widths)
{
    if (cursor_pos >= nbytes) {
        return OG_ERROR;
    }
    if (cmdBuf[cursor_pos] == '\n') {
        *c_bytes = 1;
        *c_widths = 0;
        return OG_SUCCESS;
    }
    if (cm_utf8_chr_bytes((uint8)cmdBuf[cursor_pos], c_bytes) != OG_SUCCESS ||
        *c_bytes == 0 || cursor_pos + *c_bytes > nbytes || *c_bytes > OGSQL_UTF8_CHR_SIZE) {
        return OG_ERROR;
    }
    *c_widths = ogsql_utf8_chr_widths(cmdBuf + cursor_pos, *c_bytes);
    return (*c_widths == OG_INVALID_ID32) ? OG_ERROR : OG_SUCCESS;
}

static void OgsqlRedrawFromCursor(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx, uint32 clearWidth)
{
    uint32 tail_width;
    uint32 render_spacenum = 0;
    bool8 render_endspace[OGSQL_HISTORY_BUF_SIZE];
    OgsqlRenderCtxT renderCtx;

    if (state == NULL || ctx == NULL) {
        return;
    }
    tail_width = (state->cursorWidth < state->nwidths) ? (state->nwidths - state->cursorWidth) : 0;
    renderCtx = *ctx;

    /* Clear from cursor to end of screen before rewriting. This handles multi-line
       content: \033[J erases from the cursor position to the end of the terminal
       screen, removing stale characters on the current line and all lines below.
       The previous approach (writing clear_width spaces) could not clear content
       that wrapped onto subsequent physical lines, leaving residue after deletion
       (W-02/W-07). When ws_col == 0 (non-tty), the terminal has no wrap so spaces
       are still needed. */
    if (ctx->wsCol > 0) {
        OgsqlLineEditStateT renderState = *state;
        renderState.spacenum = render_spacenum;
        renderState.endspace = render_endspace;
        renderCtx.endspace = render_endspace;
        OgsqlRefreshCurrentEndspace(&renderState, &renderCtx);
        render_spacenum = renderState.spacenum;
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");
        OgsqlWriteWrappedText(state->cmdBuf + state->cursorPos, state->nbytes - state->cursorPos,
            OgsqlRenderTotalAtCursor(&renderState, &renderCtx,
                (OgsqlCursorT){ state->cursorPos, state->cursorWidth }), &renderCtx);
        if (state->cursorPos < state->nbytes) {
            OgsqlMoveCursorToRenderPos(&renderState, &renderCtx,
                (OgsqlCursorT){ state->nbytes, state->nwidths },
                (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        }
    } else {
        ogsql_terminal_write(state->nbytes - state->cursorPos, state->cmdBuf + state->cursorPos);
        ogsql_cmd_write_spaces(clearWidth);
        ogsql_cmd_move_left(tail_width + clearWidth, state->cursorWidth + tail_width + clearWidth, ctx->welcomeWidth,
            ctx->wsCol, ctx->endspace);
    }
}

static void OgsqlRedrawWholeInputFromRow(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    uint32 currentRow)
{
    uint32 render_spacenum = 0;
    uint32 welcomeLen;
    bool8 render_endspace[OGSQL_HISTORY_BUF_SIZE];
    OgsqlRenderCtxT renderCtx;

    if (state == NULL || ctx == NULL) {
        return;
    }
    renderCtx = *ctx;
    renderCtx.endspace = render_endspace;
    if (ctx->wsCol == 0) {
        ogsql_terminal_write(state->nbytes, state->cmdBuf);
        return;
    }

    for (uint32 i = 0; i < currentRow; i++) {
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[A");
    }
    ogsql_terminal_write(1, "\r");
    welcomeLen = (ctx->welcomeBuf == NULL) ? 0 : (uint32)strlen(ctx->welcomeBuf);
    if (welcomeLen > 0) {
        /* Rewriting the prompt also clears zero-width combining characters that
           may have become attached to its trailing cell. */
        ogsql_terminal_write(welcomeLen, ctx->welcomeBuf);
    } else {
        for (uint32 i = 0; i < ctx->welcomeWidth; i++) {
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[C");
        }
    }
    ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");

    if (state->nbytes == 0) {
        /* Touch a normal-width cell, then reposition with CR instead of BS so
           terminals do not keep stale state from a just-erased wide character. */
        ogsql_terminal_write(1, " ");
        ogsql_terminal_write(1, "\r");
        for (uint32 i = 0; i < ctx->welcomeWidth; i++) {
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[C");
        }
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[K");
        return;
    }

    {
        OgsqlLineEditStateT renderState = *state;
        renderState.spacenum = render_spacenum;
        renderState.endspace = render_endspace;
        OgsqlRefreshCurrentEndspace(&renderState, &renderCtx);
        render_spacenum = renderState.spacenum;
    }
    OgsqlWriteWrappedText(state->cmdBuf, state->nbytes, renderCtx.welcomeWidth, &renderCtx);
    if (state->cursorPos < state->nbytes) {
        OgsqlLineEditStateT cursorState = *state;
        cursorState.spacenum = render_spacenum;
        cursorState.endspace = render_endspace;
        OgsqlMoveCursorToRenderPos(&cursorState, &renderCtx,
            (OgsqlCursorT){ state->nbytes, state->nwidths },
            (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
    }
}

static void OgsqlMoveToLineBegin(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    if (state == NULL || ctx == NULL || state->cursorPos == 0) {
        return;
    }

    if (ctx->wsCol > 0) {
        OgsqlMoveCursorToRenderPos(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth },
            (OgsqlCursorT){ 0, 0 });
    } else {
        ogsql_cmd_move_left(state->cursorWidth, state->cursorWidth, ctx->welcomeWidth, ctx->wsCol, ctx->endspace);
    }
    state->cursorPos = 0;
    state->cursorWidth = 0;
}

static void OgsqlMoveToLineEnd(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    if (state == NULL || ctx == NULL) {
        return;
    }
    if (state->cursorPos < state->nbytes) {
        if (ctx->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth },
                (OgsqlCursorT){ state->nbytes, state->nwidths });
        } else {
            ogsql_cmd_move_right(state->nwidths - state->cursorWidth, state->cursorWidth, ctx->welcomeWidth,
                ctx->wsCol, ctx->endspace);
        }
    }
    state->cursorPos = state->nbytes;
    state->cursorWidth = state->nwidths;
}

static void OgsqlDeleteCharAtCursor(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    errno_t rc;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 old_total = 0;
    uint32 new_total;

    if (state == NULL || ctx == NULL ||
        ogsql_get_current_char(state->cmdBuf, state->cursorPos, state->nbytes, &c_bytes, &c_widths) != OG_SUCCESS) {
        return;
    }
    if (ctx->wsCol > 0) {
        old_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
    }
    if (state->cursorPos + c_bytes < state->nbytes) {
        rc = memmove_s(state->cmdBuf + state->cursorPos, state->maxLen - state->cursorPos,
            state->cmdBuf + state->cursorPos + c_bytes, state->nbytes - state->cursorPos - c_bytes);
        if (rc != EOK) {
            return;
        }
    }
    state->nbytes -= c_bytes;
    state->nwidths -= c_widths;
    state->cmdBuf[state->nbytes] = '\0';
    if (ctx->wsCol > 0) {
        if (c_widths == 0) {
            OgsqlRedrawWholeInputFromRow(state, ctx, old_total / ctx->wsCol);
            return;
        }
        new_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        ogsql_move_cursor_between_render_totals(old_total, new_total, ctx->wsCol);
        OgsqlRedrawFromCursor(state, ctx, c_widths);
    } else {
        OgsqlRedrawFromCursor(state, ctx, c_widths);
    }
}

static void OgsqlDeleteBeforeCursor(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    OgsqlCursorT startCursor)
{
    errno_t rc;
    uint32 delete_bytes;
    uint32 delete_width;
    uint32 old_total = 0;
    uint32 new_total;
    uint32 first_delete_bytes = 0;
    uint32 first_delete_width = 0;
    bool32 delete_suffix;
    bool32 redraw_whole = OG_FALSE;

    if (state == NULL || ctx == NULL || startCursor.pos >= state->cursorPos) {
        return;
    }
    delete_bytes = state->cursorPos - startCursor.pos;
    delete_width = state->cursorWidth - startCursor.width;
    delete_suffix = (state->cursorPos == state->nbytes) ? OG_TRUE : OG_FALSE;
    if (ogsql_get_current_char(state->cmdBuf, startCursor.pos, state->nbytes, &first_delete_bytes,
        &first_delete_width) == OG_SUCCESS && first_delete_width == 0) {
        redraw_whole = OG_TRUE;
    }
    if (ctx->wsCol > 0) {
        old_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
    }
    if (ctx->wsCol == 0) {
        ogsql_cmd_move_left(delete_width, state->cursorWidth, ctx->welcomeWidth, ctx->wsCol, ctx->endspace);
    }
    if (state->cursorPos < state->nbytes) {
        rc = memmove_s(state->cmdBuf + startCursor.pos, state->maxLen - startCursor.pos,
            state->cmdBuf + state->cursorPos, state->nbytes - state->cursorPos);
        if (rc != EOK) {
            return;
        }
    }
    state->nbytes -= delete_bytes;
    state->nwidths -= delete_width;
    state->cursorPos = startCursor.pos;
    state->cursorWidth = startCursor.width;
    state->cmdBuf[state->nbytes] = '\0';
    if (ctx->wsCol > 0) {
        if (redraw_whole == OG_TRUE) {
            OgsqlRedrawWholeInputFromRow(state, ctx, old_total / ctx->wsCol);
            return;
        }
        new_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        ogsql_move_cursor_between_render_totals(old_total, new_total, ctx->wsCol);
        if (delete_suffix == OG_TRUE) {
            ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");
        } else {
            OgsqlRedrawFromCursor(state, ctx, delete_width);
        }
    } else {
        OgsqlRedrawFromCursor(state, ctx, delete_width);
    }
}

static void OgsqlDeleteToLineEnd(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    uint32 clear_width;
    uint32 first_delete_bytes = 0;
    uint32 first_delete_width = 0;
    uint32 old_total = 0;
    uint32 new_total;
    bool32 redraw_whole = OG_FALSE;

    if (state == NULL || ctx == NULL || state->cursorPos >= state->nbytes) {
        return;
    }
    clear_width = state->nwidths - state->cursorWidth;
    if (ogsql_get_current_char(state->cmdBuf, state->cursorPos, state->nbytes, &first_delete_bytes,
        &first_delete_width) == OG_SUCCESS && first_delete_width == 0) {
        redraw_whole = OG_TRUE;
    }
    if (ctx->wsCol > 0) {
        old_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
    }
    state->nbytes = state->cursorPos;
    state->nwidths = state->cursorWidth;
    state->cmdBuf[state->nbytes] = '\0';
    if (ctx->wsCol > 0) {
        if (redraw_whole == OG_TRUE) {
            OgsqlRedrawWholeInputFromRow(state, ctx, old_total / ctx->wsCol);
            return;
        }
        new_total = OgsqlRenderTotalAtCursor(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        ogsql_move_cursor_between_render_totals(old_total, new_total, ctx->wsCol);
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[J");
    } else {
        ogsql_cmd_write_spaces(clear_width);
        ogsql_cmd_move_left(clear_width, state->cursorWidth + clear_width, ctx->welcomeWidth, ctx->wsCol,
            ctx->endspace);
    }
}

static bool32 ogsql_is_word_blank(char *cmdBuf, uint32 pos, uint32 c_bytes)
{
    return (c_bytes == 1 && cmdBuf[pos] <= ' ') ? OG_TRUE : OG_FALSE;
}

static status_t ogsql_get_prev_word_start(char *cmdBuf, uint32 cursor_pos, uint32 cursor_width, uint32 *start_pos,
    uint32 *start_width)
{
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 pos = cursor_pos;
    uint32 width = cursor_width;

    while (pos > 0) {
        if (ogsql_get_prev_char(cmdBuf, pos, &c_bytes, &c_widths) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (!ogsql_is_word_blank(cmdBuf, pos - c_bytes, c_bytes)) {
            break;
        }
        pos -= c_bytes;
        width -= c_widths;
    }

    while (pos > 0) {
        if (ogsql_get_prev_char(cmdBuf, pos, &c_bytes, &c_widths) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (ogsql_is_word_blank(cmdBuf, pos - c_bytes, c_bytes)) {
            break;
        }
        pos -= c_bytes;
        width -= c_widths;
    }

    *start_pos = pos;
    *start_width = width;
    return OG_SUCCESS;
}

static void OgsqlClearScreenAndRedraw(const OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    const char clearScreen[] = "\033[H\033[J";
    uint32 welcome_len;

    if (state == NULL || ctx == NULL) {
        return;
    }
    welcome_len = (ctx->welcomeBuf == NULL) ? 0 : (uint32)strlen(ctx->welcomeBuf);
    ogsql_terminal_write((uint32)strlen(clearScreen), clearScreen);
    if (welcome_len > 0) {
        ogsql_terminal_write(welcome_len, ctx->welcomeBuf);
    }
    OgsqlWriteWrappedText(state->cmdBuf, state->nbytes, ctx->welcomeWidth, ctx);
    if (state->cursorPos < state->nbytes) {
        if (ctx->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(state, ctx, (OgsqlCursorT){ state->nbytes, state->nwidths },
                (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        } else {
            ogsql_cmd_move_left(state->nwidths - state->cursorWidth, state->nwidths, ctx->welcomeWidth, ctx->wsCol,
                ctx->endspace);
        }
    }
}

static uint32 ogsql_get_terminal_columns(void)
{
#ifndef WIN32
    struct winsize size = { 0 };

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col != 0) {
        return size.ws_col;
    }
#endif
    return OGSQL_DEFAULT_TERMINAL_COLUMNS;
}

static void OgsqlSyncTerminalResize(OgsqlLineEditStateT *state, OgsqlRenderCtxT *ctx)
{
    uint32 new_ws_col = ogsql_get_terminal_columns();
    uint32 current_row;

    if (state == NULL || ctx == NULL || new_ws_col == ctx->wsCol) {
        return;
    }

    ctx->wsCol = new_ws_col;
    current_row = OgsqlRenderRowAtCursor(state, ctx);
    OgsqlRefreshCurrentEndspace(state, ctx);
    OgsqlRedrawWholeInputFromRow(state, ctx, current_row);
}

static bool32 ogsql_getchar_blocking(int32 *key_char)
{
#ifdef WIN32
    *key_char = getchar();
    return (*key_char == EOF) ? OG_FALSE : OG_TRUE;
#else
    uint8 ch;
    ssize_t ret;

    do {
        ret = read(STDIN_FILENO, &ch, 1);
        if (ret == 1) {
            *key_char = (int32)ch;
            return OG_TRUE;
        }
        if (ret == 0) {
            return OG_FALSE;
        }
    } while (errno == EINTR);
    return OG_FALSE;
#endif
}

static bool32 ogsql_getchar_with_timeout(int32 *key_char, uint32 timeout_ms)
{
#ifdef WIN32
    (void)timeout_ms;
    return ogsql_getchar_blocking(key_char);
#else
    fd_set readfds;
    struct timeval timeout;
    int ret;

    do {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        timeout.tv_sec = timeout_ms / OGSQL_MSEC_PER_SEC;
        timeout.tv_usec = (timeout_ms % OGSQL_MSEC_PER_SEC) * OGSQL_USEC_PER_MSEC;
        ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);
        if (ret > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            return ogsql_getchar_blocking(key_char);
        }
    } while (ret < 0 && errno == EINTR);
    return OG_FALSE;
#endif
}

static void ogsql_drain_escape_sequence(int32 key_char)
{
    while (key_char >= 0x20 && key_char <= 0x3F) {
        if (!ogsql_getchar_with_timeout(&key_char, OGSQL_SELECT_RETRY_TIMEOUT_MS)) {
            return;
        }
    }
}

static bool32 ogsql_escape_sequence_can_have_params(int32 esc_key)
{
    return (esc_key == '[' || esc_key == 'O') ? OG_TRUE : OG_FALSE;
}

static bool32 ogsql_read_escape_keys(int32 *escKey, int32 *sequenceKey)
{
    if (!ogsql_getchar_with_timeout(escKey, OGSQL_SELECT_RETRY_TIMEOUT_MS)) {
        return OG_FALSE;
    }
    if (!ogsql_escape_sequence_can_have_params(*escKey)) {
        return OG_FALSE;
    }
    return ogsql_getchar_with_timeout(sequenceKey, OGSQL_SELECT_RETRY_TIMEOUT_MS);
}

static void OgsqlConsumeEscapeSequence(void)
{
    int32 escKey;
    int32 sequenceKey;

    if (!ogsql_read_escape_keys(&escKey, &sequenceKey)) {
        return;
    }
    ogsql_drain_escape_sequence(sequenceKey);
}

typedef enum EnOgsqlReverseSearchResultT {
    OGSQL_REVERSE_SEARCH_CONTINUE,
    OGSQL_REVERSE_SEARCH_CANCEL,
    OGSQL_REVERSE_SEARCH_ACCEPT_EDIT,
    OGSQL_REVERSE_SEARCH_ACCEPT_EXECUTE
} OgsqlReverseSearchResultT;

static void OgsqlResetReverseSearchDisplay(OgsqlLineEditStateT *displayState)
{
    if (displayState == NULL) {
        return;
    }
    displayState->nbytes = 0;
    displayState->nwidths = 0;
    displayState->cursorPos = 0;
    displayState->cursorWidth = 0;
    displayState->spacenum = 0;
    if (displayState->cmdBuf != NULL && displayState->maxLen > 0) {
        displayState->cmdBuf[0] = '\0';
    }
    if (displayState->endspace != NULL) {
        (void)memset_s(displayState->endspace, OGSQL_HISTORY_BUF_SIZE, 0, OGSQL_HISTORY_BUF_SIZE);
    }
}

static void OgsqlClearReverseSearchDisplay(OgsqlLineEditStateT *displayState, const OgsqlRenderCtxT *ctx)
{
    if (displayState == NULL || ctx == NULL) {
        return;
    }
    if (displayState->nbytes == 0) {
        OgsqlResetReverseSearchDisplay(displayState);
        return;
    }
    if (displayState->cursorPos < displayState->nbytes) {
        if (ctx->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(displayState, ctx,
                (OgsqlCursorT){ displayState->cursorPos, displayState->cursorWidth },
                (OgsqlCursorT){ displayState->nbytes, displayState->nwidths });
        } else {
            ogsql_cmd_move_right(displayState->nwidths - displayState->cursorWidth, displayState->cursorWidth,
                ctx->welcomeWidth, ctx->wsCol, displayState->endspace);
        }
        displayState->cursorPos = displayState->nbytes;
        displayState->cursorWidth = displayState->nwidths;
    }
    OgsqlClearEditInputDisplay(displayState, ctx);
    OgsqlResetReverseSearchDisplay(displayState);
}

static void OgsqlRenderReverseSearchLine(const OgsqlReverseRenderRequestT *request, const OgsqlRenderCtxT *ctx,
    OgsqlLineEditStateT *displayState)
{
    const char *prefix;
    char *renderBuf;
    uint32 render_len;
    uint32 query_end;
    int32 ret;
    OgsqlRenderCtxT renderCtx;
    OgsqlEndspaceRequestT endspaceRequest;

    if (request == NULL || ctx == NULL || displayState == NULL || displayState->cmdBuf == NULL ||
        displayState->maxLen == 0) {
        return;
    }
    OgsqlClearReverseSearchDisplay(displayState, ctx);
    renderBuf = displayState->cmdBuf;
    renderCtx = *ctx;
    renderCtx.endspace = displayState->endspace;

    if (request->failed == OG_TRUE) {
        prefix = "(failed reverse-i-search): ";
        ret = snprintf_s(renderBuf, displayState->maxLen, displayState->maxLen - 1,
            "(failed reverse-i-search): %.*s", (int32)request->queryLen, request->query);
    } else if (request->match != NULL) {
        prefix = "(reverse-i-search): ";
        ret = snprintf_s(renderBuf, displayState->maxLen, displayState->maxLen - 1,
            "(reverse-i-search): %.*s -> %.*s", (int32)request->queryLen, request->query,
            (int32)request->match->nbytes, request->match->hist_buf);
    } else {
        prefix = "(reverse-i-search): ";
        ret = snprintf_s(renderBuf, displayState->maxLen, displayState->maxLen - 1,
            "(reverse-i-search): %.*s", (int32)request->queryLen, request->query);
    }
    if (ret < 0) {
        renderBuf[0] = '\0';
        query_end = 0;
    } else {
        query_end = (uint32)strlen(prefix) + request->queryLen;
    }

    render_len = (uint32)strlen(renderBuf);
    for (uint32 i = 0; i < render_len; i++) {
        if (renderBuf[i] == '\n' || renderBuf[i] == '\r') {
            renderBuf[i] = ' ';
        }
    }
    if (query_end > render_len) {
        query_end = render_len;
    }
    displayState->nbytes = render_len;
    displayState->nwidths = ogsql_text_display_width(renderBuf, render_len);
    displayState->cursorPos = query_end;
    displayState->cursorWidth = ogsql_text_display_width(renderBuf, query_end);
    endspaceRequest = (OgsqlEndspaceRequestT){ renderBuf, render_len, &displayState->spacenum,
        displayState->endspace };
    OgsqlSetEndspaceByText(&endspaceRequest, &renderCtx);
    OgsqlWriteWrappedText(renderBuf, render_len, renderCtx.welcomeWidth, &renderCtx);
    if (displayState->cursorPos < displayState->nbytes && ctx->wsCol > 0) {
        OgsqlMoveCursorToRenderPos(displayState, &renderCtx,
            (OgsqlCursorT){ displayState->nbytes, displayState->nwidths },
            (OgsqlCursorT){ displayState->cursorPos, displayState->cursorWidth });
    } else if (displayState->cursorPos < displayState->nbytes) {
        ogsql_cmd_move_left(displayState->nwidths - displayState->cursorWidth, displayState->nwidths,
            ctx->welcomeWidth, ctx->wsCol, displayState->endspace);
    }
}

static void OgsqlRestoreReverseSearchInput(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    const OgsqlLineEditStateT *restoreState, OgsqlLineEditStateT *displayState)
{
    errno_t rc;
    OgsqlRenderCtxT renderCtx;

    if (state == NULL || ctx == NULL || restoreState == NULL || displayState == NULL) {
        return;
    }
    renderCtx = *ctx;
    renderCtx.endspace = state->endspace;
    OgsqlClearReverseSearchDisplay(displayState, ctx);
    if (state->cmdBuf != restoreState->cmdBuf) {
        rc = memcpy_s(state->cmdBuf, state->maxLen, restoreState->cmdBuf, restoreState->nbytes);
        if (rc != EOK) {
            state->cmdBuf[0] = '\0';
            state->nbytes = 0;
            state->nwidths = 0;
            state->cursorPos = 0;
            state->cursorWidth = 0;
        } else {
            state->nbytes = restoreState->nbytes;
            state->nwidths = restoreState->nwidths;
            state->cursorPos = restoreState->cursorPos;
            state->cursorWidth = restoreState->cursorWidth;
        }
    } else {
        state->nbytes = restoreState->nbytes;
        state->nwidths = restoreState->nwidths;
        state->cursorPos = restoreState->cursorPos;
        state->cursorWidth = restoreState->cursorWidth;
    }
    state->cmdBuf[state->nbytes] = '\0';
    OgsqlRefreshCurrentEndspace(state, &renderCtx);
    OgsqlWriteWrappedText(state->cmdBuf, state->nbytes, renderCtx.welcomeWidth, &renderCtx);
    if (state->cursorPos < state->nbytes && ctx->wsCol > 0) {
        OgsqlMoveCursorToRenderPos(state, &renderCtx, (OgsqlCursorT){ state->nbytes, state->nwidths },
            (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
    } else if (state->cursorPos < state->nbytes) {
        ogsql_cmd_move_left(state->nwidths - state->cursorWidth, state->nwidths, ctx->welcomeWidth, ctx->wsCol,
            ctx->endspace);
    }

}

static bool32 ogsql_reverse_search_refresh_match(int histCount, const char *query, uint32 queryLen,
    uint32 afterIndex, uint32 *currentMatch)
{
    if (ogsql_history_find_ranked(histCount, query, queryLen, afterIndex, currentMatch) == OG_TRUE) {
        return OG_TRUE;
    }

    *currentMatch = 0;
    return OG_FALSE;
}

static void OgsqlReverseSearchRenderCurrent(OgsqlReverseSearchStateT *search)
{
    OgsqlReverseRenderRequestT request;

    if (search == NULL) {
        return;
    }
    request = (OgsqlReverseRenderRequestT){ search->query, search->queryLen,
        ogsql_history_get(search->histCount, search->currentMatch), search->failed };
    OgsqlRenderReverseSearchLine(&request, search->renderCtx, search->displayState);
}

static void OgsqlReverseSearchNextMatch(OgsqlReverseSearchStateT *search)
{
    if (search == NULL) {
        return;
    }
    search->failed = (ogsql_reverse_search_refresh_match(search->histCount, search->query, search->queryLen,
        search->currentMatch, &search->currentMatch) == OG_TRUE) ? OG_FALSE : OG_TRUE;
    OgsqlReverseSearchRenderCurrent(search);
}

static void OgsqlReverseSearchCancel(OgsqlReverseSearchStateT *search)
{
    if (search == NULL) {
        return;
    }
    OgsqlRestoreReverseSearchInput(search->lineState, search->renderCtx, search->originalState,
        search->displayState);
    if (search->listNum != NULL) {
        *search->listNum = search->originalListNum;
    }
}

static void OgsqlReverseSearchClearScreen(OgsqlReverseSearchStateT *search)
{
    if (search == NULL) {
        return;
    }
    ogsql_terminal_write(OGSQL_CLEAR_SCREEN_SEQ_LEN, "\033[2J\033[H");
    if (search->renderCtx->welcomeBuf != NULL) {
        ogsql_terminal_write((uint32)strlen(search->renderCtx->welcomeBuf), search->renderCtx->welcomeBuf);
    }
    OgsqlResetReverseSearchDisplay(search->displayState);
    OgsqlReverseSearchRenderCurrent(search);
}

static bool32 ogsql_reverse_search_accept_edit(OgsqlReverseSearchStateT *search)
{
    if (search == NULL || search->currentMatch == 0 ||
        OgsqlCopyHistoryEntryToCmd(ogsql_history_get(search->histCount, search->currentMatch),
        search->lineState) != OG_SUCCESS) {
        return OG_FALSE;
    }
    OgsqlRestoreReverseSearchInput(search->lineState, search->renderCtx, search->lineState, search->displayState);
    if (search->listNum != NULL) {
        *search->listNum = 0;
    }
    return OG_TRUE;
}

static bool32 ogsql_reverse_search_accept_execute(OgsqlReverseSearchStateT *search)
{
    if (search == NULL || search->currentMatch == 0 ||
        OgsqlCopyHistoryEntryToCmd(ogsql_history_get(search->histCount, search->currentMatch),
        search->lineState) != OG_SUCCESS) {
        return OG_FALSE;
    }
    OgsqlClearReverseSearchDisplay(search->displayState, search->renderCtx);
    OgsqlRefreshCurrentEndspace(search->lineState, search->renderCtx);
    OgsqlWriteWrappedText(search->lineState->cmdBuf, search->lineState->nbytes,
        search->renderCtx->welcomeWidth, search->renderCtx);
    ogsql_terminal_write(1, "\n");
    if (search->listNum != NULL) {
        *search->listNum = 0;
    }
    return OG_TRUE;
}

static void OgsqlReverseSearchBackspace(OgsqlReverseSearchStateT *search)
{
    uint32 c_bytes;
    uint32 c_widths;

    if (search == NULL || search->queryLen == 0 ||
        ogsql_get_prev_char(search->query, search->queryLen, &c_bytes, &c_widths) != OG_SUCCESS) {
        return;
    }
    search->queryLen -= c_bytes;
    search->query[search->queryLen] = '\0';
    search->failed = (ogsql_reverse_search_refresh_match(search->histCount, search->query, search->queryLen, 0,
        &search->currentMatch) == OG_TRUE) ? OG_FALSE : OG_TRUE;
    OgsqlReverseSearchRenderCurrent(search);
}

static void ogsql_reverse_search_append_char(OgsqlReverseSearchStateT *search, int32 key_char)
{
    char chr[OGSQL_UTF8_CHR_SIZE];
    uint32 c_bytes;
    errno_t rc;

    if (search == NULL || cm_utf8_chr_bytes((uint8)key_char, &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
        c_bytes > OGSQL_UTF8_CHR_SIZE || search->queryLen + c_bytes >= OGSQL_HISTORY_BUF_SIZE) {
        return;
    }
    chr[0] = (char)key_char;
    for (uint32 i = 1; i < c_bytes; i++) {
        if (!ogsql_getchar_with_timeout(&key_char, OGSQL_SELECT_RETRY_TIMEOUT_MS) ||
            !IS_VALID_UTF8_CHAR((uint8)key_char)) {
            return;
        }
        chr[i] = (char)key_char;
    }
    rc = memcpy_s(search->query + search->queryLen, OGSQL_HISTORY_BUF_SIZE - search->queryLen, chr, c_bytes);
    if (rc != EOK) {
        return;
    }
    search->queryLen += c_bytes;
    search->query[search->queryLen] = '\0';
    search->failed = (ogsql_reverse_search_refresh_match(search->histCount, search->query, search->queryLen, 0,
        &search->currentMatch) == OG_TRUE) ? OG_FALSE : OG_TRUE;
    OgsqlReverseSearchRenderCurrent(search);
}

static OgsqlReverseSearchResultT ogsql_reverse_search_dispatch_key(OgsqlReverseSearchStateT *search, int32 keyChar)
{
    switch (keyChar) {
        case CMD_KEY_CTRL_R:
            OgsqlReverseSearchNextMatch(search);
            return OGSQL_REVERSE_SEARCH_CONTINUE;
        case CMD_KEY_CTRL_G:
            OgsqlReverseSearchCancel(search);
            return OGSQL_REVERSE_SEARCH_CANCEL;
        case CMD_KEY_CTRL_L:
            OgsqlReverseSearchClearScreen(search);
            return OGSQL_REVERSE_SEARCH_CONTINUE;
        case CMD_KEY_ESCAPE:
            OgsqlConsumeEscapeSequence();
            return ogsql_reverse_search_accept_edit(search) ? OGSQL_REVERSE_SEARCH_ACCEPT_EDIT :
                OGSQL_REVERSE_SEARCH_CONTINUE;
        case CMD_KEY_ASCII_CR:
        case CMD_KEY_ASCII_LF:
            return ogsql_reverse_search_accept_execute(search) ? OGSQL_REVERSE_SEARCH_ACCEPT_EXECUTE :
                OGSQL_REVERSE_SEARCH_CONTINUE;
        case CMD_KEY_ASCII_DEL:
        case CMD_KEY_ASCII_BS:
            OgsqlReverseSearchBackspace(search);
            return OGSQL_REVERSE_SEARCH_CONTINUE;
        default:
            if (keyChar >= ' ') {
                ogsql_reverse_search_append_char(search, keyChar);
            }
            return OGSQL_REVERSE_SEARCH_CONTINUE;
    }
}

static OgsqlReverseSearchResultT OgsqlReverseHistorySearch(int histCount, int *listNum,
    OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx)
{
    char query[OGSQL_HISTORY_BUF_SIZE];
    char displayBuf[OGSQL_HISTORY_BUF_SIZE * OGSQL_REVERSE_RENDER_BUF_FACTOR];
    bool8 display_endspace[OGSQL_HISTORY_BUF_SIZE];
    OgsqlLineEditStateT originalState;
    OgsqlLineEditStateT displayState;
    OgsqlReverseSearchStateT search;
    int originalListNum = (listNum == NULL) ? 0 : *listNum;
    uint32 queryLen = 0;
    uint32 current_match = 0;
    int32 key_char;
    OgsqlReverseSearchResultT result;
    bool32 failed;
    errno_t rc;

    if (state == NULL || state->cmdBuf == NULL || ctx == NULL || histCount <= 0) {
        return OGSQL_REVERSE_SEARCH_CANCEL;
    }

    /* Search rendering uses displayBuf, so preserving the original metadata is enough to restore the draft. */
    originalState = *state;
    displayState = (OgsqlLineEditStateT){ displayBuf, sizeof(displayBuf), 0, 0, 0, 0, 0, display_endspace };
    displayBuf[0] = '\0';
    query[0] = '\0';
    rc = memcpy_s(display_endspace, sizeof(display_endspace), state->endspace, OGSQL_HISTORY_BUF_SIZE);
    if (rc != EOK) {
        return OGSQL_REVERSE_SEARCH_CANCEL;
    }

    OgsqlMoveToLineEnd(state, ctx);
    OgsqlClearEditInputDisplay(state, ctx);
    displayState.nwidths = 0;
    displayState.spacenum = 0;
    failed = (ogsql_reverse_search_refresh_match(histCount, query, queryLen, 0, &current_match) == OG_TRUE) ?
        OG_FALSE : OG_TRUE;
    search = (OgsqlReverseSearchStateT){ histCount, listNum, originalListNum, query, queryLen, current_match, failed,
        state, ctx, &displayState, &originalState };
    OgsqlReverseSearchRenderCurrent(&search);

    while (ogsql_getchar_blocking(&key_char)) {
        result = ogsql_reverse_search_dispatch_key(&search, key_char);
        if (result != OGSQL_REVERSE_SEARCH_CONTINUE) {
            return result;
        }
    }
    return OGSQL_REVERSE_SEARCH_CANCEL;
}

void ogsql_clear_previous_input_line(char *cmdBuf, uint32 nbytes, uint32 prompt_width, uint32 line_width,
    uint32 recorded_rows)
{
    uint32 ws_col = ogsql_get_terminal_columns();
    uint32 padding_spaces = ogsql_render_padding_before_cursor(cmdBuf, nbytes, nbytes, prompt_width, ws_col);
    uint32 rendered_width = line_width + padding_spaces;
    uint32 row_count;

    if (ws_col == 0) {
        ws_col = OGSQL_DEFAULT_TERMINAL_COLUMNS;
    }

    /* We are on the next continuation prompt after the previous input line was
       accepted, so move up from that prompt to the previous prompt row. If the
       previous rendered line ended exactly at the last column, OgsqlWriteWrappedText()
       has already moved the cursor to a blank physical row; the final +1 covers
       the accepted newline in both exact-width and non-exact-width cases. */
    row_count = (recorded_rows > 0) ? recorded_rows : ((prompt_width + rendered_width) / ws_col + 1);

    while (row_count--) {
        ogsql_terminal_write(OGSQL_ANSI_SEQ_LEN, "\033[A");
    }
    ogsql_terminal_write(OGSQL_ANSI_CLEAR_SEQ_LEN, "\r\033[J");
}

static void OgsqlRedrawInsertedCompletion(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    const OgsqlCompletionRedrawCtxT *redrawCtx)
{
    uint32 tailWidth;
    OgsqlLineEditStateT cursorState;

    if (redrawCtx == NULL) {
        return;
    }
    tailWidth = redrawCtx->oldNwidths - redrawCtx->oldCursor.width;
    if (ctx->wsCol > 0) {
        cursorState = *state;
        OgsqlRedrawWholeInputFromRow(&cursorState, ctx, redrawCtx->oldRow);
        return;
    }
    ogsql_terminal_write(state->nbytes - redrawCtx->oldCursor.pos, state->cmdBuf + redrawCtx->oldCursor.pos);
    ogsql_cmd_move_left(tailWidth, state->nwidths, ctx->welcomeWidth, ctx->wsCol, ctx->endspace);
}

static bool32 OgsqlInsertCompletionText(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    const char *insertText, uint32 insertLen)
{
    errno_t rc;
    OgsqlCursorT oldCursor;
    OgsqlCompletionRedrawCtxT redrawCtx;
    uint32 oldNwidths;
    uint32 oldRow = 0;
    uint32 insertWidth;

    if (state == NULL || ctx == NULL || insertLen == 0 ||
        state->nbytes + insertLen > state->maxLen - OGSQL_CMD_BUF_RESET_TAIL_LEN ||
        state->nbytes + insertLen > OGSQL_HISTORY_BUF_SIZE - OGSQL_CMD_BUF_RESET_TAIL_LEN) {
        return OG_FALSE;
    }

    insertWidth = ogsql_text_display_width(insertText, insertLen);
    oldCursor = (OgsqlCursorT){ state->cursorPos, state->cursorWidth };
    oldNwidths = state->nwidths;
    if (ctx->wsCol > 0) {
        oldRow = OgsqlRenderRowAtCursor(state, ctx);
    }
    if (oldCursor.pos < state->nbytes) {
        rc = memmove_s(state->cmdBuf + oldCursor.pos + insertLen, state->maxLen - oldCursor.pos - insertLen,
            state->cmdBuf + oldCursor.pos, state->nbytes - oldCursor.pos);
        if (rc != EOK) {
            return OG_FALSE;
        }
    }
    rc = memcpy_s(state->cmdBuf + oldCursor.pos, state->maxLen - oldCursor.pos, insertText, insertLen);
    if (rc != EOK) {
        return OG_FALSE;
    }

    state->nbytes += insertLen;
    state->nwidths += insertWidth;
    state->cmdBuf[state->nbytes] = '\0';
    state->cursorPos = oldCursor.pos + insertLen;
    state->cursorWidth = oldCursor.width + insertWidth;
    redrawCtx = (OgsqlCompletionRedrawCtxT){ oldCursor, oldNwidths, oldRow };
    OgsqlRedrawInsertedCompletion(state, ctx, &redrawCtx);
    return OG_TRUE;
}

static void OgsqlAdjustCompletionRowWrap(OgsqlCompletionRowsT *rows)
{
    while (rows->col >= rows->wsCol) {
        rows->col -= rows->wsCol;
        if (rows->col == 0) {
            continue;
        }
        rows->row++;
        if (rows->row > rows->maxRow) {
            rows->maxRow = rows->row;
        }
    }
}

static void OgsqlCountCompletionTextRows(const char *text, uint32 len, OgsqlCompletionRowsT *rows)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;

    if (rows == NULL || rows->wsCol == 0) {
        return;
    }
    while (offset < len) {
        if (cm_utf8_chr_bytes((uint8)text[offset], &c_bytes) != OG_SUCCESS || c_bytes == 0 ||
            offset + c_bytes > len || c_bytes > OGSQL_UTF8_CHR_SIZE) {
            c_bytes = 1;
            c_widths = 1;
        } else {
            c_widths = ogsql_utf8_chr_widths((char *)text + offset, c_bytes);
            if (c_widths == OG_INVALID_ID32) {
                c_bytes = 1;
                c_widths = 1;
            }
        }

        if (rows->col + c_widths > rows->wsCol) {
            rows->row++;
            rows->col = 0;
        }
        if (rows->row > rows->maxRow) {
            rows->maxRow = rows->row;
        }
        rows->col += c_widths;
        OgsqlAdjustCompletionRowWrap(rows);
        offset += c_bytes;
    }
}

static uint32 ogsql_completion_match_rows(const char **matches, uint32 match_count, uint32 ws_col)
{
    OgsqlCompletionRowsT rows = { ws_col, 1, 0, 1 };

    if (match_count == 0) {
        return 0;
    }
    if (rows.wsCol == 0) {
        rows.wsCol = OGSQL_DEFAULT_TERMINAL_COLUMNS;
    }

    for (uint32 i = 0; i < match_count; i++) {
        uint32 wordLen = (uint32)strlen(matches[i]);
        OgsqlCountCompletionTextRows(matches[i], wordLen, &rows);
        if ((i + 1) % OGSQL_COMPLETION_COLUMN_COUNT == 0 || i + 1 == match_count) {
            rows.row++;
            rows.col = 0;
        } else {
            OgsqlCountCompletionTextRows("    ", OGSQL_COMPLETION_INDENT_LEN, &rows);
        }
    }

    return rows.maxRow;
}

static void OgsqlPrintCompletionMatches(const OgsqlCompletionPrintCtxT *printCtx)
{
    uint32 welcome_len;
    const OgsqlRenderCtxT *ctx;
    OgsqlLineEditStateT *state;

    if (printCtx == NULL || printCtx->matches == NULL || printCtx->state == NULL || printCtx->renderCtx == NULL) {
        return;
    }
    ctx = printCtx->renderCtx;
    state = printCtx->state;
    welcome_len = (ctx->welcomeBuf == NULL) ? 0 : (uint32)strlen(ctx->welcomeBuf);
    if (state->cursorPos < state->nbytes) {
        if (ctx->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(state, ctx, (OgsqlCursorT){ state->cursorPos, state->cursorWidth },
                (OgsqlCursorT){ state->nbytes, state->nwidths });
        } else {
            ogsql_cmd_move_right(state->nwidths - state->cursorWidth, state->cursorWidth, ctx->welcomeWidth,
                ctx->wsCol, ctx->endspace);
        }
    }
    ogsql_terminal_write(1, "\n");
    if (printCtx->displayBaseRows != NULL) {
        *printCtx->displayBaseRows += ogsql_input_render_rows(state->cmdBuf, state->nbytes, state->nwidths,
            ctx->welcomeWidth, ctx->wsCol);
        *printCtx->displayBaseRows += ogsql_completion_match_rows(printCtx->matches, printCtx->matchCount,
            ctx->wsCol);
    }
    for (uint32 i = 0; i < printCtx->matchCount; i++) {
        uint32 word_len = (uint32)strlen(printCtx->matches[i]);

        ogsql_terminal_write(word_len, printCtx->matches[i]);
        if ((i + 1) % OGSQL_COMPLETION_COLUMN_COUNT == 0 || i + 1 == printCtx->matchCount) {
            ogsql_terminal_write(1, "\n");
        } else {
            ogsql_terminal_write(OGSQL_COMPLETION_INDENT_LEN, "    ");
        }
    }

    if (welcome_len > 0) {
        ogsql_terminal_write(welcome_len, ctx->welcomeBuf);
    }
    OgsqlWriteWrappedText(state->cmdBuf, state->nbytes, ctx->welcomeWidth, ctx);
    if (state->cursorPos < state->nbytes) {
        if (ctx->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(state, ctx, (OgsqlCursorT){ state->nbytes, state->nwidths },
                (OgsqlCursorT){ state->cursorPos, state->cursorWidth });
        } else {
            ogsql_cmd_move_left(state->nwidths - state->cursorWidth, state->nwidths, ctx->welcomeWidth, ctx->wsCol,
                ctx->endspace);
        }
    }
}

static void OgsqlHandleTabCompletion(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    uint32 *displayBaseRows, const ogsql_cmd_def_t *commandDefs, uint32 commandCount);

static void OgsqlReadlineMakeEditState(const OgsqlReadlineLoopT *loop, OgsqlLineEditStateT *state,
    OgsqlRenderCtxT *ctx)
{
    if (loop == NULL || state == NULL || ctx == NULL) {
        return;
    }
    *state = (OgsqlLineEditStateT){ loop->cmdBuf, loop->maxLen, *loop->nbytes, *loop->nwidths, *loop->cursorPos,
        *loop->cursorWidth, *loop->spacenum, loop->endspace };
    *ctx = OgsqlMakeRenderCtx(loop->welcomeBuf, loop->welcomeWidth, *loop->wsCol, loop->endspace);
}

static void OgsqlReadlineSaveEditState(const OgsqlReadlineLoopT *loop, const OgsqlLineEditStateT *state,
    const OgsqlRenderCtxT *ctx)
{
    if (loop == NULL || state == NULL || ctx == NULL) {
        return;
    }
    *loop->nbytes = state->nbytes;
    *loop->nwidths = state->nwidths;
    *loop->cursorPos = state->cursorPos;
    *loop->cursorWidth = state->cursorWidth;
    *loop->spacenum = state->spacenum;
    *loop->wsCol = ctx->wsCol;
}

static void OgsqlReadlineRefreshEndspace(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlRefreshCurrentEndspace(&state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
}

static void OgsqlReadlineMoveBegin(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlMoveToLineBegin(&state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
}

static void OgsqlReadlineMoveEnd(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlMoveToLineEnd(&state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
}

static void OgsqlReadlineDeleteCurrent(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlDeleteCharAtCursor(&state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
    OgsqlReadlineRefreshEndspace(loop);
}

static void OgsqlReadlineDeleteToEnd(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlDeleteToLineEnd(&state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
    OgsqlReadlineRefreshEndspace(loop);
}

static void OgsqlReadlineDeleteBefore(const OgsqlReadlineLoopT *loop, OgsqlCursorT startCursor)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlDeleteBeforeCursor(&state, &ctx, startCursor);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
    OgsqlReadlineRefreshEndspace(loop);
}

static void OgsqlReadlineHandleTab(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlHandleTabCompletion(&state, &ctx, loop->displayBaseRows, loop->commandDefs, loop->commandCount);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
}

static bool32 ogsql_readline_handle_reverse_search(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;
    OgsqlReverseSearchResultT result;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    result = OgsqlReverseHistorySearch(*loop->histCount, loop->listNum, &state, &ctx);
    OgsqlReadlineSaveEditState(loop, &state, &ctx);
    return (result == OGSQL_REVERSE_SEARCH_ACCEPT_EXECUTE) ? OG_TRUE : OG_FALSE;
}

static void OgsqlReadlineHandleCtrlD(const OgsqlReadlineLoopT *loop)
{
    if (*loop->nbytes == 0) {
        *loop->readResult = OGSQL_READLINE_RESULT_STOP;
        return;
    }
    OgsqlReadlineDeleteCurrent(loop);
}

static void OgsqlReadlineDeletePrevWord(const OgsqlReadlineLoopT *loop)
{
    uint32 startPos = 0;
    uint32 startWidth = 0;

    if (ogsql_get_prev_word_start(loop->cmdBuf, *loop->cursorPos, *loop->cursorWidth, &startPos,
        &startWidth) == OG_SUCCESS) {
        OgsqlReadlineDeleteBefore(loop, (OgsqlCursorT){ startPos, startWidth });
    }
}

static void OgsqlReadlineClearScreen(const OgsqlReadlineLoopT *loop)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    OgsqlClearScreenAndRedraw(&state, &ctx);
    *loop->displayBaseRows = 0;
}

static void OgsqlReadlineHandleBackspace(const OgsqlReadlineLoopT *loop)
{
    uint32 cBytes = 0;
    uint32 cWidths = 0;

    if (*loop->cursorPos == 0) {
        if (*loop->nbytes == 0 && loop->allowAbortLine) {
            *loop->lineAborted = OG_TRUE;
        }
        return;
    }
    if (*loop->nbytes == 0 || ogsql_get_prev_char(loop->cmdBuf, *loop->cursorPos, &cBytes, &cWidths) !=
        OG_SUCCESS) {
        return;
    }
    OgsqlReadlineDeleteBefore(loop, (OgsqlCursorT){ *loop->cursorPos - cBytes, *loop->cursorWidth - cWidths });
}

static bool32 ogsql_readline_consume_tilde_key(int32 escKey, int32 directionKey)
{
    int32 endKey;

    if (directionKey != CMD_KEY_HOME_OLD && directionKey != CMD_KEY_HOME_ALT &&
        directionKey != CMD_KEY_END_OLD && directionKey != CMD_KEY_END_ALT &&
        directionKey != CMD_KEY_DEL) {
        return OG_TRUE;
    }
    if (!ogsql_getchar_with_timeout(&endKey, OGSQL_SELECT_RETRY_TIMEOUT_MS)) {
        return OG_FALSE;
    }
    if (endKey == '~') {
        return OG_TRUE;
    }
    if (ogsql_escape_sequence_can_have_params(escKey)) {
        ogsql_drain_escape_sequence(endKey);
    }
    return OG_FALSE;
}

static bool32 ogsql_readline_handle_home_end(const OgsqlReadlineLoopT *loop, int32 escKey, int32 directionKey)
{
    if (directionKey == CMD_KEY_HOME || directionKey == CMD_KEY_HOME_OLD || directionKey == CMD_KEY_HOME_ALT) {
        if (ogsql_readline_consume_tilde_key(escKey, directionKey)) {
            OgsqlReadlineMoveBegin(loop);
        }
        return OG_TRUE;
    }
    if (directionKey == CMD_KEY_END || directionKey == CMD_KEY_END_OLD || directionKey == CMD_KEY_END_ALT) {
        if (ogsql_readline_consume_tilde_key(escKey, directionKey)) {
            OgsqlReadlineMoveEnd(loop);
        }
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 ogsql_readline_handle_history_key(const OgsqlReadlineLoopT *loop, int32 directionKey)
{
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    if (directionKey == CMD_KEY_UP) {
        if (*loop->histCount > 0 && *loop->listNum < *loop->histCount) {
            OgsqlReadlineMoveEnd(loop);
            OgsqlReadlineMakeEditState(loop, &state, &ctx);
            OgsqlHistTurnUp(loop->histCount, loop->listNum, &state, &ctx);
            OgsqlReadlineSaveEditState(loop, &state, &ctx);
        }
        return OG_TRUE;
    }
    if (directionKey == CMD_KEY_DOWN) {
        if (*loop->listNum >= 1) {
            OgsqlReadlineMoveEnd(loop);
            OgsqlReadlineMakeEditState(loop, &state, &ctx);
            OgsqlHistTurnDown(loop->histCount, loop->listNum, &state, &ctx);
            OgsqlReadlineSaveEditState(loop, &state, &ctx);
        }
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 ogsql_readline_handle_arrow_key(const OgsqlReadlineLoopT *loop, int32 directionKey)
{
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    if (directionKey == CMD_KEY_RIGHT) {
        if (*loop->cursorPos >= *loop->nbytes ||
            ogsql_get_current_char(loop->cmdBuf, *loop->cursorPos, *loop->nbytes, &c_bytes, &c_widths) != OG_SUCCESS) {
            return OG_TRUE;
        }
        OgsqlReadlineMakeEditState(loop, &state, &ctx);
        if (*loop->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(&state, &ctx, (OgsqlCursorT){ *loop->cursorPos, *loop->cursorWidth },
                (OgsqlCursorT){ *loop->cursorPos + c_bytes, *loop->cursorWidth + c_widths });
        } else {
            ogsql_cmd_move_right(c_widths, *loop->cursorWidth, loop->welcomeWidth, *loop->wsCol, loop->endspace);
        }
        *loop->cursorPos += c_bytes;
        *loop->cursorWidth += c_widths;
        return OG_TRUE;
    }
    if (directionKey == CMD_KEY_LEFT) {
        if (*loop->cursorPos == 0 || ogsql_get_prev_char(loop->cmdBuf, *loop->cursorPos, &c_bytes, &c_widths) !=
            OG_SUCCESS) {
            return OG_TRUE;
        }
        OgsqlReadlineMakeEditState(loop, &state, &ctx);
        if (*loop->wsCol > 0) {
            OgsqlMoveCursorToRenderPos(&state, &ctx, (OgsqlCursorT){ *loop->cursorPos, *loop->cursorWidth },
                (OgsqlCursorT){ *loop->cursorPos - c_bytes, *loop->cursorWidth - c_widths });
        } else {
            ogsql_cmd_move_left(c_widths, *loop->cursorWidth, loop->welcomeWidth, *loop->wsCol, loop->endspace);
        }
        *loop->cursorPos -= c_bytes;
        *loop->cursorWidth -= c_widths;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void OgsqlReadlineHandleEscape(const OgsqlReadlineLoopT *loop)
{
    int32 escKey;
    int32 directionKey;

    if (!ogsql_read_escape_keys(&escKey, &directionKey)) {
        return;
    }
    if (ogsql_readline_handle_home_end(loop, escKey, directionKey) ||
        ogsql_readline_handle_history_key(loop, directionKey) ||
        ogsql_readline_handle_arrow_key(loop, directionKey)) {
        return;
    }
    if (directionKey == CMD_KEY_DEL && ogsql_readline_consume_tilde_key(escKey, directionKey)) {
        OgsqlReadlineDeleteCurrent(loop);
        return;
    }
    if (ogsql_escape_sequence_can_have_params(escKey)) {
        ogsql_drain_escape_sequence(directionKey);
    }
}

static bool32 ogsql_readline_read_utf8_char(const OgsqlReadlineLoopT *loop, int32 firstKey, uint32 *cBytes,
    uint32 *cWidths)
{
    int32 keyChar;

    if (cm_utf8_chr_bytes((uint8)firstKey, cBytes) != OG_SUCCESS || *cBytes == 0 ||
        *cBytes > OGSQL_UTF8_CHR_SIZE || *loop->nbytes + *cBytes > loop->maxLen - OGSQL_CMD_BUF_RESET_TAIL_LEN) {
        return OG_FALSE;
    }

    loop->chr[0] = (char)firstKey;
    for (uint32 i = 1; i < *cBytes; i++) {
        if (!ogsql_getchar_with_timeout(&keyChar, OGSQL_SELECT_RETRY_TIMEOUT_MS) ||
            !IS_VALID_UTF8_CHAR((uint8)keyChar)) {
            return OG_FALSE;
        }
        loop->chr[i] = (char)keyChar;
    }

    *cWidths = ogsql_utf8_chr_widths(loop->chr, *cBytes);
    return (*cWidths == OG_INVALID_ID32) ? OG_FALSE : OG_TRUE;
}

static void ogsql_readline_redraw_inserted_char(const OgsqlReadlineLoopT *loop, uint32 cBytes, uint32 cWidths,
    bool32 appendChar, uint32 oldRow, uint32 appendStartTotal)
{
    uint32 tailWidth;
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;

    OgsqlReadlineMakeEditState(loop, &state, &ctx);
    if (appendChar) {
        if (state.nbytes == cBytes && ctx.wsCol > 0) {
            state.cursorPos = state.nbytes;
            state.cursorWidth = state.nwidths;
            OgsqlRedrawWholeInputFromRow(&state, &ctx, 0);
        } else {
            OgsqlWriteWrappedText(loop->chr, cBytes, appendStartTotal, &ctx);
        }
        return;
    }

    if (ctx.wsCol > 0) {
        state.cursorPos = *loop->cursorPos + cBytes;
        state.cursorWidth = *loop->cursorWidth + cWidths;
        OgsqlRedrawWholeInputFromRow(&state, &ctx, oldRow);
    } else {
        tailWidth = state.nwidths - cWidths - *loop->cursorWidth;
        OgsqlWriteWrappedText(loop->cmdBuf + *loop->cursorPos, state.nbytes - *loop->cursorPos,
            ctx.welcomeWidth + *loop->cursorWidth, &ctx);
        ogsql_cmd_move_left(tailWidth, state.nwidths, loop->welcomeWidth, *loop->wsCol, loop->endspace);
    }
}

static uint32 OgsqlReadlineAppendRenderTotal(const OgsqlReadlineLoopT *loop, uint32 startTotal, uint32 cWidths)
{
    uint32 total = startTotal;
    uint32 line;

    if (loop == NULL || loop->wsCol == NULL || *loop->wsCol == 0) {
        return total + cWidths;
    }
    if (cWidths == OGSQL_WIDE_CHAR_WIDTH && total % *loop->wsCol == *loop->wsCol - 1) {
        line = total / *loop->wsCol + 1;
        if (loop->endspace != NULL && line < OGSQL_HISTORY_BUF_SIZE) {
            loop->endspace[line] = OG_TRUE;
        }
        if (loop->spacenum != NULL) {
            (*loop->spacenum)++;
        }
        total++;
    }
    return total + cWidths;
}

static void ogsql_readline_insert_char(const OgsqlReadlineLoopT *loop, uint32 cBytes, uint32 cWidths)
{
    bool32 appendChar = (*loop->cursorPos == *loop->nbytes) ? OG_TRUE : OG_FALSE;
    uint32 oldRow = 0;
    uint32 appendStartTotal = 0;
    OgsqlLineEditStateT state;
    OgsqlRenderCtxT ctx;
    errno_t rc;

    if (appendChar) {
        if (*loop->cursorRenderTotalValid == OG_TRUE) {
            appendStartTotal = *loop->cursorRenderTotal;
        } else {
            OgsqlReadlineMakeEditState(loop, &state, &ctx);
            appendStartTotal = OgsqlRenderTotalAtCursor(&state, &ctx,
                (OgsqlCursorT){ state.cursorPos, state.cursorWidth });
        }
    } else if (*loop->wsCol > 0) {
        OgsqlReadlineMakeEditState(loop, &state, &ctx);
        oldRow = OgsqlRenderRowAtCursor(&state, &ctx);
    }
    if (*loop->cursorPos < *loop->nbytes) {
        rc = memmove_s(loop->cmdBuf + *loop->cursorPos + cBytes,
            loop->maxLen - (*loop->cursorPos + cBytes), loop->cmdBuf + *loop->cursorPos,
            *loop->nbytes - *loop->cursorPos);
        if (rc != EOK) {
            return;
        }
    }
    rc = memcpy_s(loop->cmdBuf + *loop->cursorPos, loop->maxLen - *loop->cursorPos, loop->chr, cBytes);
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return;
    }

    *loop->nbytes += cBytes;
    *loop->nwidths += cWidths;
    loop->cmdBuf[*loop->nbytes] = '\0';
    if (appendChar) {
        *loop->cursorRenderTotal = OgsqlReadlineAppendRenderTotal(loop, appendStartTotal, cWidths);
        *loop->cursorRenderTotalValid = OG_TRUE;
    } else {
        OgsqlReadlineRefreshEndspace(loop);
        *loop->cursorRenderTotalValid = OG_FALSE;
    }
    ogsql_readline_redraw_inserted_char(loop, cBytes, cWidths, appendChar, oldRow, appendStartTotal);
    *loop->cursorPos += cBytes;
    *loop->cursorWidth += cWidths;
}

static void ogsql_readline_handle_printable(const OgsqlReadlineLoopT *loop, int32 firstKey)
{
    uint32 cBytes = 0;
    uint32 cWidths = 0;

    if (ogsql_readline_read_utf8_char(loop, firstKey, &cBytes, &cWidths)) {
        ogsql_readline_insert_char(loop, cBytes, cWidths);
    }
}

static void OgsqlHandleTabCompletion(OgsqlLineEditStateT *state, const OgsqlRenderCtxT *ctx,
    uint32 *displayBaseRows, const ogsql_cmd_def_t *commandDefs, uint32 commandCount)
{
    uint32 token_start = 0;
    uint32 token_len = 0;
    uint32 match_count;
    uint32 common_len;
    uint32 suffix_len;
    const char *matches[OGSQL_MAX_COMPLETION_MATCHES];
    char dynamic_words[OGSQL_MAX_COMPLETION_MATCHES][OGSQL_OBJ_NAME_LEN];
    char common[OGSQL_MAX_COMPLETION_WORD_LEN];
    char suffix[OGSQL_MAX_COMPLETION_WORD_LEN];
    uint32 dynamic_count = 0;
    OgsqlCompletionStoreT store = { matches, &match_count, dynamic_words, &dynamic_count };
    OgsqlCompletionRequestT request;
    OgsqlCompletionPrintCtxT printCtx;

    if (state == NULL || ctx == NULL ||
        ogsql_completion_find_token(state->cmdBuf, state->cursorPos, &token_start, &token_len) != OG_SUCCESS) {
        return;
    }

    request = (OgsqlCompletionRequestT){ state->cmdBuf, state->cursorPos, token_start, state->cmdBuf + token_start,
        token_len, commandDefs, commandCount };
    match_count = ogsql_completion_collect(&request, &store);
    if (match_count == 0) {
        return;
    }

    if (match_count == 1) {
        suffix_len = ogsql_completion_make_suffix(matches[0], state->cmdBuf + token_start, token_len, suffix,
            sizeof(suffix));
        if (OgsqlInsertCompletionText(state, ctx, suffix, suffix_len)) {
            OgsqlRefreshCurrentEndspace(state, ctx);
        }
        return;
    }

    common_len = ogsql_completion_common_prefix(matches, match_count, common, sizeof(common));
    if (common_len > token_len) {
        suffix_len = ogsql_completion_make_suffix(common, state->cmdBuf + token_start, token_len, suffix,
            sizeof(suffix));
        if (OgsqlInsertCompletionText(state, ctx, suffix, suffix_len)) {
            OgsqlRefreshCurrentEndspace(state, ctx);
        }
        return;
    }

    printCtx = (OgsqlCompletionPrintCtxT){ matches, match_count, state, ctx, displayBaseRows };
    OgsqlPrintCompletionMatches(&printCtx);
}

static void OgsqlReadlineUpdateEditState(OgsqlReadlineSessionT *session)
{
    session->renderCtx = OgsqlMakeRenderCtx(session->baseRenderCtx->welcomeBuf,
        session->baseRenderCtx->welcomeWidth, session->wsCol, session->endspace);
    session->editState = (OgsqlLineEditStateT){ session->state->cmdBuf, session->state->maxLen, session->nbytes,
        session->nwidths, session->cursorPos, session->cursorWidth, session->spacenum, session->endspace };
}

static bool32 ogsql_readline_init_session(OgsqlReadlineSessionT *session, OgsqlLineEditStateT *state,
    OgsqlRenderCtxT *baseRenderCtx, OgsqlReadlineCtxT *readlineCtx)
{
    errno_t rc;

    if (session == NULL || state == NULL || baseRenderCtx == NULL || readlineCtx == NULL ||
        readlineCtx->histCount == NULL || readlineCtx->listNum == NULL || readlineCtx->abortLine == NULL) {
        return OG_FALSE;
    }
    rc = memset_s(session, sizeof(OgsqlReadlineSessionT), 0, sizeof(OgsqlReadlineSessionT));
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return OG_FALSE;
    }

    session->state = state;
    session->baseRenderCtx = baseRenderCtx;
    session->readlineCtx = readlineCtx;
    session->readResult = OGSQL_READLINE_RESULT_OK;
    *readlineCtx->abortLine = OG_FALSE;
    if (readlineCtx->acceptedInputLen != NULL) {
        *readlineCtx->acceptedInputLen = 0;
    }
    if (readlineCtx->acceptedRenderRows != NULL) {
        *readlineCtx->acceptedRenderRows = 0;
    }
#ifndef WIN32
    session->wsCol = ogsql_get_terminal_columns();
#endif
    session->loop = (OgsqlReadlineLoopT){ readlineCtx->histCount, readlineCtx->listNum, state->cmdBuf,
        state->maxLen, baseRenderCtx->welcomeBuf, baseRenderCtx->welcomeWidth, &session->wsCol, &session->nbytes,
        &session->nwidths, &session->cursorPos, &session->cursorWidth, &session->spacenum, session->endspace,
        &session->displayBaseRows, readlineCtx->allowAbortLine, &session->lineAborted, &session->readResult,
        session->chr, &session->cursorRenderTotal, &session->cursorRenderTotalValid, readlineCtx->commandDefs,
        readlineCtx->commandCount };
    session->cursorRenderTotal = baseRenderCtx->welcomeWidth;
    session->cursorRenderTotalValid = OG_TRUE;
    return OG_TRUE;
}

static OgsqlReadlineResultT OgsqlReadlineEnterRawMode(OgsqlReadlineSessionT *session)
{
#ifndef WIN32
    struct termios newt;
    errno_t rc;

    if (tcgetattr(STDIN_FILENO, &session->oldt) != 0) {
        return OGSQL_READLINE_RESULT_FALLBACK;
    }
    rc = memcpy_s(&newt, sizeof(newt), &session->oldt, sizeof(session->oldt));
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return OGSQL_READLINE_RESULT_STOP;
    }
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL);
    newt.c_iflag &= ~ICRNL;
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &session->oldt);
        return OGSQL_READLINE_RESULT_FALLBACK;
    }
    session->terminalRawEnabled = OG_TRUE;
#else
    (void)session;
#endif
    return OGSQL_READLINE_RESULT_OK;
}

static void OgsqlReadlineLeaveRawMode(OgsqlReadlineSessionT *session)
{
#ifndef WIN32
    if (session->terminalRawEnabled) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &session->oldt);
    }
#else
    (void)session;
#endif
}

static void OgsqlReadlinePreloadInput(OgsqlReadlineSessionT *session)
{
    uint32 preloadLen = session->readlineCtx->preloadLen;

    if (preloadLen == 0) {
        return;
    }
    session->nbytes = preloadLen;
    session->nwidths = ogsql_text_display_width(session->state->cmdBuf, preloadLen);
    session->cursorPos = session->nbytes;
    session->cursorWidth = session->nwidths;
    OgsqlReadlineUpdateEditState(session);
    OgsqlRefreshCurrentEndspace(&session->editState, &session->renderCtx);
    session->spacenum = session->editState.spacenum;
    session->cursorRenderTotal = OgsqlRenderTotalAtCursor(&session->editState, &session->renderCtx,
        (OgsqlCursorT){ session->cursorPos, session->cursorWidth });
    session->cursorRenderTotalValid = OG_TRUE;
    OgsqlWriteWrappedText(session->state->cmdBuf, session->nbytes, session->renderCtx.welcomeWidth,
        &session->renderCtx);
}

static void OgsqlReadlineSyncResizeBeforeKey(OgsqlReadlineSessionT *session)
{
#ifndef WIN32
    uint32 oldWsCol = session->wsCol;

    OgsqlReadlineUpdateEditState(session);
    OgsqlSyncTerminalResize(&session->editState, &session->renderCtx);
    session->wsCol = session->renderCtx.wsCol;
    session->spacenum = session->editState.spacenum;
    if (session->wsCol != oldWsCol) {
        session->cursorRenderTotalValid = OG_FALSE;
    }
#else
    (void)session;
#endif
}

static void OgsqlReadlineDispatchKey(OgsqlReadlineSessionT *session)
{
    if (session->keyChar < ' ' || session->keyChar == CMD_KEY_ASCII_DEL) {
        session->cursorRenderTotalValid = OG_FALSE;
    }
    switch (session->keyChar) {
        case CMD_KEY_ESCAPE:
            OgsqlReadlineHandleEscape(&session->loop);
            return;
        case CMD_KEY_TAB:
            OgsqlReadlineHandleTab(&session->loop);
            return;
        case CMD_KEY_CTRL_R:
            if (ogsql_readline_handle_reverse_search(&session->loop)) {
                session->keyChar = CMD_KEY_ASCII_LF;
            }
            return;
        case CMD_KEY_CTRL_A:
            OgsqlReadlineMoveBegin(&session->loop);
            return;
        case CMD_KEY_CTRL_E:
            OgsqlReadlineMoveEnd(&session->loop);
            return;
        case CMD_KEY_CTRL_D:
            OgsqlReadlineHandleCtrlD(&session->loop);
            return;
        case CMD_KEY_CTRL_K:
            OgsqlReadlineDeleteToEnd(&session->loop);
            return;
        case CMD_KEY_CTRL_U:
            OgsqlReadlineDeleteBefore(&session->loop, (OgsqlCursorT){ 0, 0 });
            return;
        case CMD_KEY_CTRL_W:
            OgsqlReadlineDeletePrevWord(&session->loop);
            return;
        case CMD_KEY_CTRL_L:
            OgsqlReadlineClearScreen(&session->loop);
            return;
        case CMD_KEY_ASCII_DEL:
        case CMD_KEY_ASCII_BS:
            OgsqlReadlineHandleBackspace(&session->loop);
            return;
        case CMD_KEY_ASCII_CR:
        case CMD_KEY_ASCII_LF:
            *session->readlineCtx->listNum = 0;
            ogsql_terminal_write(1, "\n");
            return;
        default:
            ogsql_readline_handle_printable(&session->loop, session->keyChar);
            return;
    }
}

static void OgsqlReadlineReadLoop(OgsqlReadlineSessionT *session)
{
    while (session->readResult == OGSQL_READLINE_RESULT_OK && !session->lineAborted &&
        session->keyChar != CMD_KEY_ASCII_LF && session->keyChar != CMD_KEY_ASCII_CR) {
        if (!ogsql_getchar_blocking(&session->keyChar)) {
            session->readResult = OGSQL_READLINE_RESULT_STOP;
            break;
        }
        OgsqlReadlineSyncResizeBeforeKey(session);
        OgsqlReadlineDispatchKey(session);
    }
}

static void OgsqlReadlineFinishSuccess(OgsqlReadlineSessionT *session)
{
    OgsqlReadlineCtxT *ctx = session->readlineCtx;
    errno_t rc;

    if (ctx->acceptedInputLen != NULL) {
        *ctx->acceptedInputLen = session->nbytes;
    }
    if (ctx->acceptedRenderRows != NULL) {
        *ctx->acceptedRenderRows = session->displayBaseRows + ogsql_input_render_rows(session->state->cmdBuf,
            session->nbytes, session->nwidths, session->baseRenderCtx->welcomeWidth, session->wsCol);
    }
    OgsqlReadlineUpdateEditState(session);
    rc = memcpy_s(session->state->cmdBuf + session->nbytes, session->state->maxLen - session->nbytes, "\n",
        OGSQL_CMD_BUF_RESET_TAIL_LEN);
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        session->readResult = OGSQL_READLINE_RESULT_STOP;
    }
}

static void OgsqlReadlineFinish(OgsqlReadlineSessionT *session)
{
    if (session->lineAborted) {
        session->state->cmdBuf[0] = '\0';
        *session->readlineCtx->abortLine = OG_TRUE;
        ogsql_terminal_write(OGSQL_ANSI_CLEAR_SEQ_LEN, "\r\033[K");
    } else if (session->readResult == OGSQL_READLINE_RESULT_OK) {
        OgsqlReadlineFinishSuccess(session);
    }

    OgsqlReadlineLeaveRawMode(session);
    session->state->nbytes = session->nbytes;
    session->state->nwidths = session->nwidths;
    session->state->cursorPos = session->cursorPos;
    session->state->cursorWidth = session->cursorWidth;
    session->state->spacenum = session->spacenum;
    session->baseRenderCtx->wsCol = session->wsCol;
}

OgsqlReadlineResultT ogsql_line_editor_read(OgsqlLineEditStateT *state, OgsqlRenderCtxT *baseRenderCtx,
    OgsqlReadlineCtxT *readlineCtx)
{
    OgsqlReadlineSessionT session;
    OgsqlReadlineResultT rawModeResult;

    if (!ogsql_readline_init_session(&session, state, baseRenderCtx, readlineCtx)) {
        return OGSQL_READLINE_RESULT_STOP;
    }

    rawModeResult = OgsqlReadlineEnterRawMode(&session);
    if (rawModeResult != OGSQL_READLINE_RESULT_OK) {
        return rawModeResult;
    }
    OgsqlReadlinePreloadInput(&session);
    OgsqlReadlineReadLoop(&session);
    OgsqlReadlineFinish(&session);
    return session.readResult;
}

bool32 ogsql_line_editor_should_use(FILE *in, bool32 is_file)
{
#ifdef WIN32
    (void)in;
    (void)is_file;
    return OG_FALSE;
#else
    return (g_local_config.history_on == OG_TRUE && is_file == OG_FALSE && in == stdin &&
        isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) ? OG_TRUE : OG_FALSE;
#endif
}
