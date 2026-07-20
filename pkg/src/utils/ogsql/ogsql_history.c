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
 * ogsql_history.c
 *
 * -------------------------------------------------------------------------
 */
#include <string.h>
#include "cm_util.h"
#include "ogsql_history.h"

#define OGSQL_ASCII_MAX 127

typedef struct OgsqlHistoryInputT {
    char *cmdBuf;
    uint32 nbytes;
    uint32 nwidths;
} OgsqlHistoryInputT;

typedef struct OgsqlHistoryMatchRankT {
    uint32 tokenExtra;
    uint32 statementExtra;
    uint32 historyIndex;
} OgsqlHistoryMatchRankT;

/* Slots 1..N form a ring buffer; slot 0 is reserved for draft restoration.
 * The default history size of 32 limits usable entries but does not reduce this fixed allocation.
 * With the current maximum of 100, the worst-case resident size is about 405 KiB. */
static ogsql_cmd_history_list_t g_histList[OGSQL_MAX_HISTORY_SIZE + 1];
static uint32 g_histHead = 0;

static const char *const HISTORY_SENSITIVE_WORDS[] = {
    "PASSWORD",
    "IDENTIFIED",
    "GS_ENCRYPT_AES128",
    "GS_DECRYPT_AES128",
    "GS_ENCRYPT",
    "GS_DECRYPT",
    "AES_ENCRYPT",
    "AES_DECRYPT",
    "PG_CREATE_PHYSICAL_REPLICATION_SLOT_EXTERN",
    "SECRET_ACCESS_KEY",
    "SECRETKEY",
    "CREATE_CREDENTIAL",
    "ACCESS_KEY",
};
#define OGSQL_HISTORY_SENSITIVE_WORD_COUNT (sizeof(HISTORY_SENSITIVE_WORDS) / sizeof(HISTORY_SENSITIVE_WORDS[0]))

void ogsql_history_reset(void)
{
    g_histHead = 0;
    for (int i = 0; i <= OGSQL_MAX_HISTORY_SIZE; i++) {
        OGSQL_CHECK_MEMS_SECURE(memset_s(&g_histList[i], sizeof(g_histList[i]), 0, sizeof(g_histList[i])));
    }
}

status_t ogsql_history_save_draft(const char *text, uint32 nbytes, uint32 nwidths)
{
    errno_t rc;

    if (text == NULL || nbytes > ogsql_history_text_limit()) {
        return OG_ERROR;
    }
    rc = memcpy_s(g_histList[0].hist_buf, sizeof(g_histList[0].hist_buf), text, nbytes);
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return OG_ERROR;
    }
    g_histList[0].hist_buf[nbytes] = '\0';
    g_histList[0].nbytes = nbytes;
    g_histList[0].nwidths = nwidths;
    return OG_SUCCESS;
}

const ogsql_cmd_history_list_t *ogsql_history_get_draft(void)
{
    return &g_histList[0];
}
static char OgsqlHistoryUpperChar(char ch)
{
    return (ch >= 'a' && ch <= 'z') ? (ch - ('a' - 'A')) : ch;
}

static bool32 ogsql_history_contains_sensitive_word(const char *cmdBuf, uint32 cmd_bytes, const char *word)
{
    uint32 word_len;

    if (cmdBuf == NULL || word == NULL) {
        return OG_FALSE;
    }

    word_len = (uint32)strlen(word);
    if (word_len == 0 || cmd_bytes < word_len) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i <= cmd_bytes - word_len; i++) {
        bool32 matched = OG_TRUE;

        for (uint32 j = 0; j < word_len; j++) {
            if (OgsqlHistoryUpperChar(cmdBuf[i + j]) != word[j]) {
                matched = OG_FALSE;
                break;
            }
        }

        if (matched == OG_TRUE) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static bool32 ogsql_history_contains_sensitive_keyword(const char *cmdBuf, uint32 cmd_bytes)
{
    for (uint32 i = 0; i < OGSQL_HISTORY_SENSITIVE_WORD_COUNT; i++) {
        if (ogsql_history_contains_sensitive_word(cmdBuf, cmd_bytes, HISTORY_SENSITIVE_WORDS[i]) == OG_TRUE) {
            return OG_TRUE;
        }
    }

    for (uint32 i = 0; i < g_local_config.history_sensitive_word_count; i++) {
        if (ogsql_history_contains_sensitive_word(cmdBuf, cmd_bytes,
            g_local_config.historySensitiveWords[i]) == OG_TRUE) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static bool32 ogsql_is_sensitive_history_cmd(char *cmdBuf, uint32 cmd_bytes)
{
    text_t ignore_passwd_text;
    int32 mattch_type;
    bool32 mattched = OG_FALSE;

    cm_str2text_safe(cmdBuf, cmd_bytes, &ignore_passwd_text);
    cm_text_try_map_key2type(&ignore_passwd_text, &mattch_type, &mattched);
    if (mattched == OG_TRUE) {
        return OG_TRUE;
    }

    return ogsql_history_contains_sensitive_keyword(cmdBuf, cmd_bytes);
}

uint32 ogsql_history_text_limit(void)
{
    uint32 historyBufferLimit = OGSQL_HISTORY_BUF_SIZE - OGSQL_CMD_BUF_RESET_TAIL_LEN;

    return (g_local_config.effective_max_sql_len < historyBufferLimit) ?
        g_local_config.effective_max_sql_len : historyBufferLimit;
}

static uint32 OgsqlHistoryPhysicalIndex(uint32 logicalIndex)
{
    uint32 historySize = g_local_config.history_size;
    uint32 zeroBasedHead;

    if (logicalIndex == 0 || logicalIndex > historySize || g_histHead == 0 ||
        historySize < OGSQL_MIN_HISTORY_SIZE || historySize > OGSQL_MAX_HISTORY_SIZE) {
        return 0;
    }
    zeroBasedHead = g_histHead - 1;
    return ((zeroBasedHead + historySize - (logicalIndex - 1)) % historySize) + 1;
}

const ogsql_cmd_history_list_t *ogsql_history_get(int histCount, uint32 logicalIndex)
{
    uint32 physicalIndex;

    if (histCount <= 0 || logicalIndex == 0 || logicalIndex > (uint32)histCount) {
        return NULL;
    }
    physicalIndex = OgsqlHistoryPhysicalIndex(logicalIndex);
    return (physicalIndex == 0) ? NULL : &g_histList[physicalIndex];
}

static bool32 OgsqlHistoryCanPush(const OgsqlHistoryInputT *state, int *histCount)
{
    if (state == NULL || histCount == NULL || state->cmdBuf == NULL) {
        return OG_FALSE;
    }
    if (g_local_config.history_on != OG_TRUE) {
        return OG_FALSE;
    }
    if (state->nbytes == 0) {
        return OG_FALSE;
    }
    if (state->nbytes > ogsql_history_text_limit()) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 OgsqlHistoryRejectSensitiveCmd(const OgsqlHistoryInputT *state)
{
    if (ogsql_is_sensitive_history_cmd(state->cmdBuf, state->nbytes) == OG_TRUE) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 OgsqlHistoryStoreCmd(const OgsqlHistoryInputT *state, int *histCount)
{
    ogsql_cmd_history_list_t *entry;
    uint32 historySize = g_local_config.history_size;
    uint32 nextHead;
    errno_t rc;

    if (historySize < OGSQL_MIN_HISTORY_SIZE || historySize > OGSQL_MAX_HISTORY_SIZE) {
        return OG_FALSE;
    }
    nextHead = (g_histHead >= historySize) ? 1 : (g_histHead + 1);
    entry = &g_histList[nextHead];
    rc = memcpy_s(entry->hist_buf, OGSQL_HISTORY_BUF_SIZE, state->cmdBuf, state->nbytes);
    if (rc != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return OG_FALSE;
    }
    entry->hist_buf[state->nbytes] = '\0';
    entry->nbytes = state->nbytes;
    entry->nwidths = state->nwidths;
    g_histHead = nextHead;
    if (*histCount < (int)historySize) {
        *histCount += 1;
    }
    return OG_TRUE;
}

static bool32 OgsqlHistoryPush(const OgsqlHistoryInputT *state, int *histCount)
{
    if (OgsqlHistoryCanPush(state, histCount) != OG_TRUE) {
        return OG_FALSE;
    }
    if (OgsqlHistoryRejectSensitiveCmd(state) == OG_TRUE) {
        return OG_FALSE;
    }
    return OgsqlHistoryStoreCmd(state, histCount);
}

void ogsql_history_pending_reset(OgsqlPendingHistoryT *pending)
{
    if (pending == NULL) {
        return;
    }
    OGSQL_CHECK_MEMS_SECURE(memset_s(pending->buf, sizeof(pending->buf), 0, sizeof(pending->buf)));
    pending->len = 0;
    pending->overflow = OG_FALSE;
}

void ogsql_history_pending_append(OgsqlPendingHistoryT *pending, const char *line, uint32 lineLen)
{
    uint32 historyTextLimit;
    uint32 separatorLen;
    errno_t rc;

    if (pending == NULL || line == NULL || pending->overflow == OG_TRUE) {
        return;
    }
    historyTextLimit = ogsql_history_text_limit();
    separatorLen = (pending->len > 0) ? 1 : 0;
    if (pending->len > historyTextLimit || separatorLen > historyTextLimit - pending->len ||
        lineLen > historyTextLimit - pending->len - separatorLen) {
        pending->overflow = OG_TRUE;
        return;
    }
    if (separatorLen > 0) {
        pending->buf[pending->len++] = '\n';
    }
    if (lineLen > 0) {
        rc = memcpy_s(pending->buf + pending->len, sizeof(pending->buf) - pending->len, line, lineLen);
        if (rc != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, rc);
            pending->overflow = OG_TRUE;
            return;
        }
        pending->len += lineLen;
    }
    pending->buf[pending->len] = '\0';
}

void ogsql_history_pending_restore(OgsqlPendingHistoryT *pending, uint32 len, bool32 overflow)
{
    if (pending == NULL) {
        return;
    }
    if (len > pending->len) {
        len = pending->len;
    }
    if (len < pending->len) {
        OGSQL_CHECK_MEMS_SECURE(memset_s(pending->buf + len, sizeof(pending->buf) - len, 0, pending->len - len));
    }
    pending->len = len;
    pending->buf[len] = '\0';
    pending->overflow = overflow;
}

void ogsql_history_pending_commit(OgsqlPendingHistoryT *pending, int *histCount, uint32 displayWidth)
{
    OgsqlHistoryInputT state;

    if (pending == NULL) {
        return;
    }
    if (pending->len > 0 && pending->overflow != OG_TRUE) {
        state = (OgsqlHistoryInputT){ pending->buf, pending->len, displayWidth };
        (void)OgsqlHistoryPush(&state, histCount);
    }
    ogsql_history_pending_reset(pending);
}

static bool32 ogsql_history_match_delimiter(char chr)
{
    uint8 value = (uint8)chr;

    if (value <= ' ') {
        return OG_TRUE;
    }
    switch (value) {
        case '\'':
        case '"':
        case ',':
        case ';':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '=':
        case '<':
        case '>':
        case '!':
        case '|':
        case '&':
        case '+':
        case '*':
        case '/':
        case '%':
        case '^':
        case '~':
        case '?':
        case ':':
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static bool32 ogsql_history_query_match_extra(const ogsql_cmd_history_list_t *entry, const char *query,
    uint32 queryLen, uint32 *tokenExtra)
{
    uint32 bestExtra = OG_INVALID_ID32;

    if (entry == NULL || query == NULL || tokenExtra == NULL || entry->nbytes < queryLen) {
        return OG_FALSE;
    }
    if (queryLen == 0) {
        *tokenExtra = 0;
        return OG_TRUE;
    }

    for (uint32 pos = 0; pos + queryLen <= entry->nbytes; pos++) {
        uint32 i;

        for (i = 0; i < queryLen; i++) {
            char left = entry->hist_buf[pos + i];
            char right = query[i];
            if (left >= 0 && left <= OGSQL_ASCII_MAX && right >= 0 && right <= OGSQL_ASCII_MAX) {
                left = OgsqlHistoryUpperChar(left);
                right = OgsqlHistoryUpperChar(right);
            }
            if (left != right) {
                break;
            }
        }
        if (i == queryLen) {
            uint32 tokenStart = pos;
            uint32 tokenEnd = pos + queryLen;

            while (tokenStart > 0 && !ogsql_history_match_delimiter(entry->hist_buf[tokenStart - 1])) {
                tokenStart--;
            }
            while (tokenEnd < entry->nbytes && !ogsql_history_match_delimiter(entry->hist_buf[tokenEnd])) {
                tokenEnd++;
            }
            bestExtra = MIN(bestExtra, (pos - tokenStart) + (tokenEnd - pos - queryLen));
        }
    }

    if (bestExtra == OG_INVALID_ID32) {
        return OG_FALSE;
    }
    *tokenExtra = bestExtra;
    return OG_TRUE;
}

static int32 ogsql_history_match_rank_compare(const OgsqlHistoryMatchRankT *left,
    const OgsqlHistoryMatchRankT *right)
{
    if (left->tokenExtra != right->tokenExtra) {
        return (left->tokenExtra < right->tokenExtra) ? -1 : 1;
    }
    if (left->statementExtra != right->statementExtra) {
        return (left->statementExtra < right->statementExtra) ? -1 : 1;
    }
    if (left->historyIndex != right->historyIndex) {
        return (left->historyIndex < right->historyIndex) ? -1 : 1;
    }
    return 0;
}

static bool32 ogsql_history_get_match_rank(int histCount, const char *query, uint32 queryLen, uint32 index,
    OgsqlHistoryMatchRankT *rank)
{
    const ogsql_cmd_history_list_t *entry = ogsql_history_get(histCount, index);
    uint32 tokenExtra;

    if (rank == NULL || entry == NULL ||
        ogsql_history_query_match_extra(entry, query, queryLen, &tokenExtra) != OG_TRUE) {
        return OG_FALSE;
    }
    rank->tokenExtra = (queryLen == 0) ? 0 : tokenExtra;
    rank->statementExtra = (queryLen == 0) ? 0 : entry->nbytes - queryLen;
    rank->historyIndex = index;
    return OG_TRUE;
}

bool32 ogsql_history_find_ranked(int histCount, const char *query, uint32 queryLen, uint32 afterIndex,
    uint32 *matchIndex)
{
    OgsqlHistoryMatchRankT afterRank;
    OgsqlHistoryMatchRankT bestRank;
    bool32 hasAfterRank;
    bool32 hasBestRank = OG_FALSE;

    if (matchIndex == NULL) {
        return OG_FALSE;
    }
    hasAfterRank = (afterIndex > 0 &&
        ogsql_history_get_match_rank(histCount, query, queryLen, afterIndex, &afterRank) == OG_TRUE) ?
        OG_TRUE : OG_FALSE;

    for (uint32 i = 1; i <= (uint32)histCount; i++) {
        OgsqlHistoryMatchRankT candidateRank;

        if (ogsql_history_get_match_rank(histCount, query, queryLen, i, &candidateRank) != OG_TRUE) {
            continue;
        }
        if (hasAfterRank == OG_TRUE && ogsql_history_match_rank_compare(&candidateRank, &afterRank) <= 0) {
            continue;
        }
        if (hasBestRank != OG_TRUE || ogsql_history_match_rank_compare(&candidateRank, &bestRank) < 0) {
            bestRank = candidateRank;
            hasBestRank = OG_TRUE;
        }
    }

    if (hasBestRank != OG_TRUE) {
        return OG_FALSE;
    }
    *matchIndex = bestRank.historyIndex;
    return OG_TRUE;
}
