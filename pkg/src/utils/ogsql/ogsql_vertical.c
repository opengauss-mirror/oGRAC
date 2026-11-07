/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd. All rights reserved.
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
 * ogsql_vertical.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_vertical.h"

bool32 ogsql_vertical_is_terminated(const text_t *line)
{
    uint32 len;

    if (line == NULL) {
        return OG_FALSE;
    }

    len = line->len;
    while (len > 0 && (uchar)line->str[len - 1] <= ' ') {
        len--;
    }
    if (len > 0 && line->str[len - 1] == ';') {
        len--;
        while (len > 0 && (uchar)line->str[len - 1] <= ' ') {
            len--;
        }
    }
    if (len < OGSQL_VERTICAL_MARKER_LEN) {
        return OG_FALSE;
    }

    if (line->str[len - 1] != 'v' && line->str[len - 1] != 'V') {
        return OG_FALSE;
    }
    return (line->str[len - OGSQL_VERTICAL_MARKER_LEN] == '\\') ? OG_TRUE : OG_FALSE;
}

bool32 ogsql_vertical_is_marker_only(const text_t *line)
{
    if (line == NULL) {
        return OG_FALSE;
    }

    return (ogsql_vertical_marker_prefix_len(line) == line->len) ? OG_TRUE : OG_FALSE;
}

uint32 ogsql_vertical_marker_prefix_len(const text_t *line)
{
    uint32 pos = 0;
    uint32 end;

    if (line == NULL) {
        return 0;
    }

    while (pos < line->len && (uchar)line->str[pos] <= ' ') {
        pos++;
    }
    if (pos + OGSQL_VERTICAL_MARKER_LEN > line->len || line->str[pos] != '\\' ||
        (line->str[pos + 1] != 'v' && line->str[pos + 1] != 'V')) {
        return 0;
    }

    end = pos + OGSQL_VERTICAL_MARKER_LEN;
    while (end < line->len && (uchar)line->str[end] <= ' ') {
        end++;
    }
    if (end == line->len) {
        return end;
    }
    if (line->str[end] != ';') {
        return 0;
    }

    end++;
    while (end < line->len && (uchar)line->str[end] <= ' ') {
        end++;
    }
    return end;
}

bool32 ogsql_vertical_strip_marker(text_t *line)
{
    if (line == NULL || !ogsql_vertical_is_terminated(line)) {
        return OG_FALSE;
    }

    while (line->len > 0 && (uchar)line->str[line->len - 1] <= ' ') {
        line->len--;
    }
    if (line->len > 0 && line->str[line->len - 1] == ';') {
        line->len--;
        while (line->len > 0 && (uchar)line->str[line->len - 1] <= ' ') {
            line->len--;
        }
    }
    line->len -= OGSQL_VERTICAL_MARKER_LEN;
    while (line->len > 0 && (uchar)line->str[line->len - 1] <= ' ') {
        line->len--;
    }
    if (line->len > 0 && line->str[line->len - 1] == ';') {
        line->len--;
    }
    line->str[line->len] = '\0';
    return OG_TRUE;
}

uint32 ogsql_vertical_text_lines(const char *text)
{
    uint32 line_count = 1;

    for (; *text != '\0'; text++) {
        if (*text == '\n') {
            line_count++;
        }
    }
    return line_count;
}

uint32 ogsql_vertical_label_padding(uint32 name_width, uint32 label_width)
{
    return label_width - MIN(name_width, label_width) + OGSQL_VERTICAL_LABEL_GAP;
}

uint32 ogsql_vertical_value_indent(uint32 label_width)
{
    return label_width + OGSQL_VERTICAL_LABEL_GAP + OGSQL_VERTICAL_COLON_GAP;
}

bool32 ogsql_vertical_need_newpage(uint64 lines_on_page, uint32 column_count, uint32 page_lines)
{
    if (page_lines == 0) {
        return OG_FALSE;
    }
    return ((lines_on_page + column_count + 1 > page_lines) ? OG_TRUE : OG_FALSE);
}
