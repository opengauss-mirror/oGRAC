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
 * ogsql_vertical.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_VERTICAL_H
#define OGSQL_VERTICAL_H

#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OGSQL_VERTICAL_MARKER_LEN 2
#define OGSQL_VERTICAL_LABEL_GAP 1
#define OGSQL_VERTICAL_COLON_GAP 2

bool32 ogsql_vertical_is_terminated(const text_t *line);
bool32 ogsql_vertical_is_marker_only(const text_t *line);
uint32 ogsql_vertical_marker_prefix_len(const text_t *line);
bool32 ogsql_vertical_strip_marker(text_t *line);
uint32 ogsql_vertical_text_lines(const char *text);
uint32 ogsql_vertical_label_padding(uint32 name_width, uint32 label_width);
uint32 ogsql_vertical_value_indent(uint32 label_width);
bool32 ogsql_vertical_need_newpage(uint64 lines_on_page, uint32 column_count, uint32 page_lines);

#ifdef __cplusplus
}
#endif

#endif
