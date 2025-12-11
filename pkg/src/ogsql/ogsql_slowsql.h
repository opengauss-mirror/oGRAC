/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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
 * ogsql_lowsql.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/ogsql_slowsql.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __OGSQL_SLOWSQL_H__
#define __OGSQL_SLOWSQL_H__

#include <dirent.h>
#include "cm_date.h"
#include "cm_log.h"
#include "cm_context_pool.h"
#include "knl_undo.h"
#include "knl_context.h"
#include "knl_interface.h"
#include "ogsql_stmt.h"

#define SLOWSQL_MAX_FILE_NAME_LEN 32
#define SLOWSQL_READ_BUF_SIZE 2048
#define SLOWSQL_FILE_PREFIX "ogracd"

/* Build log framework with invisible control characters */
#define SLOWSQL_STR_SPLIT 0X1E  // ASCII Record Separator (RS), splits log sections
#define SLOWSQL_HEAD 0XFE       // Non-printable character marks log start
#define SLOWSQL_TAIL 0XFF       // Non-printable character marks log end

#define STANDARD_SLOWSQL_COLS (SLOWSQL_VIEW_COLS - 2)
#define SLOWSQL_SEPARATOR_POS (OG_LOG_SLOWSQL_LENGTH_16K - 2)
#define SLOWSQL_TERMINATOR_POS (OG_LOG_SLOWSQL_LENGTH_16K - 1)

typedef struct slowsql_record_params {
    char *param_buf;
    uint32 *explain_hash;
    text_t *sql_text;
    text_t *plan_text;
} slowsql_record_params_t;

typedef struct {
    DIR *dir_handle;
    struct dirent *curr_entry;
} dir_iterator_t;

typedef struct st_slowsql_record_file {
    char name[SLOWSQL_MAX_FILE_NAME_LEN];
} slowsql_file_t;

typedef struct st_slowsql_record_dump {
    uint32 buf_size;
    uint32 offset;
    char *buf;
} slowsql_record_dump_t;

typedef struct st_slowsql_record_helper {
    uint32 count;
    uint32 index;
    uint32 out_pos;
    uint32 in_pos;
    uint32 in_size;
    char path[OG_MAX_PATH_BUFFER_SIZE];
    char buf[SLOWSQL_READ_BUF_SIZE];
    slowsql_file_t files[OG_MAX_LOG_FILE_COUNT];
} slowsql_record_helper_t;

void ogsql_slowsql_record_slowsql(sql_stmt_t *statement, struct timespec *tv_begin);
status_t ogsql_slowsql_load_files(slowsql_record_helper_t *helper);
status_t ogsql_slowsql_fetch_file(slowsql_record_helper_t *helper, char *buf, uint32 *size, knl_cursor_t *cursor);
bool32 ogsql_slowsql_get_value(uint32 *start_pos, char *buf, uint32 size, text_t *value);
bool32 og_slowsql_should_skip_logging(sql_stmt_t *statement, session_t *session);

#endif