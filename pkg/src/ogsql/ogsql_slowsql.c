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
 * ogsql_slowsql.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/ogsql_slowsql.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_file.h"
#include "cm_malloc.h"
#include "srv_instance.h"
#include "ogsql_func.h"
#include "ogsql_plan_defs.h"
#include "expl_executor.h"
#include "ogsql_slowsql.h"

#define NORMAL_SQL_LEN 8192
#define MAX_PLAN_TEXT 8000
#define MAX_PARAM_LEN 4096

#define SLOWSQL_FORMAT "%c%d|%s|%s|%d|%s|%llu|\"%s\"|%010u|%010u|\"%s\"%c \"%s\"\n%c"
#define SLOWSQL_EXPLAIN_FORMAT "%c%d|%s|%s|%d|%s|%llu|\"%s\"|%010u|%010u|\"%s\"\n%c\"%s\"\n%c"

static bool32 og_slowsql_get_sql_text(sql_stmt_t *statement, text_t *sql_text)
{
    if (statement->context == NULL || statement->context->type > OGSQL_TYPE_DML_CEIL) {
        return OG_FALSE;
    }

    return (ogx_read_text(sql_pool, &statement->context->ctrl, sql_text, OG_TRUE) == OG_SUCCESS);
}

typedef struct {
    sql_stmt_t *stmt;
    bool32 original_eof;
    bool32 original_is_explain;
} StmtStateGuard;

static inline StmtStateGuard stmt_state_guard_create(sql_stmt_t *stmt)
{
    StmtStateGuard guard = {
        .stmt = stmt,
        .original_eof = stmt->eof,
        .original_is_explain = stmt->is_explain
    };
    stmt->is_explain = OG_TRUE;
    return guard;
}

static inline void stmt_state_guard_restore(StmtStateGuard *guard)
{
    if (guard->stmt == NULL) {
        return;
    }
    guard->stmt->eof = guard->original_eof;
    guard->stmt->is_explain = guard->original_is_explain;
}

static inline void process_explain_text_finalize(text_t *plan_text, char *origin_pos)
{
    plan_text->len = (uint32)(plan_text->str - origin_pos);
    plan_text->str = origin_pos;
    if (plan_text->len > 0) {
        plan_text->str[plan_text->len - 1] = '\0';
    }
}

static bool32 og_slowsql_get_explain_text(sql_stmt_t *statement, text_t *plan_text)
{
    if (statement->context == NULL || statement->context->type > OGSQL_TYPE_DML_CEIL) {
        return OG_FALSE;
    }

    char *origin_pos = plan_text->str;
    StmtStateGuard guard = stmt_state_guard_create(statement);

    if (expl_get_explain_text(statement, plan_text) != OG_SUCCESS) {
        stmt_state_guard_restore(&guard);
        return OG_FALSE;
    }

    process_explain_text_finalize(plan_text, origin_pos);

    stmt_state_guard_restore(&guard);
    return OG_TRUE;
}


typedef status_t (*TypeLengthCalcFunc)(sql_stmt_t *stmt, variant_t *value, uint32 *length);

static status_t calc_string_type_length(sql_stmt_t *stmt, variant_t *value, uint32 *length)
{
    variant_t result;
    var_copy(value, &result);
    char temp_buf[OG_MAX_NUMBER_LEN + 1] = { 0 };
    text_buf_t buffer;
    CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN + 1, temp_buf);
    status_t err = var_as_string(SESSION_NLS(stmt), &result, &buffer);
    *length = (err == OG_SUCCESS) ? result.v_text.len : 0;
    return err;
}

static status_t calc_binary_type_length(sql_stmt_t *stmt, variant_t *value, uint32 *length)
{
    (void)stmt;
    *length = value->v_bin.size;
    return OG_SUCCESS;
}

static status_t calc_lob_type_length(sql_stmt_t *stmt, variant_t *value, uint32 *length)
{
    (void)stmt;
    *length = sql_get_lob_var_length(value);
    return OG_SUCCESS;
}

static status_t calc_default_type_length(sql_stmt_t *stmt, variant_t *value, uint32 *length)
{
    (void)stmt;
    *length = value->v_text.len;
    return OG_SUCCESS;
}

typedef struct {
    int type;
    TypeLengthCalcFunc calc_func;
} TypeLengthMapItem;

static status_t og_slowsql_get_param_length(sql_stmt_t *statement, variant_t *value, int32 *type,
                                            uint32 *length)
{
    if (value->is_null) {
        value->type = OG_TYPE_UNKNOWN;
        *type = OG_TYPE_UNKNOWN;
    } else {
        *type = value->type - OG_TYPE_BASE;
    }

    const TypeLengthMapItem type_map[] = {
        {OG_TYPE_INTEGER,          calc_string_type_length},
        {OG_TYPE_BIGINT,           calc_string_type_length},
        {OG_TYPE_REAL,             calc_string_type_length},
        {OG_TYPE_NUMBER,           calc_string_type_length},
        {OG_TYPE_DECIMAL,          calc_string_type_length},
        {OG_TYPE_DATE,             calc_string_type_length},
        {OG_TYPE_BOOLEAN,          calc_string_type_length},
        {OG_TYPE_UINT32,           calc_string_type_length},
        {OG_TYPE_NUMBER2,          calc_string_type_length},
        {OG_TYPE_TIMESTAMP,        calc_string_type_length},
        {OG_TYPE_TIMESTAMP_TZ_FAKE, calc_string_type_length},
        {OG_TYPE_TIMESTAMP_TZ,     calc_string_type_length},
        {OG_TYPE_TIMESTAMP_LTZ,    calc_string_type_length},
        {OG_TYPE_BINARY,           calc_binary_type_length},
        {OG_TYPE_VARBINARY,        calc_binary_type_length},
        {OG_TYPE_RAW,              calc_binary_type_length},
        {OG_TYPE_CLOB,             calc_lob_type_length},
        {OG_TYPE_BLOB,             calc_lob_type_length},
        {OG_TYPE_IMAGE,            calc_lob_type_length}
    };

    *length = 0;
    TypeLengthCalcFunc calcFunc = calc_default_type_length;

    const int map_count = sizeof(type_map) / sizeof(type_map[0]);
    for (int i = 0; i < map_count; ++i) {
        if (type_map[i].type == value->type) {
            calcFunc = type_map[i].calc_func;
            break;
        }
    }

    if (value->type != OG_TYPE_UNKNOWN) {
        status_t calc_status = calcFunc(statement, value, length);
        if (calc_status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_slowsql_build_param_info(sql_stmt_t *statement, char *param_buf, uint32 param_buf_length)
{
    if (statement->context == NULL || statement->context->params == NULL || statement->param_info.params == NULL ||
        !statement->params_ready) {
        return OG_SUCCESS;
    }

    uint32 count = statement->context->params->count;
    if (count == 0) {
        return OG_SUCCESS;
    }

    char temp_buf[OG_MAX_NUMBER_LEN + 1] = { 0 };
    text_buf_t buffer;
    CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN + 1, temp_buf);

    uint32 offset = 0;
    char text_buf[OG_PARAM_BUFFER_SIZE] = { 0 };
    for (uint32 i = 0; i < count; i++) {
        variant_t *value = &statement->param_info.params[i].value;
        int32 type = 0;
        uint32 len = 0;
        OG_RETURN_IFERR(og_slowsql_get_param_length(statement, value, &type, &len));

        const char *format = (i == count - 1) ? (type == -1 ? "%d-NULL" : "%d-%u")
                                              : (type == -1 ? "%d-NULL," : "%d-%u,");
        int32 ret = snprintf_s(text_buf, sizeof(text_buf), sizeof(text_buf) - 1, format, type, len);
        if (ret == -1) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return OG_ERROR;
        }

        uint32 buf_len = (uint32)strlen(text_buf);
        if (buf_len >= (param_buf_length - offset - 1)) {
            break;
        }

        errno_t err = strcat_s(param_buf, param_buf_length, text_buf);
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        offset += buf_len;
    }

    return OG_SUCCESS;
}

static void og_slowsql_dump_slowsql(slowsql_record_dump_t *dump, const char *fmt, ...)
{
    va_list args;

    char *buffer = dump->buf + dump->offset;
    uint32 buffer_size = MIN(dump->buf_size - dump->offset, OG_MAX_LOG_CONTENT_LENGTH);

    va_start(args, fmt);
    int ret = vsnprintf_s(buffer, buffer_size, buffer_size - 1, fmt, args);
    va_end(args);

    if (ret < 0) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return;
    }
    dump->offset += (uint32)strlen(buffer);
}

static void og_slowsql_trace_section(const char *title, sql_stmt_t *statement, uint64 exec_duration,
                                        void (*trace_body)(slowsql_record_dump_t *, ogx_stat_t *, uint64))
{
    char *buffer = NULL;
    OGSQL_SAVE_STACK(statement);
    if (sql_push(statement, OG_MAX_LOG_CONTENT_LENGTH, (void **)&buffer) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return;
    }

    slowsql_record_dump_t slowsql_dump = { .buf_size = OG_MAX_LOG_CONTENT_LENGTH, .offset = 0, .buf = buffer };

    og_slowsql_dump_slowsql(&slowsql_dump, "%s", title);
    trace_body(&slowsql_dump, statement->stat, exec_duration);
    OG_LOG_SLOWSQL(slowsql_dump.offset, "%s", slowsql_dump.buf);

    OGSQL_RESTORE_STACK(statement);
}

static void og_slowsql_trace_baseinfo_body(slowsql_record_dump_t *dump, ogx_stat_t *stat, uint64 exec_duration)
{
    og_slowsql_dump_slowsql(dump, "stat info about base info of the slow sql:\n");
    og_slowsql_dump_slowsql(dump, "\tthe count of processed row: %lld\n", stat->processed_rows);
    og_slowsql_dump_slowsql(dump, "\tI/O wait time: %lld[us]\n", stat->io_wait_time);
    og_slowsql_dump_slowsql(dump, "\tcondition wait time: %lld[us]\n", stat->con_wait_time);
    og_slowsql_dump_slowsql(dump, "\tdisk read times: %lld\n", stat->disk_reads);
    og_slowsql_dump_slowsql(dump, "\tdisk write times: %lld\n", stat->disk_writes);
    og_slowsql_dump_slowsql(dump, "\ttotal buffer get times: %lld\n", stat->buffer_gets);
    og_slowsql_dump_slowsql(dump, "\ttotal execution time: %lld[ns]\n", exec_duration);
}

static void og_slowsql_collect_stats(sql_stmt_t *statement, uint64 exec_duration)
{
    og_slowsql_trace_section("stat info about base info of the slow sql:\n", statement, exec_duration,
        og_slowsql_trace_baseinfo_body);
}

inline bool32 og_slowsql_should_skip_logging(sql_stmt_t *statement, session_t *session)
{
    /*
     * Skip logging under following conditions:
     * - Session has no active pipe connection
     * - Invalid SQL context
     * - Non-DML statement types
     * - EXPLAIN statement execution
     */
    return (session->pipe == NULL || statement->context == NULL || statement->context->type > OGSQL_TYPE_DML_CEIL ||
            statement->is_explain);
}

static status_t og_slowsql_prepare_explain_buffer(sql_stmt_t *statement, text_t *sql_text, text_t *plan_text,
                                                     char **pTemp)
{
    plan_text->str[0] = '\0';

    if (statement->context->ctrl.text_size <= sql_text->len) {
        sql_text->str[0] = '\0';
        return OG_SUCCESS;
    }

    uint32 malloc_size = CM_ALIGN8(statement->context->ctrl.text_size);
    if (malloc_size == 0) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)malloc_size, "slow_sql explain text");
        return OG_ERROR;
    }

    if (sql_push(statement, malloc_size, (void **)pTemp) != OG_SUCCESS) {
        return OG_ERROR;
    }

    errno_t err = memset_s(*pTemp, malloc_size, 0, malloc_size);
    if (err != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return OG_ERROR;
    }

    sql_text->str = *pTemp;
    sql_text->len = malloc_size;

    return OG_SUCCESS;
}

static bool32 og_slowsql_handle_exec_stage(sql_stmt_t *statement, slowsql_record_params_t *params)
{
    bool32 ret = og_slowsql_get_sql_text(statement, params->sql_text) &&
                 (og_slowsql_build_param_info(statement, params->param_buf, MAX_PARAM_LEN) == OG_SUCCESS) &&
                 og_slowsql_get_explain_text(statement, params->plan_text);
    *params->explain_hash = cm_hash_text(params->plan_text, INFINITE_HASH_RANGE);
    return ret;
}

static bool32 og_slowsql_collect_params_and_stage(sql_stmt_t *statement, session_t *session, const char **stage,
                                                     slowsql_record_params_t *params)
{
    uint32 cmd = (uint32)session->agent->recv_pack.head->cmd;

    switch (cmd) {
        case CS_CMD_PREPARE:
            *stage = "PREPARE";
            return og_slowsql_get_sql_text(statement, params->sql_text);

        case CS_CMD_EXECUTE:
        case CS_CMD_PREP_AND_EXEC:
            *stage = (cmd == CS_CMD_EXECUTE) ? "EXECUTE" : "PREP_EXEC";
            return og_slowsql_handle_exec_stage(statement, params);

        case CS_CMD_QUERY:
        case CS_CMD_FETCH:
            *stage = (cmd == CS_CMD_QUERY) ? "QUERY" : "FETCH";
            return og_slowsql_get_sql_text(statement, params->sql_text);

        default:
            return OG_FALSE;
    }
}

static void og_slowsql_log_slow_sql_execution(void *stmt_handle, uint64 exec_duration)
{
    sql_stmt_t *statement = (sql_stmt_t *)stmt_handle;
    session_t *session = statement->session;
    if (og_slowsql_should_skip_logging(statement, session)) {
        return;
    }

    OGSQL_SAVE_STACK(statement);

    /* Prepare log buffers */
    char *temp_sql_buf = NULL;
    char normal_sql_buf[NORMAL_SQL_LEN + 1] = { 0 };
    char plan_buf[MAX_PLAN_TEXT + 1] = { 0 };
    text_t sql_text = { .str = normal_sql_buf, .len = NORMAL_SQL_LEN };
    text_t plan_text = { .str = plan_buf, .len = MAX_PLAN_TEXT };
    if (og_slowsql_prepare_explain_buffer(statement, &sql_text, &plan_text, &temp_sql_buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return;
    }

    /* Parameter collection */
    const char *stage = NULL;
    char param_buf[MAX_PARAM_LEN + 1] = { 0 };
    uint32 explain_hash = 0;
    slowsql_record_params_t params = {
        .param_buf = param_buf, .explain_hash = &explain_hash, .sql_text = &sql_text, .plan_text = &plan_text
    };

    if (!og_slowsql_collect_params_and_stage(statement, session, &stage, &params)) {
        OGSQL_RESTORE_STACK(statement);
        return;
    }

    /* Format log information */
    const char *format = (plan_buf[0] == '\0') ? SLOWSQL_FORMAT : SLOWSQL_EXPLAIN_FORMAT;
    char timestamp[OG_MAX_TIME_STRLEN + 1] = { 0 };
    char client_ip[CM_MAX_IP_LEN] = { 0 };
    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", timestamp, sizeof(timestamp));
    (void)cm_inet_ntop((struct sockaddr *)&SESSION_PIPE(session)->link.tcp.remote.addr, client_ip, CM_MAX_IP_LEN);
    const char *param_str = (param_buf[0] == '\0') ? "NULL" : param_buf;
    const char *plan_str = (plan_buf[0] == '\0') ? "NULL" : plan_buf;
    OG_LOG_SLOWSQL(sql_text.len, format, SLOWSQL_HEAD, session->curr_tenant_id, timestamp, stage,
                   session->knl_session.id, client_ip, exec_duration, param_str, statement->context->ctrl.hash_value,
                   explain_hash, sql_text.str, SLOWSQL_STR_SPLIT, plan_str, SLOWSQL_TAIL);

    /* Record statistics */
    if (cm_log_param_instance()->slowsql_print_enable && statement->stat != NULL) {
        og_slowsql_collect_stats(statement, exec_duration);
    }

    OGSQL_RESTORE_STACK(statement);
}

/* Update longest SQL execution time record */
static void og_slowsql_get_slowest_sql_time(void *stmt_handle, uint64 exec_duration)
{
    sql_stmt_t *statement = (sql_stmt_t *)stmt_handle;
    session_t *session = statement->session;
    undo_context_t *undo_ctx = &session->knl_session.kernel->undo_ctx;

    /* Maintain maximum execution time */
    undo_ctx->longest_sql_time = MAX(undo_ctx->longest_sql_time, exec_duration);
}

/* Record SQL execution that exceeds time threshold */
void ogsql_slowsql_record_slowsql(sql_stmt_t *stmt, struct timespec *tv_begin)
{
    /* Calculate nanosecond-level duration */
    struct timespec tv_end;
    clock_gettime(CLOCK_MONOTONIC, &tv_end);
    const uint64 exec_duration = ogsql_timespec_func_diff_ns(tv_begin, &tv_end);

    /* Log only when exceeding threshold and valid statement */
    const uint64 threshold = cm_log_param_instance()->sql_stage_threshold * 1000;
    if (stmt != NULL && exec_duration >= threshold) {
        og_slowsql_log_slow_sql_execution(stmt, exec_duration);
        og_slowsql_get_slowest_sql_time(stmt, exec_duration);
    }
}

/* Extract field value from pipe-delimited buffer */
bool32 ogsql_slowsql_get_value(uint32 *current_pos, char *buffer, uint32 buffer_size, text_t *value)
{
    if (current_pos == NULL || buffer == NULL || value == NULL || *current_pos >= buffer_size) {
        if (value != NULL) {
            value->len = 0;
            value->str = NULL;
        }
        return OG_FALSE;
    }

    value->str = buffer + *current_pos;
    value->len = 0;

    char *delimiter = (char *)memchr(buffer + *current_pos, '|', buffer_size - *current_pos);
    if (delimiter != NULL) {
        value->len = (uint32)(delimiter - value->str);
        *current_pos = (uint32)(delimiter - buffer);
        return OG_TRUE;
    }

    return OG_FALSE;
}
/* Open log directory for iteration */
static status_t og_slowsql_open_logdir(const char *path, dir_iterator_t *iterator)
{
    /* Open target directory */
    iterator->dir_handle = opendir(path);
    if (iterator->dir_handle == NULL) {
        int os_err = cm_get_os_error();
        if (os_err == ENOENT) {  // Directory not exist is acceptable
            OG_LOG_DEBUG_INF("Slowsql directory [%s] not exist, skip loading", path);
            return OG_SUCCESS;
        }
        OG_LOG_DEBUG_ERR("Failed to open Slowsql directory [%s], errno:%d", path, os_err);
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* Add slow sql log file to processing list */
static void og_slowsql_process_logfile_entry(char *filename, slowsql_record_helper_t *helper)
{
    /* Skip files without SLOWSQL prefix */
    if (strlen(filename) == 0 || !CM_STR_BEGIN_WITH(filename, SLOWSQL_FILE_PREFIX)) {
        return;
    }

    /* Handle maximum file count limitation */
    if (helper->count >= OG_MAX_LOG_FILE_COUNT) {
        OG_LOG_DEBUG_WAR("Exceeded maximum slowsql files(%d), discarding: %s", OG_MAX_LOG_FILE_COUNT, filename);
        return;
    }

    /* Store valid file entry */
    slowsql_file_t *entry = &helper->files[helper->count++];
    errno_t err_code = strncpy_s(entry->name, SLOWSQL_MAX_FILE_NAME_LEN, filename, strlen(filename));
    if (err_code != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err_code);
    }
}

/* Load slow sql log files from specified directory */
status_t ogsql_slowsql_load_files(slowsql_record_helper_t *helper)
{
    dir_iterator_t iterator = { 0 };

    OG_RETURN_IFERR(og_slowsql_open_logdir(helper->path, &iterator));
    if (iterator.dir_handle == NULL) {
        return OG_SUCCESS;  // Directory not exist is normal case
    }

    /* Traverse directory entries */
    while ((iterator.curr_entry = readdir(iterator.dir_handle)) != NULL) {
        og_slowsql_process_logfile_entry(iterator.curr_entry->d_name, helper);
    }

    /* Cleanup directory handle */
    (void)closedir(iterator.dir_handle);

    return OG_SUCCESS;
}

/* Get next log file entry from processing list */
static inline slowsql_file_t *og_slowsql_fetch_next_file(slowsql_record_helper_t *helper)
{
    return (helper->index < helper->count) ? &helper->files[helper->index++] : NULL;
}

/* Open next available log file for reads */
static status_t build_log_file_full_path(const slowsql_record_helper_t *helper, const slowsql_file_t *log_entry,
                                         char *full_path, uint32 buf_size)
{
    if (helper == NULL || log_entry == NULL || full_path == NULL || buf_size == 0) {
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(full_path, buf_size, 0, buf_size));
    int ret = snprintf_s(full_path, buf_size, OG_MAX_FILE_NAME_LEN, "%s/%s", helper->path, log_entry->name);
    return (ret > 0 && ret < (int)buf_size) ? OG_SUCCESS : OG_ERROR;
}

static status_t og_slowsql_open_next_file(slowsql_record_helper_t *helper, knl_cursor_t *cursor)
{
    if (helper == NULL || cursor == NULL) {
        return OG_ERROR;
    }

    char full_path[OG_FILE_NAME_BUFFER_SIZE];
    while (OG_TRUE) {
        slowsql_file_t *log_entry = og_slowsql_fetch_next_file(helper);
        if (log_entry == NULL) {
            cursor->eof = OG_TRUE;
            return OG_SUCCESS;
        }

        PRTS_RETURN_IFERR(build_log_file_full_path(helper, log_entry, full_path, OG_FILE_NAME_BUFFER_SIZE));

        status_t open_ret = cm_open_file(full_path, O_RDONLY | O_BINARY, &cursor->file);
        if (open_ret == OG_SUCCESS) {
            return OG_SUCCESS;
        }

        if (errno == ENOENT) {
            OG_LOG_DEBUG_ERR("Log file [%s] not found, retrying with next file", full_path);
            continue;
        }

        return OG_ERROR;
    }
}

/* Update buffer state after read operation */
static inline void og_slowsql_update_buffer_state(slowsql_record_helper_t *helper, int32 bytes_read, bool32 *eof_flag)
{
    if (bytes_read > 0) {
        *eof_flag = OG_FALSE;
        helper->in_size += bytes_read;
        return;
    }
    *eof_flag = OG_TRUE;
}

/* Read data chunk from current log file */
static status_t og_slowsql_read_file_data(slowsql_record_helper_t *helper, knl_cursor_t *cursor, bool32 *end_of_file)
{
    int32 bytes_read = 0;
    uint32 available_space = SLOWSQL_READ_BUF_SIZE - helper->in_pos;

    /* Read data from file into buffer */
    if (cm_read_file(cursor->file, helper->buf + helper->in_pos, available_space, &bytes_read) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to read log file [fd:%d], error:%d", cursor->file, errno);
        return OG_ERROR;
    }

    og_slowsql_update_buffer_state(helper, bytes_read, end_of_file);
    return OG_SUCCESS;
}

/* Switch to next log file in processing sequence */
static inline void og_slowsql_switch_file(slowsql_record_helper_t *helper, knl_cursor_t *cursor)
{
    cm_close_file(cursor->file);
    cursor->file = OG_INVALID_HANDLE;

    /* Reset buffer positions for new file processing */
    helper->out_pos = 0;
    helper->in_pos = 0;
    helper->in_size = 0;
}

/* Fetch next data block from log files */
static status_t check_and_open_next_file(slowsql_record_helper_t *helper, knl_cursor_t *cursor)
{
    if (cursor->file == OG_INVALID_HANDLE) {
        OG_RETURN_IFERR(og_slowsql_open_next_file(helper, cursor));
        if (cursor->eof) {
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static status_t og_slowsql_fetch_block(slowsql_record_helper_t *helper, knl_cursor_t *cursor)
{
    if (helper == NULL || cursor == NULL) {
        return OG_ERROR;
    }

    bool32 end_of_file = OG_FALSE;
    while (OG_TRUE) {
        OG_RETURN_IFERR(check_and_open_next_file(helper, cursor));
        if (cursor->eof) {
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(og_slowsql_read_file_data(helper, cursor, &end_of_file));

        if (!end_of_file) {
            return OG_SUCCESS;
        }
        og_slowsql_switch_file(helper, cursor);
    }
}

/* Preserve unprocessed data at buffer head */
static inline status_t og_slowsql_retain_unprocessed_data(slowsql_record_helper_t *helper, int32 remaining)
{
    if (remaining > 0) {
        MEMS_RETURN_IFERR(memcpy_s(helper->buf, (uint32)remaining, helper->buf + helper->out_pos, (uint32)remaining));
    }

    /* Reset buffer positions */
    helper->in_pos = (uint32)remaining;
    helper->out_pos = 0;
    helper->in_size = helper->in_pos;

    return OG_SUCCESS;
}

/* Prepare buffer for continuous reads */
static status_t og_slowsql_try_fetch_block(slowsql_record_helper_t *helper, knl_cursor_t *cursor)
{
    /* Check if buffer has enough data for processing */
    int32 remaining_data = (int32)(helper->in_size - helper->out_pos);
    if (remaining_data > (int32)sizeof(uint32)) {
        return OG_SUCCESS;
    }

    /* Preserve unprocessed data and attempt to fetch new block */
    OG_RETURN_IFERR(og_slowsql_retain_unprocessed_data(helper, remaining_data));

    return og_slowsql_fetch_block(helper, cursor);
}

static inline void og_slowsql_read_from_buffer(slowsql_record_helper_t *helper, void *dest, uint32 size)
{
    MEMS_RETVOID_IFERR(memcpy_s(dest, size, helper->buf + helper->out_pos, size));
    helper->out_pos += size;
}

/* Extract row size from buffer header */
static inline bool32 og_slowsql_get_row_size(slowsql_record_helper_t *helper, uint32 *row_size)
{
    /* Read 4-byte header containing row length */
    og_slowsql_read_from_buffer(helper, row_size, sizeof(uint32));

    /* Validate row size constraints */
    if (*row_size == 0 || *row_size > OG_MAX_LOG_SLOWSQL_LENGTH) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

/* Allocates and initializes a temporary buffer for processing large records */
static status_t og_slowsql_alloc_temp_buffer(sql_stmt_t *stmt, char **temp_buf)
{
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_LOG_SLOWSQL_LENGTH + 1, (void **)temp_buf));
    if (*temp_buf == NULL) {
        return OG_ERROR;
    }

    if (memset_s(*temp_buf, OG_MAX_LOG_SLOWSQL_LENGTH + 1, 0, OG_MAX_LOG_SLOWSQL_LENGTH + 1) != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errno);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

// Validates record termination marker in buffer
static inline status_t og_slowsql_validate_record(const char *buf, uint32 size)
{
    if (buf[size - 1] != (char)SLOWSQL_TAIL) {
        OG_THROW_ERROR(ERR_READ_SLOWSQL_FILE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* Copies data from read buffer to output buffer with file rotation support */
static status_t og_slowsql_copy_data(slowsql_record_helper_t *helper, char *output_buf, uint32 required_size,
                                        knl_cursor_t *cursor)
{
    bool32 eof_flag = OG_FALSE;
    uint32 total_copied = 0;

    while (!eof_flag && total_copied < required_size) {
        uint32 remain_space = required_size - total_copied;
        uint32 available_data = helper->in_size - helper->out_pos;
        uint32 copy_size = MIN(remain_space, available_data);
        if (copy_size > 0) {
            MEMS_RETURN_IFERR(
                memcpy_s(output_buf + total_copied, remain_space, helper->buf + helper->out_pos, copy_size));
            total_copied += copy_size;
            helper->out_pos += copy_size;
        }

        if (total_copied >= required_size) {
            return OG_SUCCESS;
        }

        // Reset buffer and read next chunk
        helper->out_pos = 0;
        helper->in_pos = 0;
        helper->in_size = 0;
        OG_RETURN_IFERR(og_slowsql_read_file_data(helper, cursor, &eof_flag));
    }

    return OG_SUCCESS;
}

/* Processes oversized log records with format validation */
static status_t og_slowsql_fetch_large_row(
    sql_stmt_t *stmt, slowsql_record_helper_t *helper, char *output_buf, uint32 *actual_size,
                                              knl_cursor_t *cursor)
{
    char *temp_buffer = NULL;
    bool32 data_ready = OG_FALSE;

    OG_RETURN_IFERR(og_slowsql_alloc_temp_buffer(stmt, &temp_buffer));

    do {
        /* Copy complete record to temporary buffer */
        OG_RETURN_IFERR(og_slowsql_copy_data(helper, temp_buffer, *actual_size, cursor));

        /* Validate record structure */
        if (og_slowsql_validate_record(temp_buffer, *actual_size) != OG_SUCCESS) {
            break;
        }

        /* Format output according to specification */
        errno_t errcode = memcpy_s(output_buf, OG_LOG_SLOWSQL_LENGTH_16K, temp_buffer, OG_LOG_SLOWSQL_LENGTH_16K);
        if (errcode != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }

        output_buf[SLOWSQL_SEPARATOR_POS] = (char)SLOWSQL_STR_SPLIT;
        output_buf[SLOWSQL_TERMINATOR_POS] = (char)SLOWSQL_TAIL;
        *actual_size = OG_LOG_SLOWSQL_LENGTH_16K;
        data_ready = OG_TRUE;
    } while (0);

    return data_ready ? OG_SUCCESS : OG_ERROR;
}

/* Process row based on record size */
static inline status_t og_slowsql_try_process_row
    (sql_stmt_t *stmt, slowsql_record_helper_t *helper, char *output_buf, uint32 *record_size,
                                                     knl_cursor_t *cursor)
{
    return (*record_size > OG_LOG_SLOWSQL_LENGTH_16K)
               ? og_slowsql_fetch_large_row(stmt, helper, output_buf, record_size, cursor)
               : og_slowsql_copy_data(helper, output_buf, *record_size, cursor);
}

/* Main entry point for fetching complete log records */
status_t ogsql_slowsql_fetch_file
    (slowsql_record_helper_t *helper, char *output_buf, uint32 *record_size, knl_cursor_t *cursor)
{
    sql_stmt_t *stmt = cursor->stmt;
    if (stmt == NULL) {
        return OG_ERROR;
    }

    while (OG_TRUE) {
        OG_RETURN_IFERR(og_slowsql_try_fetch_block(helper, cursor));
        if (cursor->eof) {
            return OG_SUCCESS;
        }

        /* Get record size from buffer header */
        if (!og_slowsql_get_row_size(helper, record_size)) {
            og_slowsql_switch_file(helper, cursor);
            continue;
        }

        /* Process based on record size */
        status_t ret = og_slowsql_try_process_row(stmt, helper, output_buf, record_size, cursor);
        if (ret == OG_SUCCESS) {
            return OG_SUCCESS;
        }
        og_slowsql_switch_file(helper, cursor);
    }

    return OG_SUCCESS;
}