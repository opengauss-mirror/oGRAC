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
 * ogsql_load.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_load.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "cm_thread.h"
#include "ogsql_load.h"
#include "cm_lex.h"
#include "cm_chan.h"
#include "cm_signal.h"
#include "cm_log.h"
#include "cm_utils.h"
#include "cm_memory.h"

#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#endif
#include "ogsql_common.h"
#include "cm_queue.h"

char g_load_pswd[OG_PASSWORD_BUFFER_SIZE + 4];

typedef enum {
    LOADER_READ_ERR = -1,
    LOADER_READ_END = 0,
    LOADER_READ_OK = 1,
} EN_LOADER_READ_STATUS;

#define RAW_BUF_SIZE            SIZE_M(1)
#define LOAD_MAXALLOCSIZE       (0x3fffffff) /* 1 gigabyte - 1 */
#define MAX_LOAD_SQL_SIZE       SIZE_K(64)
#define MAX_TRUNCATED_FIELD_LEN 20u
#define MAX_CHAN_BLOCK_CNT      5
#define MAX_LOAD_PRINT_TEXT_LEN 10
#define WAIT_WORKER_THREAD_TIME 20000
#define MAX_LOAD_LOB_BATCH_CNT  SIZE_K(8)

/* include escape and enclosed */
#define MAX_LOAD_COLUMN_LEN(type) (uint64)(OGSQL_IS_LOB_TYPE(type) ? ((uint64)8192 * 1048576 + 2) : ((uint64)SIZE_K(16) + 2))

#define CURRENT_FILE_ROW(worker) ((worker)->start_line + (worker)->locat_info.curr_line_in_block)

#define GET_IND_PTR(loader, row, col) (loader)->col_ind[(col)] + (row)

#define LOAD_TYPE_NEED_PUT_SPACE(type) \
    (OGSQL_IS_STRING_TYPE_EX(type) || \
    OGSQL_IS_BINARY_TYPE_EX(type) || \
    OGSQL_IS_LOB_TYPE(type))

#define LOAD_RESET_COLUMN_CTX(ogx)                \
    do {                                          \
        (ogx)->col_id = 0;                        \
        (ogx)->is_first_chunk = OG_TRUE;          \
        (ogx)->is_enclosed = OG_FALSE;            \
        (ogx)->is_enclosed_begin = OG_FALSE;      \
        (ogx)->loaded_length = 0;                 \
        (ogx)->lob_writed_length = 0;             \
        (ogx)->field_terminal_matched_cnt = 0;    \
        (ogx)->line_terminal_matched_cnt = 0;     \
        (ogx)->reach_column_end = OG_FALSE;       \
        (ogx)->reach_line_end = OG_FALSE;         \
        (ogx)->need_skip_current_line = OG_FALSE; \
        (ogx)->fatal_error = OG_FALSE;            \
    } while (0)

/* make sure first block is full , set current_line_ctx.reach_line_end = OG_TRUE */
#define LOAD_RESET_BLOCK_CTX(ogx)                              \
    do {                                                       \
        (ogx)->is_complete_row = OG_FALSE;                     \
        (ogx)->current_line_ctx.is_enclosed = OG_FALSE;        \
        (ogx)->current_line_ctx.reach_line_end = OG_TRUE;      \
        (ogx)->current_line_ctx.line_terminal_matched_cnt = 0; \
        (ogx)->next_line_ctx.is_enclosed = OG_FALSE;           \
        (ogx)->next_line_ctx.reach_line_end = OG_FALSE;        \
        (ogx)->next_line_ctx.line_terminal_matched_cnt = 0;    \
    } while (0)

#define LOAD_RESET_LINE_CTX(ogx)              \
    do {                                      \
        (ogx)->is_enclosed = OG_FALSE;        \
        (ogx)->reach_line_end = OG_FALSE;     \
        (ogx)->line_terminal_matched_cnt = 0; \
    } while (0)

#define LOAD_TRY_RESET_LINE_CTX(ogx) \
    if ((ogx)->reach_line_end) {     \
        LOAD_RESET_LINE_CTX(ogx);    \
    }

#define LOADER_DEFAULT_THREADS 1

#define OGSQL_LOAD_DEBUG(fmt, ...)        \
    if (g_load_opts.debug_on) {          \
        ogsql_printf(fmt, ##__VA_ARGS__); \
        ogsql_printf("\n");               \
    }

#define LOAD_LOCAT_INFO_INC(worker)                 \
    do {                                           \
        (worker)->locat_info.read_rows++;          \
        (worker)->locat_info.curr_line_in_block++; \
    } while (0)

#define LOAD_OCCUR_ERROR(loader) (!ogsql_if_all_workers_ok(loader) || ogsql_if_reach_allowed_errors(loader))
#define LOAD_SERIAL (g_load_opts.threads == 1)

typedef struct loader_string_t {
    char *data;
    uint64 len;
    uint64 maxlen;
} loader_string_t;

typedef loader_string_t *loader_string_ptr_t;

typedef struct st_load_option {
    bool32 enclosed_optionally;
    char fields_enclosed;
    char fields_terminated[TERMINATED_STR_ARRAY_SIZE];
    char fields_escape;
    char lines_terminated[TERMINATED_STR_ARRAY_SIZE];
    char trailing_columns[MAX_LOAD_SQL_SIZE];
    list_t obj_list; /* list of column names to load data which you need */
    char set_columns[MAX_LOAD_SQL_SIZE];
    uint64 ignore_lines;
    uint32 max_databuf_size;
    uint32 max_filebuf_size;
    uint32 auto_commit_rows;
    uint32 charset_id;
    uint32 threads;
    uint32 allowed_batch_errs;
    bool32 nologging;
    bool8 debug_on;
    bool8 null2space;
    bool8 replace;
    bool8 convert_jsonb;  /* it shows that input-json-data is clob or string */
    bool8 ignore;
    bool8 set_flag;
    bool8 is_case_insensitive;
    crypt_info_t crypt_info;
} load_option_t;

/** The default options for loading data */
static load_option_t g_load_opts = {
    .enclosed_optionally = OG_FALSE,
    .fields_enclosed = OGSQL_DEFAULT_ENCLOSED_CHAR,
    .fields_terminated = OGSQL_DEFAULT_FIELD_SEPARATOR_STR,
    .fields_escape = '\\',
    .lines_terminated = OGSQL_DEFAULT_LINE_SEPARATOR_STR,
    .ignore_lines = 0,
    .max_databuf_size = SIZE_M(1),
    .max_filebuf_size = FILE_BUFFER_SIZE,
    .auto_commit_rows = OGSQL_AUTO_COMMIT,
    .charset_id = OG_DEFAULT_LOCAL_CHARSET,
    .threads = LOADER_DEFAULT_THREADS,
    .allowed_batch_errs = 0,
    .nologging = OG_FALSE,
    .debug_on = OG_FALSE,
    .null2space = OG_FALSE,
    .replace = OG_FALSE,
    .convert_jsonb = OG_FALSE,
    .ignore = OG_FALSE,
    .is_case_insensitive = OG_TRUE,
};

typedef enum {
    WORKER_STATUS_ERR = -1,
    WORKER_STATUS_INIT,
    WORKER_STATUS_RECV,
    WORKER_STATUS_LOAD,
    WORKER_STATUS_END,
} en_worker_status;

typedef enum {
    LOADER_STATUS_ERR = -1,  // load error
    LOADER_STATUS_OK
} en_loader_status;

typedef enum en_loader_EOL {
    LOADER_EOL_UNKNOWN,
    LOADER_EOL_NL,
    LOADER_EOL_CR,
    LOADER_EOL_CRNL
} en_loader_EOL;

typedef struct load_line_ctx {
    bool8 is_enclosed;    /* is between column enclosed char */
    bool8 reach_line_end; /* is a complete row */
    uint32 line_terminal_matched_cnt;
} load_line_ctx_t;

typedef struct load_block_ctx {
    bool8 is_complete_row;
    load_line_ctx_t current_line_ctx;
    load_line_ctx_t next_line_ctx;
} load_block_ctx_t;

typedef struct load_column_ctx {
    uint32 col_id;
    bool8 is_first_chunk;
    bool8 is_enclosed_begin;
    bool8 is_enclosed;
    uint32 field_terminal_matched_cnt;
    uint32 line_terminal_matched_cnt;
    uint64 loaded_length;         /* length of column in datafile include enclosed char. */
    uint64 lob_writed_length;     /* length of lob column write into ogconn. */
    bool8 reach_column_end;       /* is a complete column */
    bool8 reach_line_end;         /* reach line end. */
    bool8 need_skip_current_line; /* some column error , need skip curren line. */
    bool8 fatal_error;
    text_t column_data; /* store part column data */
} load_column_ctx_t;

typedef struct load_column_param {
    char enclosed_char;
    char *line_terminal;
    uint32 line_terminal_len;
    char *field_terminal;
    uint32 field_terminal_len;
} load_column_param_t;

typedef struct load_fetch_column {
    load_column_ctx_t *column_ctx;
    text_t column_txt;
} load_fetch_column_t;

typedef struct load_block {
    uint64 start_line;
    uint64 id;
    text_t buf;
} load_block_t;

typedef struct load_block_pool {
    char **buffer_list;
    uint32 idle_cnt;
    spinlock_t lock;
} load_block_pool_t;

typedef struct location_info {
    uint32 curr_row;  /* the current batching row, i.e., number of rows in loader */
    uint64 read_rows; /* count all rows */
    uint64 curr_line_in_block;
} location_info_t;

typedef struct {
    uint32 id; /* worker id */

    en_worker_status status;
    bool32 closed;

    chan_t *chan; /* channel used to recv data */
    load_block_t block;
    char *orig_block_buf;

    ogsql_conn_info_t conn_info; /* connection information */

    void *loader;

    char *table;
    uint16 *col_ind[OG_MAX_COLUMNS]; /* column indicators */
    void *col_data[OG_MAX_COLUMNS];  /* column data */
    char *col_data_buf;              /* the data buffer for all columns */
    uint16 max_batch_rows;           /* the maximal No. of rows in each batch */

    uint64 loaded_rows;             /* The successfully loaded rows to server */
    volatile uint64 committed_rows; /* The number of rows that have been committed into TABLE */
    uint64 error_rows;              /* The number of error rows in loader */
    uint32 allowed_batch_errs;      /* The number of allowed batch error rows in loader */
    uint32 actual_batch_errs;       /* The current number of batch error rows in loader */
    uint32 skip_rows;               /* The number of skip rows in loader */
    uint32 check_line_errs;         /* The number of line to check is error rows in loader */
    uint64 prev_loaded_rows;

    load_column_param_t *column_param;
    load_column_ctx_t column_ctx;
    location_info_t locat_info;
    uint64 start_line;
} worker_t;

typedef struct {
    en_loader_status status;
    chan_t **chan;
    thread_t *threads;
    worker_t *workers;

    fixed_memory_pool_t block_pool;
    load_column_param_t column_param;

    spinlock_t conn_lock; // control serial access to main connection.

    char load_file[OG_MAX_FILE_PATH_LENGH];
    FILE *fp;
    char table[MAX_ENTITY_LEN + 1];

    uint64 read_rows;
    uint64 committed_rows;
    uint64 loaded_rows;
    uint64 file_rows;
    uint64 ignored_lines;
    uint64 error_rows;
    uint32 allowed_batch_errs;
    uint32 actual_batch_errs;
    uint32 skip_rows;
    spinlock_t report_lock;

    char *raw_buf;
    uint64 raw_buf_len;
    uint64 raw_buf_index;
    bool8 eof;
    bool8 csv_mode;
    en_loader_EOL eol_type;

    uint64 start_line;
    loader_string_t line_buf;

    /* The shared information among all workers */
    ogconn_inner_column_desc_t *col_desc;
    char insert_sql[MAX_LOAD_SQL_SIZE];
    uint16 col_bndsz[OG_MAX_COLUMNS]; /* column binding size, it is times of 4 */
    uint16 col_bndtype[OG_MAX_COLUMNS];
    uint32 col_num;
    uint32 lob_col_num;
    uint32 row_size; /* the width of all columns in bytes */
    gcm_encrypt_t decrypt_ctx;
    FILE *encrypt_conf_fp;
    crypt_info_t crypt_info;
} loader_t;

#define GET_LOADER(worker) ((loader_t *)(worker)->loader)

static char *g_rand_local_key = NULL;
char *g_rand_factor_key = NULL;
char *g_cipher = NULL;
uint32 g_cipher_len;
char *g_current_user = NULL;
uint32 g_current_user_len = 0;

spinlock_t g_user_lock = 0;
spinlock_t g_pswd_lock = 0;

void loader_save_user(char *orig_user, uint32 orig_len)
{
    cm_spin_lock(&g_user_lock, NULL);

    do {
        if (g_current_user == NULL) {
            g_current_user = malloc(OG_NAME_BUFFER_SIZE * 2);
            OG_BREAK_IF_TRUE(g_current_user == NULL);
        }

        OG_BREAK_IF_TRUE(memset_s(g_current_user, OG_NAME_BUFFER_SIZE * 2, 0, OG_NAME_BUFFER_SIZE * 2) != EOK);

        OG_BREAK_IF_TRUE(orig_len > OG_NAME_BUFFER_SIZE + 4);

        OG_BREAK_IF_TRUE(memcpy_s(g_current_user, OG_NAME_BUFFER_SIZE * 2, orig_user, orig_len) != EOK);

        g_current_user_len = orig_len;
    } while (0);

    cm_spin_unlock(&g_user_lock);

    return;
}

static status_t loader_save_pswd_do(char *orig_pswd, uint32 orig_len)
{
    if (g_rand_local_key == NULL) {
        g_rand_local_key = malloc(OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4);
        if (g_rand_local_key == NULL) {
            return OG_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s(g_rand_local_key, OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4, 0,
                                   OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4));
    }

    if (g_rand_factor_key == NULL) {
        g_rand_factor_key = malloc(OG_MAX_FACTOR_KEY_STR_LEN + 4);
        if (g_rand_factor_key == NULL) {
            return OG_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s(g_rand_factor_key, OG_MAX_FACTOR_KEY_STR_LEN + 4, 0,
                                   OG_MAX_FACTOR_KEY_STR_LEN + 4));
    }

    if (g_cipher == NULL) {
        g_cipher = malloc(OG_PASSWORD_BUFFER_SIZE * 2);
        if (g_cipher == NULL) {
            return OG_ERROR;
        }
    }

    if (orig_len > OG_PASSWORD_BUFFER_SIZE + 4) {
        return OG_ERROR;
    }

    if ((uint32)strlen(g_rand_factor_key) != OG_MAX_FACTOR_KEY_STR_LEN) {
        char rand_buf[OG_AES256KEYSIZE / 2 + 4];
        uint32 rand_len = OG_AES256KEYSIZE / 2;

        /* generate 128bit rand_buf and then base64 encode */
        OG_RETURN_IFERR(cm_rand((uchar *)rand_buf, rand_len));
        uint32 rand_factor_key_len = OG_MAX_FACTOR_KEY_STR_LEN + 4;
        OG_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, rand_len, g_rand_factor_key, &rand_factor_key_len));

        OG_RETURN_IFERR(cm_generate_work_key((const char *)g_rand_factor_key, g_rand_local_key,
            OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4));
    }
    
    if ((status_t)ogconn_encrypt_password(orig_pswd, orig_len, g_rand_local_key, g_rand_factor_key, g_cipher,
        &g_cipher_len) != OG_SUCCESS) {
        g_cipher_len = 0;
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t loader_save_pswd(char *orig_pswd, uint32 orig_len)
{
    cm_spin_lock(&g_pswd_lock, NULL);

    if (loader_save_pswd_do(orig_pswd, orig_len) != OG_SUCCESS) {
        CM_FREE_PTR(g_rand_local_key);
        CM_FREE_PTR(g_rand_factor_key);
        CM_FREE_PTR(g_cipher);
        cm_spin_unlock(&g_pswd_lock);
        return OG_ERROR;
    }

    cm_spin_unlock(&g_pswd_lock);

    return OG_SUCCESS;
}

status_t  ogsql_get_saved_pswd(char *pswd, uint32 len)
{
    cm_spin_lock(&g_pswd_lock, NULL);
    if ((status_t)ogconn_decrypt_password(pswd, len, g_rand_local_key, g_rand_factor_key, g_cipher,
        g_cipher_len) != OG_SUCCESS) {
        (void)memset_s(pswd, len, 0, len);
        cm_spin_unlock(&g_pswd_lock);
        return OG_ERROR;
    }
    cm_spin_unlock(&g_pswd_lock);
    return OG_SUCCESS;
}

void ogsql_get_saved_user(char *user, uint32 len)
{
    cm_spin_lock(&g_user_lock, NULL);
    errno_t errcode;

    if (user == NULL || len == 0 || g_current_user == NULL || g_current_user_len == 0) {
        cm_spin_unlock(&g_user_lock);
        return;
    }

    errcode = memset_s(user, len, 0, len);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    if (errcode == EOK) {
        errcode = memcpy_s(user, len, g_current_user, g_current_user_len);
    }
    if (errcode != EOK) {
        cm_spin_unlock(&g_user_lock);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    cm_spin_unlock(&g_user_lock);

    return;
}

void ogsql_free_user_pswd(void)
{
    if (g_current_user != NULL) {
        cm_spin_lock(&g_user_lock, NULL);
        CM_FREE_PTR(g_current_user);
        cm_spin_unlock(&g_user_lock);
    }
    
    cm_spin_lock(&g_pswd_lock, NULL);
    if (g_rand_local_key != NULL) {
        CM_FREE_PTR(g_rand_local_key);
    }

    if (g_rand_factor_key != NULL) {
        CM_FREE_PTR(g_rand_factor_key);
    }

    if (g_cipher != NULL) {
        CM_FREE_PTR(g_cipher);
    }
    cm_spin_unlock(&g_pswd_lock);
}

static void ogsql_show_loader_usage(void)
{
    ogsql_printf("The syntax of data loader is: \n");
    ogsql_printf("LOAD DATA INFILE \"file_name\"\n");
    ogsql_printf("    INTO TABLE table_name\n");
    ogsql_printf("    [REPLACE | IGNORE]\n");
    ogsql_printf("    [{FIELDS | COLUMNS} ENCLOSED BY 'ascii_char' [OPTIONALLY]]\n");
    ogsql_printf("    [{FIELDS | COLUMNS} TERMINATED BY 'string']\n");
    ogsql_printf("    [{LINES | ROWS} TERMINATED BY 'string']\n");
    ogsql_printf("    [TRAILING COLUMNS(COLUMN1[, COLUMN2, ...])]\n");
    ogsql_printf("    [IGNORE uint64_num {LINES | ROWS}]\n");
    ogsql_printf("    [CHARSET string]\n");
    ogsql_printf("    [THREADS uint32_num]\n");
    ogsql_printf("    [ERRORS uint32_num]\n");
    ogsql_printf("    [NOLOGGING]\n");
    ogsql_printf("    [NULL2SPACE]\n");
    ogsql_printf("    [DECRYPT BY 'password']\n");
    ogsql_printf("    [SET col_name = expr,...];\n");
    ogsql_printf("\n");
}

void ogsql_show_loader_opts(void)
{
    uint16 fields_terminated_len = (strlen(g_load_opts.fields_terminated) == 0 ?
                                    1 : (uint16)strlen(g_load_opts.fields_terminated));
    uint16 lines_terminated_len = (strlen(g_load_opts.lines_terminated) == 0 ?
                                   1 : (uint16)strlen(g_load_opts.lines_terminated));

    ogsql_printf("The current options for data loading is: \n");
    if (OGSQL_HAS_ENCLOSED_CHAR(g_load_opts.fields_enclosed)) {
        if (g_load_opts.enclosed_optionally) {
            ogsql_printf("  fields optionally enclosed char: '%s'\n", C2V(g_load_opts.fields_enclosed));
        } else {
            ogsql_printf("      fields enclosed char: '%s'\n", C2V(g_load_opts.fields_enclosed));
        }
    }

    ogsql_printf("    fields terminated string: '");
    for (int i = 0; i < fields_terminated_len; i++) {
        ogsql_printf("%s", C2V(g_load_opts.fields_terminated[i]));
    }
    ogsql_printf("'\n");

    ogsql_printf("     lines terminated string: '");
    for (int i = 0; i < lines_terminated_len; i++) {
        ogsql_printf("%s", C2V(g_load_opts.lines_terminated[i]));
    }
    ogsql_printf("'\n");

    ogsql_printf("            ignoring lines: " PRINT_FMT_UINT64 "\n", g_load_opts.ignore_lines);
    ogsql_printf("  maximal data buffer size: %u bytes\n", g_load_opts.max_databuf_size);
    ogsql_printf("  maximal file buffer size: %u bytes\n", g_load_opts.max_filebuf_size);
    ogsql_printf("           current charset: %s\n",
                (char *)cm_get_charset_name((charset_type_t)g_load_opts.charset_id));
    ogsql_printf("         number of threads: %u\n", g_load_opts.threads);
    ogsql_printf("            allowed errors: %u\n", g_load_opts.allowed_batch_errs);
    ogsql_printf("                 nologging: %s\n", g_load_opts.nologging ? "on" : "off");
    if (ogconn_get_call_version(CONN) >= CS_VERSION_24) {
        ogsql_printf("          convert to jsonb: %s\n", g_load_opts.convert_jsonb ? "true" : "false");
    }
    ogsql_printf("\n");
}

static void ogsql_load_report_current(loader_t *loader)
{
    cm_spin_lock(&loader->report_lock, NULL);
    {
        loader->committed_rows = 0;
        uint32 i = 0;

        for (i = 0; i < g_load_opts.threads; i++) {
            loader->committed_rows += loader->workers[i].committed_rows;
        }

        if (loader->committed_rows > 0) {
            ogsql_printf("%llu rows have been committed.\n", loader->committed_rows);
        }
    }
    cm_spin_unlock(&loader->report_lock);
}

static void ogsql_load_report_summary(loader_t *loader)
{
    uint32 i = 0;

    loader->read_rows = 0;
    loader->loaded_rows = 0;
    loader->committed_rows = 0;
    loader->error_rows = 0;
    loader->skip_rows = 0;

    if (loader->status == LOADER_STATUS_OK) {
        ogsql_printf("\nComplete the data load.\n");
    } else {
        ogsql_printf("\nFailure happens and loading process is interrupted.\n");
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->read_rows += loader->workers[i].locat_info.read_rows;
        loader->loaded_rows += loader->workers[i].loaded_rows;
        loader->committed_rows += loader->workers[i].committed_rows;
        loader->error_rows += loader->workers[i].error_rows;
        loader->skip_rows += loader->workers[i].skip_rows;
    }

    ogsql_printf("totally read rows: %llu\n", loader->file_rows);
    ogsql_printf("     ignored rows: %llu\n", loader->ignored_lines);
    ogsql_printf("      loaded rows: %llu\n", loader->loaded_rows);
    ogsql_printf("   committed rows: %llu\n", loader->committed_rows);
    ogsql_printf("       error rows: %llu\n", loader->error_rows);
    ogsql_printf("        skip rows: %u\n", loader->skip_rows);
}

static void ogsql_stop_workers(loader_t *loader)
{
    uint32 i = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->workers[i].closed = OG_TRUE;
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        cm_close_thread(&loader->threads[i]);
    }
}

/*
 * loader_init_string
 *
 * Initialize a loader_string_t struct to describe an empty string.
 */
static status_t loader_init_linebuf(loader_string_ptr_t str)
{
    uint32 size = g_load_opts.max_filebuf_size;
    str->data = (char *)malloc(size);
    if (str->data == NULL) {
        return OG_ERROR;
    }
    str->maxlen = size;
    str->len = 0;
    return OG_SUCCESS;
}

static void loader_free_string(loader_string_ptr_t str)
{
    if (str != NULL && str->data) {
        free(str->data);
        str->data = NULL;
        str->len = 0;
    }
}

/*
 * loader_append_linebuff
 *
 * Append file buffer data into line buffer
 *
 */
static status_t loader_append_linebuff(loader_string_ptr_t str, const char *data, uint64 datalen, bool8 *reach_max_size)
{
    // check space is enough
    if (str->len + datalen > (uint64)g_load_opts.max_filebuf_size) {
        OGSQL_LOAD_DEBUG("[Loader-Thread] ensure more memory %llu exceeds max size %u, used size %llu.",
            datalen, g_load_opts.max_filebuf_size, str->len);
        *reach_max_size = OG_TRUE;
        return OG_ERROR;
    }

    /* OK, append the data */
    if (datalen != 0) {
        MEMS_RETURN_IFERR(memcpy_s(str->data + str->len, (size_t)(str->maxlen - str->len), data, (size_t)datalen));
    }
    str->len += datalen;

    return OG_SUCCESS;
}

static inline int ogsql_loader_prepare(loader_t *loader);

static int ogsql_loader_init_chan(loader_t *loader)
{
    loader->chan = (chan_t **)malloc(sizeof(chan_t *) * g_load_opts.threads);
    if (loader->chan == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc chan");
        return OGCONN_ERROR;
    }

    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        loader->chan[i] = cm_chan_new(MAX_CHAN_BLOCK_CNT, sizeof(load_block_t));
        if (loader->chan[i] == NULL) {
            for (uint32 j = 0; j < i; j++) {
                CM_FREE_PTR(loader->chan[j]->buf);
                CM_FREE_PTR(loader->chan[j]);
            }
            CM_FREE_PTR(loader->chan);
            OGSQL_PRINTF(ZSERR_LOAD, "create channel failed");
            return OGCONN_ERROR;
        }
    }
    return OGCONN_SUCCESS;
}

void ogsql_loader_free_file_buffer(loader_t *loader, char *buffer)
{
    /* BEGIN -->do buffer address check. */
    uint32 file_buff_size = g_load_opts.max_filebuf_size + 1;
    uint32 block_cnt = g_load_opts.threads * (MAX_CHAN_BLOCK_CNT + 3);

    /* END -->do buffer address check. */
    cm_spin_lock(&(loader->block_pool.lock), NULL);

    OGSQL_LOAD_DEBUG("[Memory Pool] free memory id : %u",
        (uint32)(buffer - (char *)loader->block_pool.buffer_list - sizeof(char *) * block_cnt) / file_buff_size);

    loader->block_pool.buffer_list[loader->block_pool.idle_cnt] = buffer;
    loader->block_pool.idle_cnt++;

    cm_spin_unlock(&(loader->block_pool.lock));
}

static status_t loader_init_thread_mem(loader_t *loader)
{
    loader->threads = (thread_t *)malloc(sizeof(thread_t) * g_load_opts.threads);
    if (loader->threads == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc threads info");
        return OGCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->threads, sizeof(thread_t) * g_load_opts.threads, 0,
        sizeof(thread_t) * g_load_opts.threads));

    loader->workers = (worker_t *)malloc(sizeof(worker_t) * g_load_opts.threads);
    if (loader->workers == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc workers info");
        return OGCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->workers, sizeof(worker_t) * g_load_opts.threads, 0,
        sizeof(worker_t) * g_load_opts.threads));

    return OG_SUCCESS;
}

static status_t loader_open_file(loader_t *loader, const char* path)
{
    loader->fp = fopen(path, "rb");

    if (loader->fp == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "can not open file: %s", loader->load_file);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t loader_init_rawbuff(loader_t *loader)
{
    loader->raw_buf = (char *)malloc(RAW_BUF_SIZE + 1);
    if (loader->raw_buf == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "Fail to allocate %u bytes for raw buffer", RAW_BUF_SIZE + 1);
        return OGCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->raw_buf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));

    loader->raw_buf_len = 0;
    loader->raw_buf_index = 0;
    return OG_SUCCESS;
}

static int ogsql_loader_init(loader_t *loader)
{
    char path[OG_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    OG_RETURN_IFERR(realpath_file(loader->load_file, path, OG_FILE_NAME_BUFFER_SIZE));

    loader->conn_lock = 0;
    loader->loaded_rows = 0;
    loader->committed_rows = 0;
    loader->ignored_lines = 0;
    loader->read_rows = 0;
    loader->file_rows = 0;
    loader->error_rows = 0;
    loader->allowed_batch_errs = g_load_opts.allowed_batch_errs;
    loader->actual_batch_errs = 0;
    loader->skip_rows = 0;
    loader->status = LOADER_STATUS_OK;
    loader->report_lock = 0;
    loader->csv_mode = OG_TRUE;
    loader->eof = OG_FALSE;
    loader->column_param.enclosed_char = g_load_opts.fields_enclosed;
    loader->column_param.field_terminal = g_load_opts.fields_terminated;
    loader->column_param.line_terminal = g_load_opts.lines_terminated;
    loader->column_param.field_terminal_len = ((uint32)strlen(g_load_opts.fields_terminated) == 0 ?
        1 : (uint32)strlen(g_load_opts.fields_terminated));
    loader->column_param.line_terminal_len = ((uint32)strlen(g_load_opts.lines_terminated) == 0 ?
        1 : (uint32)strlen(g_load_opts.lines_terminated));

    if (ogsql_loader_init_chan(loader) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    // memory used in :
    // 1. in chan : MAX_CHAN_BLOCK_CNT
    // 2. in loader : 1
    // 3. in workter : 1
    // 4. store part column : 1
    if (ogconn_common_init_fixed_memory_pool(&loader->block_pool, (g_load_opts.max_filebuf_size + 1),
        g_load_opts.threads * (MAX_CHAN_BLOCK_CNT + 3)) != OGCONN_SUCCESS) {
        OGSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc file buffer");
        return OGCONN_ERROR;
    }

    // init threads memory
    OG_RETURN_IFERR(loader_init_thread_mem(loader));

    // open file
    OG_RETURN_IFERR(loader_open_file(loader, path));
    OG_RETURN_IFERR(loader_init_rawbuff(loader));
    OG_RETURN_IFERR(loader_init_linebuf(&loader->line_buf));

    if (g_load_opts.crypt_info.crypt_flag) {
        if (ogsql_decrypt_prepare(&g_load_opts.crypt_info, path) != OG_SUCCESS) {
            OGSQL_PRINTF(ZSERR_LOAD, "Fail to parse %s or incorrect password", OGSQL_CRYPT_CFG_NAME);
            return OGCONN_ERROR;
        }

        OG_RETURN_IFERR(ogsql_set_encrpyt_fp(&g_load_opts.crypt_info, path, cm_fileno(loader->fp)));
    }

    return ogsql_loader_prepare(loader);
}

static void ogsql_loader_close_chan(loader_t *loader)
{
    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        cm_chan_close(loader->chan[i]);
    }
}

static void ogsql_loader_free_chan(loader_t *loader)
{
    if (loader->chan != NULL) {
        for (uint32 i = 0; i < g_load_opts.threads; i++) {
            cm_chan_free(loader->chan[i]);
        }
        CM_FREE_PTR(loader->chan);
    }
}

static void ogsql_loader_free(loader_t *loader)
{
    ogsql_decrypt_end(&g_load_opts.crypt_info);

    ogsql_loader_free_chan(loader);

    if (loader->threads != NULL) {
        free(loader->threads);
        loader->threads = NULL;
    }

    if (loader->workers != NULL) {
        free(loader->workers);
        loader->workers = NULL;
    }

    if (loader->fp != NULL) {
        fclose(loader->fp);
    }

    if (loader->raw_buf != NULL) {
        free(loader->raw_buf);
        loader->raw_buf = NULL;
    }

    loader->raw_buf_len = 0;
    loader->raw_buf_index = 0;

    loader_free_string(&loader->line_buf);

    ogconn_common_uninit_fixed_memory_pool(&(loader->block_pool));
}

static status_t ogsql_loader_read_data(loader_t *loader, void *databuf, uint64 maxread, uint64 *datalen)
{
    int bytesread;
    char *decrypt_buf = NULL;
    crypt_file_t *decrypt_ctx = NULL;
    status_t ret;

    if (g_load_opts.crypt_info.crypt_flag) {
        OG_RETURN_IFERR(ogsql_get_encrypt_file(&g_load_opts.crypt_info, &decrypt_ctx, cm_fileno(loader->fp)));
        decrypt_buf = (char *)malloc(g_load_opts.max_filebuf_size);
        if (decrypt_buf == NULL) {
            ogsql_printf("can't allocate %u bytes for dump table\n", g_load_opts.max_filebuf_size);
            return OG_ERROR;
        }

        do {
            bytesread = (int)fread(decrypt_buf, 1, (size_t)maxread, loader->fp);
            if (ferror(loader->fp)) {
                OGSQL_PRINTF(ZSERR_LOAD, "reading data file");
                perror("The reason is ");
                ret = OG_ERROR;
                break;
            }

            ret = cm_decrypt_data_by_gcm(decrypt_ctx->crypt_ctx.gcm_ctx, databuf, decrypt_buf, bytesread);
            OG_BREAK_IF_ERROR(ret);
            *datalen = (uint64)bytesread;
        } while (0);

        CM_FREE_PTR(decrypt_buf);
        return ret;
    }

    bytesread = (int)fread(databuf, 1, (size_t)maxread, loader->fp);
    if (ferror(loader->fp)) {
        OGSQL_PRINTF(ZSERR_LOAD, "reading data file");
        perror("The reason is ");
        return OG_ERROR;
    }

    *datalen = (uint64)bytesread;
    return OG_SUCCESS;
}

static EN_LOADER_READ_STATUS ogsql_loader_get_raw_buf(loader_t *loader)
{
    uint64 nbytes = 0;
    uint64 inbytes;
    errno_t rc_memmove;
    if (loader->raw_buf_index < loader->raw_buf_len) {
        /* Copy down the unprocessed data */
        nbytes = loader->raw_buf_len - loader->raw_buf_index;
        rc_memmove = memmove_s(loader->raw_buf, RAW_BUF_SIZE, loader->raw_buf + loader->raw_buf_index,
                               (size_t)nbytes);
        if (rc_memmove != EOK) {
            OGSQL_PRINTF(ZSERR_LOAD, "move bin data failed.");
            return LOADER_READ_ERR;
        }
    } else {
        nbytes = 0; /* no data need be saved */
    }

    if (ogsql_loader_read_data(loader, loader->raw_buf + nbytes,
        RAW_BUF_SIZE - nbytes, &inbytes) != OG_SUCCESS) {
        return LOADER_READ_ERR;
    }

    nbytes += inbytes;
    loader->raw_buf[nbytes] = '\0';
    loader->raw_buf_index = 0;
    loader->raw_buf_len = nbytes;
    loader->eof = ((nbytes > 0) ? OG_FALSE : OG_TRUE);
    return LOADER_READ_OK;
}

static EN_LOADER_READ_STATUS ogsql_loader_read_line(loader_t *loader, load_line_ctx_t *ogx)
{
    char enclose_char = g_load_opts.fields_enclosed;
    char *line_term = g_load_opts.lines_terminated;

    char *buf = loader->raw_buf;
    uint64 buf_idx = loader->raw_buf_index;
    uint64 ori_idx = loader->raw_buf_index;
    uint64 buf_len = loader->raw_buf_len;
    bool8 reach_max_size;
    bool8 is_enclosed = ogx->is_enclosed;
    uint32 line_terminal_matched_cnt = ogx->line_terminal_matched_cnt;

    OGSQL_LOAD_DEBUG("[Read Line] position at buff: (%llu/%llu) is %s enclosed.", buf_idx, buf_len,
                    ogx->is_enclosed ? "in" : "not in");

    while (OG_TRUE) {
        if (buf_idx >= buf_len) {
            if (buf_idx > ori_idx) {
                if (OG_SUCCESS != loader_append_linebuff(&loader->line_buf, buf + ori_idx,
                                                         buf_idx - ori_idx, &reach_max_size)) {
                    if (reach_max_size) {
                        ogx->reach_line_end = OG_FALSE;
                        return LOADER_READ_OK;
                    } else {
                        return LOADER_READ_ERR;
                    }
                }
                ogx->is_enclosed = is_enclosed;
                loader->raw_buf_index = buf_idx;
            }

            if (loader->eof) {
                if (loader->line_buf.len > 0) {
                    return LOADER_READ_OK;
                }

                return LOADER_READ_END;
            }

            if (ogsql_loader_get_raw_buf(loader) != LOADER_READ_OK) {
                return LOADER_READ_ERR;
            }

            buf = loader->raw_buf;
            ori_idx = loader->raw_buf_index;
            buf_idx = loader->raw_buf_index;
            buf_len = loader->raw_buf_len;
            continue;
        }

        if (buf[buf_idx] == enclose_char) {
            is_enclosed = !is_enclosed;
            buf_idx++;
            continue;
        }

        if (is_enclosed) {
            buf_idx++;
            continue;
        }

        if (buf[buf_idx] == line_term[ogx->line_terminal_matched_cnt]) {
            ogx->line_terminal_matched_cnt++;
            if (loader->column_param.line_terminal_len == ogx->line_terminal_matched_cnt) {
                OGSQL_LOAD_DEBUG("[Read Line] Hit Line end at position %llu.", buf_idx);
                buf_idx++;
                if (OG_SUCCESS != loader_append_linebuff(&loader->line_buf, buf + ori_idx, buf_idx - ori_idx,
                                                         &reach_max_size)) {
                    if (reach_max_size) {
                        ogx->line_terminal_matched_cnt = line_terminal_matched_cnt;
                        ogx->reach_line_end = OG_FALSE;
                        return LOADER_READ_OK;
                    } else {
                        return LOADER_READ_ERR;
                    }
                }
                ogx->is_enclosed = OG_FALSE;
                ogx->reach_line_end = OG_TRUE;
                loader->raw_buf_index = buf_idx;
                ogx->line_terminal_matched_cnt = 0;
                return LOADER_READ_OK;
            } else {
                buf_idx++;
                continue;
            }
        }

        buf_idx++;
    }
}

static status_t ogsql_loader_append_line_to_block(loader_t *loader, text_t *block, uint64 max_size)
{
    if (max_size - block->len < loader->line_buf.len) {
        OGSQL_PRINTF(ZSERR_LOAD, "append line to block failed.");
        return OGCONN_ERROR;
    }

    OGSQL_LOAD_DEBUG("[Append Block] copy %llu bytes to block(used %u) max %llu.", loader->line_buf.len,
                    block->len, max_size);

    MEMS_RETURN_IFERR(memcpy_s(block->str + block->len, (size_t)(max_size - block->len), loader->line_buf.data,
                               (size_t)(loader->line_buf.len)));

    block->len += (uint32)loader->line_buf.len;
    loader->line_buf.len = 0;

    return OGCONN_SUCCESS;
}

static status_t ogsql_loader_append_line_terminate(loader_t *loader, text_t *block, uint64 max_size,
    load_block_ctx_t *ogx)
{
    MEMS_RETURN_IFERR(memcpy_s(block->str + block->len, (uint32)(max_size - block->len),
        loader->column_param.line_terminal, loader->column_param.line_terminal_len));

    block->len += loader->column_param.line_terminal_len;
    ogx->current_line_ctx.reach_line_end = OG_TRUE;
    ogx->is_complete_row = OG_TRUE;
    loader->file_rows++;
    return OG_SUCCESS;
}

/*
below can be putted into block:
    1. multi row [ROW1,ROW2...]
    2. one row [ROW1]
    3. part row
*/
static EN_LOADER_READ_STATUS ogsql_loader_read_block(loader_t *loader, text_t *block, uint64 max_size,
                                             load_block_ctx_t *ogx)
{
    EN_LOADER_READ_STATUS result = LOADER_READ_OK;
    bool8 need_stop_read = OG_FALSE;

    loader->start_line = loader->file_rows + 1;

    block->len = 0;

    if (loader->line_buf.len > 0) {
        OG_RETURN_IFERR(ogsql_loader_append_line_to_block(loader, block, max_size));
        if (ogx->next_line_ctx.reach_line_end) {
            loader->file_rows++;
            ogx->is_complete_row = OG_TRUE;
        } else {
            ogx->is_complete_row = OG_FALSE;
        }

        if (!ogx->current_line_ctx.reach_line_end) {  // last part of row
            need_stop_read = OG_TRUE;
        }

        ogx->current_line_ctx = ogx->next_line_ctx;
        LOAD_TRY_RESET_LINE_CTX(&(ogx->next_line_ctx));

        if (need_stop_read) {
            OGSQL_LOAD_DEBUG("[Read Block] block length %u, %s row.", block->len,
                            ogx->is_complete_row ? "complete" : "part");
            return LOADER_READ_OK;
        }
    }

    while (block->len < max_size) {
        result = ogsql_loader_read_line(loader, &ogx->next_line_ctx);
        if (result == LOADER_READ_ERR) {
            OGSQL_PRINTF(ZSERR_LOAD, "read line failed");
            return LOADER_READ_ERR;
        }

        if (result == LOADER_READ_END) {  // end of file
            if (block->len == 0 && loader->line_buf.len == 0) {
                if (!ogx->current_line_ctx.reach_line_end) {
                    OGSQL_LOAD_DEBUG("No terminal at end of file.try appent it.");
                    return ogsql_loader_append_line_terminate(loader, block, max_size, ogx) == OG_SUCCESS ?
                        LOADER_READ_OK : LOADER_READ_ERR;
                }
                CM_NULL_TERM(block);
                return LOADER_READ_END;
            }
        }

        if (loader->line_buf.len == 0) {
            break;
        }

        // no buffer in block to append the line
        if (max_size - block->len < loader->line_buf.len) {
            break;
        }

        OG_RETURN_IFERR(ogsql_loader_append_line_to_block(loader, block, max_size));

        if (ogx->next_line_ctx.reach_line_end) {
            loader->file_rows++;
        }

        if (!ogx->current_line_ctx.reach_line_end) {
            // part data or last part data this time.
            ogx->current_line_ctx = ogx->next_line_ctx;
            ogx->is_complete_row = ogx->next_line_ctx.reach_line_end;
            LOAD_TRY_RESET_LINE_CTX(&(ogx->next_line_ctx));
            break;
        }
        // update block info.
        ogx->current_line_ctx = ogx->next_line_ctx;
        ogx->is_complete_row = ogx->next_line_ctx.reach_line_end;
        LOAD_TRY_RESET_LINE_CTX(&(ogx->next_line_ctx));
    }

    CM_NULL_TERM(block);
    OGSQL_LOAD_DEBUG("[Read Block] block length %u, %s row.", block->len, ogx->is_complete_row ? "complete" : "part");
    return LOADER_READ_OK;
}

static inline void ogsql_set_field_indicator(worker_t *worker, uint32 row, uint32 col, uint16 val)
{
    uint16 *ind_ptr = NULL;
    ind_ptr = GET_IND_PTR(worker, row, col);
    *ind_ptr = val;
}

static inline void ogsql_put_field_null(worker_t *worker, uint32 row, uint32 col)
{
    ogsql_set_field_indicator(worker, row, col, OGCONN_NULL);
}

static inline int ogsql_put_field_uint32(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    uint32 val;
    char *field_ptr = NULL;
    num_errno_t nerr_no;

    nerr_no = cm_text2uint32_ex(field, &val);
    if (nerr_no != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into uint32 failed"
                    " at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return OGCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(uint32) * row;
    *((uint32 *)field_ptr) = val;

    ogsql_set_field_indicator(worker, row, col, sizeof(uint32));
    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_int32(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    int32 val;
    char *field_ptr = NULL;
    num_errno_t nerr_no;

    nerr_no = cm_text2int_ex(field, &val);
    if (nerr_no != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into int32 failed"
                    " at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return OGCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(int32) * row;
    *((int32 *)field_ptr) = val;

    ogsql_set_field_indicator(worker, row, col, sizeof(int32));
    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_int64(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    int64 val;
    char *field_ptr = NULL;

    if (cm_text2bigint_ex(field, &val) != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into bigint failed at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return OGCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(int64) * row;
    *((int64 *)field_ptr) = val;
    ogsql_set_field_indicator(worker, row, col, sizeof(int64));

    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_real(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    double val;
    char *field_ptr = NULL;

    CM_NULL_TERM(field);
    if (!cm_str2real_ex(field->str, &val)) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into DOUBLE/REAL failed at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return OGCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(double) * row;
    *((double *)field_ptr) = val;
    ogsql_set_field_indicator(worker, row, col, sizeof(double));

    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_raw(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    binary_t bin;

    if (field->len > 2 && field->str[0] == '0' && UPPER(field->str[1]) == 'X') {
        CM_REMOVE_FIRST_N(field, 2);
    }

    if (field->len > (uint32)GET_LOADER(worker)->col_desc[col].size * 2) {
        uint32 field_len = field->len;
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "the text field '%s' is too long at line:" PRINT_FMT_UINT64 ", column:%u,\n"
                    "the text length is %u larger than"
                    " the maximal allowed hex-string size (%u)",
                    field->str, CURRENT_FILE_ROW(worker), col + 1, field_len,
                    (uint32)GET_LOADER(worker)->col_desc[col].size * 2);
        return OGCONN_ERROR;
    }

    // put data
    bin.bytes = (uint8 *)worker->col_data[col] + row * GET_LOADER(worker)->col_bndsz[col];
    if (cm_text2bin(field, OG_FALSE, &bin, (uint32)(field->len + 1 / 2)) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_LOAD, "at line:" PRINT_FMT_UINT64 ", column:%u", CURRENT_FILE_ROW(worker), col + 1);
        ogsql_print_error(NULL);
        return OG_ERROR;
    }
    ogsql_set_field_indicator(worker, row, col, (uint16)bin.size);

    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_text(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    char *field_ptr = NULL;

    if (field->len > (uint32)GET_LOADER(worker)->col_bndsz[col]) {
        uint32 field_len = field->len;
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "the text field '%s' is too long at line:" PRINT_FMT_UINT64 ", column:%u,\n"
                    "current field len %u byte(s) is larger than"
                    " the maximal allowed column size is %u %s",
                    field->str, CURRENT_FILE_ROW(worker), col + 1, field_len,
                    (uint32)GET_LOADER(worker)->col_desc[col].size,
                    GET_LOADER(worker)->col_desc[col].is_character ? "char(s)" : "byte(s)");
        return OGCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + row * GET_LOADER(worker)->col_bndsz[col];
    // put data
    if (field->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(field_ptr, GET_LOADER(worker)->col_bndsz[col], field->str, field->len));
    }
    ogsql_set_field_indicator(worker, row, col, (uint16)field->len);

    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_clob(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    uint32 nchars;

    // put data
    if (field->len != 0) {
        OG_RETURN_IFERR(ogconn_write_batch_clob(worker->conn_info.stmt, col, row, field->str, field->len, &nchars));
    }
    ogsql_set_field_indicator(worker, row, col, sizeof(ogconn_lob_t));

    return OGCONN_SUCCESS;
}

static inline int ogsql_put_field_blob(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    // put data
    if (field->len != 0) {
        OG_RETURN_IFERR(ogconn_write_batch_blob(worker->conn_info.stmt, col, row, field->str, field->len));
    }
    ogsql_set_field_indicator(worker, row, col, sizeof(ogconn_lob_t));

    return OGCONN_SUCCESS;
}

bool32 ogsql_load_enclosed_match(const text_t *text, char enclosed_char)
{
    if (text->len < 1) {
        return OG_TRUE;
    }

    if (text->len == 1) {
        if (CM_TEXT_BEGIN(text) == enclosed_char) {
            return OG_FALSE;
        }

        return OG_TRUE;
    }

    if (CM_TEXT_BEGIN(text) == enclosed_char) {
        if (CM_TEXT_END(text) == enclosed_char) {
            return OG_TRUE;
        } else {
            return OG_FALSE;
        }
    }

    if (CM_TEXT_END(text) == enclosed_char) {
        if (CM_TEXT_BEGIN(text) == enclosed_char) {
            return OG_TRUE;
        } else {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static int ogsql_load_text_replace(text_t *text, char enclosed_char)
{
    uint32 i = 0;
    uint32 w_pos = 0;

    for (i = 0; i < text->len; i++) {
        if (text->str[i] == enclosed_char) {
            if (i + 1 < text->len) {
                if (text->str[i + 1] == text->str[i]) {
                    text->str[w_pos++] = text->str[i];
                    i++;
                    continue;
                } else {
                    text->str[w_pos++] = text->str[i];
                }
            } else {
                text->str[w_pos++] = text->str[i];
            }
        } else {
            text->str[w_pos++] = text->str[i];
        }
    }

    text->len = w_pos;
    return OGCONN_SUCCESS;
}

static int ogsql_load_remove_escape(text_t *text, char enclosed_char)
{
    if (text == NULL || text->str == NULL) {
        return OGCONN_SUCCESS;
    }

    uint32 len = text->len;
    char *data = text->str;

    if (len == 0) {
        return OGCONN_SUCCESS;
    }

    if (len == 1) {
        if (data[0] == enclosed_char) {
            return OGCONN_ERROR;
        } else {
            return OGCONN_SUCCESS;
        }
    }

    return ogsql_load_text_replace(text, enclosed_char);
}

static inline int ogsql_try_remove_field_enclosed(load_fetch_column_t *fetch_column, uint16 datatype)
{
    if (!OGSQL_HAS_ENCLOSED_CHAR(g_load_opts.fields_enclosed)) {
        return OGCONN_SUCCESS;
    }

    if (!g_load_opts.enclosed_optionally || OGSQL_IS_ENCLOSED_TYPE(datatype)) {
        // if is enclosed, remove the enclosed char
        if (!fetch_column->column_ctx->is_enclosed_begin &&
            (!OGSQL_IS_LOB_TYPE(datatype) || fetch_column->column_ctx->is_first_chunk)) {
            if (fetch_column->column_txt.str[0] == g_load_opts.fields_enclosed) {
                CM_REMOVE_FIRST_N(&(fetch_column->column_txt), 1);
            }
        }
        if (!fetch_column->column_ctx->is_enclosed) {
            if (fetch_column->column_txt.str[fetch_column->column_txt.len - 1] == g_load_opts.fields_enclosed) {
                CM_REMOVE_LAST(&(fetch_column->column_txt));
            }
        }

        // if enclosed char is inside the filed
        if (OGCONN_SUCCESS != ogsql_load_remove_escape(&(fetch_column->column_txt), g_load_opts.fields_enclosed)) {
            return OGCONN_ERROR;
        }
    }

    return OGCONN_SUCCESS;
}

static int ogsql_put_field_into_column_core(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    switch (GET_LOADER(worker)->col_bndtype[col]) {
        case OGCONN_TYPE_UINT32:
            return ogsql_put_field_uint32(worker, field, row, col);
        case OGCONN_TYPE_INTEGER:
            return ogsql_put_field_int32(worker, field, row, col);

        case OGCONN_TYPE_BIGINT:
            return ogsql_put_field_int64(worker, field, row, col);

        case OGCONN_TYPE_REAL:
            return ogsql_put_field_real(worker, field, row, col);

        case OGCONN_TYPE_BOOLEAN:
        case OGCONN_TYPE_DATE:
        case OGCONN_TYPE_TIMESTAMP:
        case OGCONN_TYPE_TIMESTAMP_LTZ:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_CHAR:
        case OGCONN_TYPE_VARCHAR:
        case OGCONN_TYPE_STRING:
        case OGCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case OGCONN_TYPE_TIMESTAMP_TZ:
        case OGCONN_TYPE_BINARY:
        case OGCONN_TYPE_VARBINARY:
            return ogsql_put_field_text(worker, field, row, col);

        case OGCONN_TYPE_RAW:
            return ogsql_put_field_raw(worker, field, row, col);

        case OGCONN_TYPE_CLOB:
            return ogsql_put_field_clob(worker, field, row, col);

        case OGCONN_TYPE_BLOB:
        case OGCONN_TYPE_IMAGE:
            return ogsql_put_field_blob(worker, field, row, col);

        case OGCONN_TYPE_CURSOR:
        case OGCONN_TYPE_COLUMN:
        case OGCONN_TYPE_UNKNOWN:
        default:
            CM_NEVER;
            return OGCONN_ERROR;
    }
}

static int ogsql_put_field_into_column(worker_t *worker, load_fetch_column_t *fetch_column, uint32 row, uint32 col)
{
    uint16 type = GET_LOADER(worker)->col_desc[col].type;
    text_t *field = &(fetch_column->column_txt);

    CM_NULL_TERM(field);
    if (!OGSQL_IS_ENCLOSED_TYPE(type)) {
        cm_trim_text(field);
    }

    if (row >= worker->max_batch_rows) {
        OGSQL_PRINTF(ZSERR_LOAD, "assert raised, expect: row(%u) < worker->max_batch_rows(%u)", row,
                    worker->max_batch_rows);
        return OG_ERROR;
    }

    if (CM_IS_EMPTY(field)) {
        if (fetch_column->column_ctx->lob_writed_length == 0) {
            ogsql_put_field_null(worker, row, col);
        }
        return OGCONN_SUCCESS;
    }

    if (ogsql_try_remove_field_enclosed(fetch_column, GET_LOADER(worker)->col_desc[col].type) != OGCONN_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        OGSQL_PRINTF(ZSERR_LOAD, "the field '%s' is not enclosed at file line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return OGCONN_ERROR;
    }

    if (OGSQL_IS_LOB_TYPE(type)) {
        fetch_column->column_ctx->lob_writed_length += field->len;
        if (fetch_column->column_ctx->lob_writed_length >= OG_MAX_LOB_SIZE) {
            OGSQL_PRINTF(ZSERR_LOAD, "lob size reach max size %llu at file line:" PRINT_FMT_UINT64 ", column:%u",
                        OG_MAX_LOB_SIZE, CURRENT_FILE_ROW(worker), col + 1);
            return OGCONN_ERROR;
        }
    }

    return ogsql_put_field_into_column_core(worker, field, row, col);
}

static void ogsql_print_debug_text(text_t *text)
{
    char print_buf[MAX_LOAD_PRINT_TEXT_LEN + 1];
    text_t print_text = { .str = print_buf, .len = 0 };
    cm_concat_text(&print_text, MAX_LOAD_PRINT_TEXT_LEN, text);
    CM_NULL_TERM(&print_text);
    OGSQL_LOAD_DEBUG("[Print Text] length %u , content %s.", text->len, print_text.str);
}

static int ogsql_put_field_into_column_ctx(worker_t *worker, load_fetch_column_t *fetch_column, uint32 row,
                                          uint32 col)
{
    uint16 type = GET_LOADER(worker)->col_desc[col].type;
    load_column_ctx_t *column_ctx = fetch_column->column_ctx;
    int32 ret = OGCONN_SUCCESS;
    fixed_memory_pool_t *pool = &(GET_LOADER(worker)->block_pool);

    ogsql_print_debug_text(&(fetch_column->column_txt));

    if (OGSQL_IS_LOB_TYPE(type) || (column_ctx->reach_column_end &&
                                   fetch_column->column_ctx->column_data.str == NULL)) {
        return ogsql_put_field_into_column(worker, fetch_column, row, col);
    }

    // not lob , not reach end
    if (column_ctx->column_data.str == NULL) {
        column_ctx->column_data.len = 0;

        column_ctx->column_data.str = ogconn_common_alloc_fixed_buffer(pool);
        if (column_ctx->column_data.str == NULL) {
            OGSQL_PRINTF(ZSERR_LOAD, "malloc memory for store column data failed.");
            return OGCONN_ERROR;
        }
    }
    cm_concat_text(&(column_ctx->column_data), pool->block_size, &(fetch_column->column_txt));
    if (column_ctx->reach_column_end) {
        fetch_column->column_txt = column_ctx->column_data;
        column_ctx->is_enclosed_begin = OG_FALSE;
        ret = ogsql_put_field_into_column(worker, fetch_column, row, col);
        ogconn_common_free_fixed_buffer(pool, column_ctx->column_data.str);
        column_ctx->column_data.str = NULL;
    }
    return ret;
}

status_t ogsql_fetch_column(worker_t *worker, text_t *text, load_column_ctx_t *ogx, load_column_param_t *param,
                           text_t *sub);

static status_t ogsql_load_skip_current_line(text_t *text, worker_t *worker, bool8 *line_end, bool8 *fetch_end)
{
    load_column_param_t *param = worker->column_param;
    load_column_ctx_t *ogx = &(worker->column_ctx);
    text_t column_txt;

    if (!ogx->need_skip_current_line || ogx->reach_line_end) {
        LOAD_RESET_COLUMN_CTX(ogx);
        *line_end = OG_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
        return OGCONN_SUCCESS;
    }

    OGSQL_LOAD_DEBUG("[Skip Line] begin to skip line %llu.",
        worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);

    while (!ogx->reach_line_end && text->len > 0) {
        if (ogsql_fetch_column(worker, text, ogx, param, &column_txt) != OGCONN_SUCCESS) {
            OGSQL_LOAD_DEBUG("[Skip Line] failed to skip line %llu.",
                            worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);
            return OGCONN_ERROR;
        }
    }

    if (text->len == 0) {
        *fetch_end = OG_TRUE;
    }
    if (ogx->reach_line_end) {
        OGSQL_LOAD_DEBUG("[Skip Line] end to skip line %llu.",
            worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);
        LOAD_RESET_COLUMN_CTX(ogx);
        *line_end = OG_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
    }
    return OGCONN_SUCCESS;
}

static void ogsql_load_print_conn_error(worker_t *worker)
{
    int32 code;
    const char *msg = NULL;

    ogconn_get_error(worker->conn_info.conn, &code, &msg);
    if (code != OG_SUCCESS) {
        OGSQL_LOAD_DEBUG("[Print Error] %d : %s", code, msg);
        OGSQL_PRINTF(ZSERR_LOAD, "errcode = %d , errinfo = %s.", code, msg);
    }
}
static status_t ogsql_load_line_check(worker_t *worker, load_column_ctx_t *ogx, bool8 *line_end)
{
    uint32 col_num = GET_LOADER(worker)->col_num;

    if (ogx->col_id == col_num) {
        if (ogx->reach_line_end) {
            // line reach end
            LOAD_RESET_COLUMN_CTX(ogx);
            worker->locat_info.curr_row++;
            *line_end = OG_TRUE;
            LOAD_LOCAT_INFO_INC(worker);
            OGSQL_LOAD_DEBUG("[Worker Thread]fetch line end.");
            return OGCONN_SUCCESS;
        } else {
            OGSQL_PRINTF(ZSERR_LOAD, "too much columns at line " PRINT_FMT_UINT64 "", CURRENT_FILE_ROW(worker));
            ogx->need_skip_current_line = OG_TRUE;
            worker->check_line_errs++;
            return OGCONN_ERROR;
        }
    }

    // Insufficient number of columns need supplemental null
    if (ogx->reach_line_end) {
        OGSQL_PRINTF(ZSERR_LOAD, "too less columns at line " PRINT_FMT_UINT64 "", CURRENT_FILE_ROW(worker));
        worker->check_line_errs++;
        LOAD_RESET_COLUMN_CTX(ogx);
        *line_end = OG_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
        OGSQL_LOAD_DEBUG("[Worker Thread]fetch line end.");
        return OGCONN_ERROR;
    }

    return OGCONN_SUCCESS;
}

static status_t ogsql_adjust_column_value(worker_t *worker)
{
    loader_t *loader = GET_LOADER(worker);
    load_column_ctx_t *ogx = &(worker->column_ctx);
    uint16 *ind = GET_IND_PTR(worker, worker->locat_info.curr_row, ogx->col_id);
    load_fetch_column_t fetch_column;
    char space_buf[OG_MAX_NAME_LEN];
    
    if (!g_load_opts.null2space) {
        return OG_SUCCESS;
    }
    
    if (LOAD_TYPE_NEED_PUT_SPACE(loader->col_desc[ogx->col_id].type) &&
        (!loader->col_desc[ogx->col_id].nullable) &&
        (*ind == OGCONN_NULL)) {
        fetch_column.column_txt.str = space_buf;
        fetch_column.column_txt.str[0] = ' ';
        fetch_column.column_txt.len = 1;
        fetch_column.column_ctx = ogx;

        return ogsql_put_field_into_column_ctx(worker, &fetch_column, worker->locat_info.curr_row, ogx->col_id);
    }

    return OG_SUCCESS;
}

static status_t ogsql_fetch_line(text_t *text, worker_t *worker, bool8 *line_end, bool8 *fetch_end)
{
    load_column_param_t *param = worker->column_param;
    load_column_ctx_t *ogx = &(worker->column_ctx);
    load_fetch_column_t fetch_column;

    fetch_column.column_ctx = ogx;

    *fetch_end = OG_FALSE;

    if (text->len == 0) {
        *fetch_end = OG_TRUE;
        return OGCONN_SUCCESS;
    }

    *line_end = OG_FALSE;

    while (text->len > 0) {
        if (ogsql_fetch_column(worker, text, ogx, param, &(fetch_column.column_txt)) != OGCONN_SUCCESS) {
            ogx->fatal_error = OG_TRUE;
            return OGCONN_ERROR;
        }

        OGSQL_LOAD_DEBUG("[Put Column Data]put %s data len [%u] into row [%u] column [%s][%u].",
                        fetch_column.column_ctx->reach_column_end ? "complete" : "part",
                        fetch_column.column_txt.len,
                        worker->locat_info.curr_row,
                        GET_LOADER(worker)->col_desc[fetch_column.column_ctx->col_id].name,
                        fetch_column.column_ctx->col_id);

        if (ogsql_put_field_into_column_ctx(worker, &fetch_column, worker->locat_info.curr_row,
            ogx->col_id) != OGCONN_SUCCESS) {
            ogsql_load_print_conn_error(worker);
            ogx->need_skip_current_line = OG_TRUE;
            return OGCONN_ERROR;
        }

        if (ogx->reach_column_end) {
            // adjust column value based on config
            OG_RETURN_IFERR(ogsql_adjust_column_value(worker));
            ogx->col_id++;
            ogx->lob_writed_length = 0;
        }

        if (ogsql_load_line_check(worker, ogx, line_end) != OGCONN_SUCCESS) {
            return OGCONN_ERROR;
        }

        if (*line_end) {
            return OGCONN_SUCCESS;
        }
    }
    OGSQL_LOAD_DEBUG("[Worker Thread]fetch block end , line not end.");
    *fetch_end = OG_TRUE;
    *line_end = OG_FALSE;
    return OGCONN_SUCCESS;
}

static bool8 ogsql_need_parser_enclosed(worker_t *worker)
{
    load_column_param_t *param = worker->column_param;

    if (!CM_IS_VALID_ENCLOSED_CHAR(param->enclosed_char)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static status_t ogsql_check_load_column(worker_t *worker, load_column_ctx_t *ogx)
{
    if (ogx->loaded_length > MAX_LOAD_COLUMN_LEN(GET_LOADER(worker)->col_desc[ogx->col_id].type)) {
        OGSQL_PRINTF(ZSERR_LOAD, "row %llu column %s size %llu exceeds max size %llu.",
                    CURRENT_FILE_ROW(worker), GET_LOADER(worker)->col_desc[ogx->col_id].name,
                    ogx->loaded_length,
                    MAX_LOAD_COLUMN_LEN(GET_LOADER(worker)->col_desc[ogx->col_id].type));
        return OGCONN_ERROR;
    }
    if (ogx->reach_column_end) {
        ogx->loaded_length = 0;
    }
    return OGCONN_SUCCESS;
}

status_t ogsql_fetch_column(worker_t *worker, text_t *text, load_column_ctx_t *ogx, load_column_param_t *param,
                           text_t *sub)
{
    char current_char;
    bool32 matched_flag = OG_FALSE;

    sub->str = text->str;
    ogx->is_enclosed_begin = ogx->is_enclosed; /* first char is enclosed ? */

    /* column is end , must NOT be enclosed */
    for (uint32 i = 0; i < text->len; i++) {
        current_char = text->str[i];
        matched_flag = OG_FALSE;

        /* enclosed char */
        if (ogsql_need_parser_enclosed(worker)) {
            if (current_char == param->enclosed_char) {
                ogx->is_enclosed = !ogx->is_enclosed;
                continue;
            }

            if (ogx->is_enclosed) {
                continue;
            }
        }

        /* reach line end */
        if (param->line_terminal[ogx->line_terminal_matched_cnt] == current_char) {
            ogx->line_terminal_matched_cnt++;
            matched_flag = OG_TRUE;
            if (param->line_terminal_len == ogx->line_terminal_matched_cnt) {
                sub->len = i + 1 - param->line_terminal_len;
                CM_REMOVE_FIRST_N(text, i + 1);
                ogx->reach_column_end = OG_TRUE;
                ogx->reach_line_end = OG_TRUE;
                ogx->line_terminal_matched_cnt = 0;
                ogx->field_terminal_matched_cnt = 0;
                ogx->is_first_chunk = (ogx->loaded_length == 0);
                ogx->loaded_length += sub->len;
                OG_RETURN_IFERR(ogsql_check_load_column(worker, ogx));
                return OGCONN_SUCCESS;
            }
        }

        /* check field terminal */
        if (param->field_terminal[ogx->field_terminal_matched_cnt] == current_char) {
            ogx->field_terminal_matched_cnt++;
            matched_flag = OG_TRUE;
            /* reach column end */
            if (param->field_terminal_len == ogx->field_terminal_matched_cnt) {
                sub->len = i + 1 - param->field_terminal_len;
                CM_REMOVE_FIRST_N(text, i + 1);
                ogx->reach_column_end = OG_TRUE;
                ogx->reach_line_end = OG_FALSE;
                ogx->line_terminal_matched_cnt = 0;
                ogx->field_terminal_matched_cnt = 0;
                ogx->is_first_chunk = (ogx->loaded_length == 0);
                ogx->loaded_length += sub->len;
                OG_RETURN_IFERR(ogsql_check_load_column(worker, ogx));
                return OGCONN_SUCCESS;
            }
        }

        if (matched_flag) {
            continue;
        }

        if (!ogsql_need_parser_enclosed(worker) || g_load_opts.enclosed_optionally) {
            continue;
        }

        /* field terminal check failed. */
        OGSQL_PRINTF(ZSERR_LOAD, "unexpected field terminal(ASCII:0x%x) at row %llu column %u end.",
                    (uint32)current_char, CURRENT_FILE_ROW(worker), ogx->col_id + 1);
        return OGCONN_ERROR;
    }

    sub->len = text->len;
    ogx->reach_column_end = OG_FALSE;
    ogx->reach_line_end = OG_FALSE;
    CM_TEXT_CLEAR(text);
    ogx->is_first_chunk = (ogx->loaded_length == 0);
    ogx->loaded_length += sub->len;
    OG_RETURN_IFERR(ogsql_check_load_column(worker, ogx));
    return OGCONN_SUCCESS;
}

static inline void ogsql_worker_error_info_output(ogconn_stmt_t stmt, worker_t *worker, uint32 actual_batch_errs,
                                                 uint32 *skip_rows)
{
    uint32 i;
    uint32 line;
    uint32 rows;
    char *err_message = NULL;
    int32 code;

    for (i = 0; i < actual_batch_errs; i++) {
        if (ogconn_get_batch_error2(stmt, &line, &code, &err_message, &rows) != OG_SUCCESS || rows == 0) {
            break;
        } else {
            if (g_load_opts.ignore && code == ERR_DUPLICATE_KEY) {
                (*skip_rows)++;
            }
        }

        ogsql_printf("line %llu:OG-%05d, %s\n",
            (uint64)(worker->locat_info.read_rows - worker->check_line_errs - worker->locat_info.curr_row + line + 1),
            code, err_message);
    }
}

static void load_post_nologging(loader_t *loader)
{
    char truncate_sql[OG_BUFLEN_256];
    int32 iret_snprintf;

    if (!g_load_opts.nologging) {
        return;
    }

    iret_snprintf = snprintf_s(truncate_sql, sizeof(truncate_sql), sizeof(truncate_sql) - 1, "truncate table %s",
        loader->table);
    if (iret_snprintf < 0) {
        ogsql_printf("make truncate sql failed.");
        return;
    }

    // do truncate when failed
    if (ogconn_query(CONN, (const char *)truncate_sql) != OG_SUCCESS) {
        ogsql_print_error(CONN);
    }
    return;
}

static void load_worker_post_nologging(worker_t *worker)
{
    if (!g_load_opts.nologging) {
        return;
    }
    // do rollback when failed
    if (ogconn_rollback(worker->conn_info.conn) != OG_SUCCESS) {
        ogsql_print_error(worker->conn_info.conn);
    }
    return;
}

static inline int ogsql_load_rows_to_db(ogconn_stmt_t stmt, worker_t *worker)
{
    int exec_status;
    uint32 affected_rows;
    uint32 actual_batch_errs = worker->actual_batch_errs;
    uint32 allowed_batch_errs = worker->allowed_batch_errs;
    uint32 skip_rows = 0;

    if (actual_batch_errs > allowed_batch_errs) {
        return OGCONN_SUCCESS;
    }
    allowed_batch_errs -= actual_batch_errs;

    if (g_load_opts.ignore) {
        (void)ogconn_set_stmt_attr(stmt, OGCONN_ATTR_ALLOWED_BATCH_ERRS, &worker->locat_info.curr_row, sizeof(uint32));
    } else {
        (void)ogconn_set_stmt_attr(stmt, OGCONN_ATTR_ALLOWED_BATCH_ERRS, &allowed_batch_errs, sizeof(uint32));
    }
    
    ogconn_set_paramset_size(stmt, worker->locat_info.curr_row);

    exec_status = ogconn_execute(stmt);

    affected_rows = ogconn_get_affected_rows(stmt);
    
    (void)ogconn_get_stmt_attr(stmt, OGCONN_ATTR_ACTUAL_BATCH_ERRS, (void *)&actual_batch_errs, sizeof(uint32), NULL);

    ogsql_worker_error_info_output(stmt, worker, actual_batch_errs, &skip_rows);

    if (g_load_opts.replace) {
        worker->loaded_rows += worker->locat_info.curr_row - actual_batch_errs;
        worker->error_rows += actual_batch_errs;
    } else {
        worker->loaded_rows += affected_rows;
        worker->error_rows += worker->locat_info.curr_row - affected_rows - skip_rows;
    }
    
    worker->actual_batch_errs += actual_batch_errs - skip_rows;
    worker->skip_rows += skip_rows;
    
    // when failed to execute output the error information
    if (exec_status != OGCONN_SUCCESS) {
        ogsql_print_error(worker->conn_info.conn);
        OGSQL_PRINTF(ZSERR_LOAD, "execute failed at line %llu in file",
                    worker->start_line + worker->loaded_rows - worker->prev_loaded_rows);
        (void)ogconn_rollback(worker->conn_info.conn);
        return OGCONN_ERROR;
    }

    worker->locat_info.curr_row = 0;
    worker->check_line_errs = 0;
    ogconn_set_paramset_size(stmt, worker->max_batch_rows);

    return OGCONN_SUCCESS;
}

static status_t ogsql_worker_load(ogconn_stmt_t stmt, text_t *read_buf, worker_t *worker)
{
    load_column_ctx_t *column_ctx = &(worker->column_ctx);
    bool8 line_end = OG_FALSE;
    bool8 fetch_end = OG_FALSE;

    worker->locat_info.curr_line_in_block = 0;
    worker->prev_loaded_rows = worker->loaded_rows;
    worker->check_line_errs = 0;

    while (!worker->closed && !fetch_end && !OGSQL_CANCELING) {
        if (worker->locat_info.curr_row >= worker->max_batch_rows && line_end) {
            if (ogsql_load_rows_to_db(stmt, worker) != OGCONN_SUCCESS) {
                return OGCONN_ERROR;
            }
        }

        if (column_ctx->need_skip_current_line) {
            /* skip error line. */
            if (ogsql_load_skip_current_line(read_buf, worker, &line_end, &fetch_end) != OGCONN_SUCCESS) {
                return OGCONN_ERROR;
            }
        } else {
            if (ogsql_fetch_line(read_buf, worker, &line_end, &fetch_end) != OGCONN_SUCCESS) {
                worker->actual_batch_errs++;
                worker->error_rows++;
                if (column_ctx->fatal_error) {
                    return OGCONN_ERROR;
                }
            }
        }
        
        // if no rows in read_buff
        if (fetch_end) {
            if (worker->locat_info.curr_row > 0 && line_end) {
                if (ogsql_load_rows_to_db(stmt, worker) != OGCONN_SUCCESS) {
                    return OG_ERROR;
                }
            }

            return OG_SUCCESS;
        }

        if (worker->actual_batch_errs > worker->allowed_batch_errs) {
            return OG_SUCCESS;
        }
    }

    return OGCONN_SUCCESS;
}

static inline void ogsql_loader_ignore_lines(loader_t *loader)
{
    load_line_ctx_t ogx;

    loader->ignored_lines = 0;

    while (loader->ignored_lines < g_load_opts.ignore_lines) {
        ogx.is_enclosed = OG_FALSE;
        ogx.reach_line_end = OG_FALSE;
        ogx.line_terminal_matched_cnt = 0;

        do {
            EN_LOADER_READ_STATUS ret = ogsql_loader_read_line(loader, &ogx);
            if (ret == LOADER_READ_END) {
                loader->status = LOADER_STATUS_ERR;
                OGSQL_PRINTF(ZSERR_LOAD, "ignore lines(%llu) exceed the file lines", g_load_opts.ignore_lines);
                return;
            }

            loader->line_buf.len = 0;
        } while (!ogx.reach_line_end);

        ++loader->ignored_lines;
        ++loader->file_rows;
    }
}

status_t ogsql_worker_prepare(worker_t *worker);
status_t ogsql_worker_open_conn(worker_t *worker);

static status_t load_prepare_conn(worker_t *worker)
{
    worker->conn_info = g_conn_info;
    if (LOAD_SERIAL) {
        return OG_SUCCESS;
    }

    worker->conn_info.stmt = NULL;
    MEMS_RETURN_IFERR(memcpy_s(worker->conn_info.passwd, OG_PASSWORD_BUFFER_SIZE + 4,
        g_load_pswd, OG_PASSWORD_BUFFER_SIZE + 4));

    return ogsql_worker_open_conn(worker);
}

status_t ogsql_worker_init(worker_t *worker)
{
    worker->locat_info.curr_row = 0;
    worker->locat_info.read_rows = 0;
    worker->loaded_rows = 0;
    worker->committed_rows = 0;
    worker->error_rows = 0;
    worker->skip_rows = 0;
    worker->check_line_errs = 0;

    worker->col_data_buf = NULL;

    worker->orig_block_buf = NULL;

    worker->block.id = 0;
    worker->block.start_line = 0;
    worker->block.buf.str = 0;
    worker->block.buf.len = 0;

    LOAD_RESET_COLUMN_CTX(&(worker->column_ctx));

    // prepare connection
    OG_RETURN_IFERR(load_prepare_conn(worker));
    // prepare sql and bind buffer
    OG_RETURN_IFERR(ogsql_worker_prepare(worker));

    return OG_SUCCESS;
}

static void ogsql_worker_close_conn(worker_t *worker)
{
    if (worker->conn_info.stmt) {
        ogconn_free_stmt(worker->conn_info.stmt);
        worker->conn_info.stmt = NULL;
    }

    if (worker->conn_info.is_conn) {
        ogconn_disconnect(worker->conn_info.conn);
        worker->conn_info.is_conn = OG_FALSE;
    }

    if (worker->conn_info.conn) {
        ogconn_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
    }
}

void ogsql_worker_free(worker_t *worker)
{
    if (!LOAD_SERIAL) {
        ogsql_worker_close_conn(worker);
    }

    if (worker->col_data_buf != NULL) {
        free(worker->col_data_buf);
        worker->col_data_buf = NULL;
    }

    if (worker->orig_block_buf != NULL) {
        ogconn_common_free_fixed_buffer(&(GET_LOADER(worker)->block_pool), worker->orig_block_buf);
        worker->orig_block_buf = NULL;
    }

    worker->block.buf.str = NULL;
    worker->block.buf.len = 0;
}

static status_t ogsql_loader_select_columns(char *select_columns)
{
    uint32 i;
    char *column_name = NULL;

    if (g_load_opts.obj_list.count > 0) {
        for (i = 0; i < g_load_opts.obj_list.count; i++) {
            column_name = cm_list_get(&g_load_opts.obj_list, i);
            MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\"", strlen("\"")));
            MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, column_name, strlen(column_name)));

            if (i < g_load_opts.obj_list.count - 1) {
                MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\",", strlen("\",")));
            }
        }
        MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\"", strlen("\"")));
        MEMS_RETURN_IFERR(strncpy_s(g_load_opts.trailing_columns, MAX_LOAD_SQL_SIZE, select_columns,
            strlen(select_columns)));
    } else {
        MEMS_RETURN_IFERR(strncpy_s(select_columns, MAX_LOAD_SQL_SIZE, "*", strlen("*")));
    }

    return OG_SUCCESS;
}

static status_t ogsql_loader_varstr_column_size(ogconn_conn_t conn, ogconn_inner_column_desc_t *col_desc, uint16
    *bnd_size)
{
    char charset_name[OG_MAX_NAME_LEN];
    uint32 local_charlen;
    uint32 server_charlen;

    if (col_desc->is_character) {
        *bnd_size = CM_ALIGN4(col_desc->size * OG_CHAR_TO_BYTES_RATIO);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(ogconn_get_conn_attr(conn, OGCONN_ATTR_NLS_CHARACTERSET, charset_name,
        sizeof(charset_name), NULL));
    server_charlen = CM_CHARSET_FUNC(cm_get_charset_id((const char *)charset_name)).max_bytes_per_char();
    OG_RETURN_IFERR(ogconn_get_conn_attr(conn, OGCONN_ATTR_CHARSET_TYPE, charset_name,
        sizeof(charset_name), NULL));
    local_charlen = CM_CHARSET_FUNC(cm_get_charset_id((const char *)charset_name)).max_bytes_per_char();
    /*
        if local charset length per character is
        larger than server charset length per character,
        bound size should be resized larger than column definition
    */
    if (server_charlen < local_charlen) {
        *bnd_size = CM_ALIGN4(col_desc->size * local_charlen / server_charlen);
    } else {
        *bnd_size = CM_ALIGN4(col_desc->size);
    }
    return OG_SUCCESS;
}

static inline int ogsql_loader_column_desc(loader_t *loader)
{
    uint32 i;
    char trailing_columns[MAX_LOAD_SQL_SIZE] = { 0 };
    char *trailing_string = trailing_columns;

    OG_RETURN_IFERR(ogsql_loader_select_columns(trailing_string));

    /* the value of loader->table already included char '"' or char '`' to express case_sensitive tablename */
    PRTS_RETURN_IFERR(snprintf_s(loader->insert_sql, MAX_LOAD_SQL_SIZE, MAX_LOAD_SQL_SIZE - 1, "select %s from %s limit 0",
        trailing_columns, loader->table));

    if (!IS_CONN) {
        (void)ogsql_print_disconn_error();
        return OG_ERROR;
    }

    if (ogconn_prepare(STMT, loader->insert_sql) != OGCONN_SUCCESS) {
        ogsql_print_error(CONN);
        return OGCONN_ERROR;
    }

    if (ogconn_get_column_count(STMT, &loader->col_num) != OGCONN_SUCCESS) {
        ogsql_print_error(CONN);
        return OGCONN_ERROR;
    }

    if (loader->col_num == 0) {
        OGSQL_PRINTF(ZSERR_LOAD, "assert raised, expect: loader->col_num(%u) > 0", loader->col_num);
        return OG_ERROR;
    }

    loader->row_size = 0;
    loader->lob_col_num = 0;

    loader->col_desc = g_columns;
    for (i = 0; i < loader->col_num; i++) {
        if (ogconn_desc_inner_column_by_id(STMT, i, &(loader->col_desc[i])) != OGCONN_SUCCESS) {
            ogsql_print_error(CONN);
            return OGCONN_ERROR;
        }

        loader->col_bndtype[i] = loader->col_desc[i].type;

        switch (loader->col_desc[i].type) {
            case OGCONN_TYPE_DATE:
            case OGCONN_TYPE_TIMESTAMP:
            case OGCONN_TYPE_TIMESTAMP_TZ_FAKE:
            case OGCONN_TYPE_TIMESTAMP_TZ:
            case OGCONN_TYPE_TIMESTAMP_LTZ:
                loader->col_bndtype[i] = OGCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(40);
                break;

            case OGCONN_TYPE_INTERVAL_DS:
                loader->col_bndtype[i] = OGCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(OG_MAX_DS_INTERVAL_STRLEN + 8);
                break;

            case OGCONN_TYPE_INTERVAL_YM:
                loader->col_bndtype[i] = OGCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(OG_MAX_YM_INTERVAL_STRLEN + 4);
                break;

            case OGCONN_TYPE_NUMBER:
            case OGCONN_TYPE_NUMBER2:
            case OGCONN_TYPE_DECIMAL:
                loader->col_bndtype[i] = OGCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(180);  // > 38 + 127
                break;

            case OGCONN_TYPE_BOOLEAN:
                loader->col_bndtype[i] = OGCONN_TYPE_STRING;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(12);
                break;

            case OGCONN_TYPE_CHAR:
            case OGCONN_TYPE_VARCHAR:
            case OGCONN_TYPE_STRING:
                OG_RETURN_IFERR(ogsql_loader_varstr_column_size(CONN, &loader->col_desc[i], &loader->col_bndsz[i]));
                break;

            case OGCONN_TYPE_BINARY:
            case OGCONN_TYPE_VARBINARY:
            case OGCONN_TYPE_RAW:
            case OGCONN_TYPE_INTEGER:
            case OGCONN_TYPE_UINT32:
            case OGCONN_TYPE_BIGINT:
            case OGCONN_TYPE_REAL:
                loader->col_bndsz[i] = CM_ALIGN4(loader->col_desc[i].size);
                break;

            case OGCONN_TYPE_BLOB:
                if (ogconn_get_call_version(CONN) >= CS_VERSION_24 && loader->col_desc[i].is_jsonb &&
                    g_load_opts.convert_jsonb) {
                    loader->col_bndtype[i] = OGCONN_TYPE_CLOB;
                }
            /* fall through */
            case OGCONN_TYPE_CLOB:
            case OGCONN_TYPE_IMAGE:
                loader->col_bndsz[i] = CM_ALIGN4(sizeof(ogconn_lob_t));
                loader->lob_col_num++;
                break;

            default:
                OGSQL_PRINTF(ZSERR_LOAD, "the date type (%s) is not supported",
                            get_datatype_name_str(loader->col_desc[i].type + OG_TYPE_BASE));
                return OGCONN_ERROR;
        }  // end switch

        loader->row_size += loader->col_bndsz[i];
    }

    return OGCONN_SUCCESS;
}

static status_t ogsql_loader_make_replace_sql(loader_t *loader, text_t *sql_text, const char *hint_comment)
{
    int iret;
    uint32 i;

    iret = snprintf_s(sql_text->str, MAX_LOAD_SQL_SIZE, MAX_CMD_LEN - 1, "replace %s into %s set ",
                      hint_comment, loader->table);
    PRTS_RETURN_IFERR(iret);
    sql_text->len = iret;

    for (i = 0; i < loader->col_num; i++) {
        if (i != 0) {  // more than columns
            CM_TEXT_APPEND(sql_text, ',');
        }
                
        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len,
                          MAX_LOAD_SQL_SIZE - sql_text->len - 1, "\"%s\"=:%u", loader->col_desc[i].name, i);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }

    if (g_load_opts.set_flag) {
        CM_TEXT_APPEND(sql_text, ',');
        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len,
                          strlen(g_load_opts.set_columns), "%s", g_load_opts.set_columns);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }
    
    return OGCONN_SUCCESS;
}

static status_t ogsql_loader_make_insert_sql(loader_t *loader, text_t *sql_text, const char *hint_comment,
                                            const char *trailing_columns)
{
    int iret;
    uint32 i;

    iret = snprintf_s(sql_text->str, MAX_LOAD_SQL_SIZE, MAX_CMD_LEN - 1, "insert %s into %s %s values(",
                      hint_comment, loader->table, trailing_columns);
    PRTS_RETURN_IFERR(iret);
    sql_text->len = iret;

    for (i = 0; i < loader->col_num; i++) {
        if (i != 0) {  // more than columns
            CM_TEXT_APPEND(sql_text, ',');
        }

        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len, MAX_CMD_LEN, ":%u", i);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }
    
    CM_TEXT_APPEND(sql_text, ')');

    return OGCONN_SUCCESS;
}

static status_t ogsql_loader_make_hint(char *hint_comment, size_t hint_len)
{
    if (!g_load_opts.replace && g_load_opts.set_flag) {
        MEMS_RETURN_IFERR(strncat_s(hint_comment, hint_len, "/*+ throw_duplicate */",
            strlen("/*+ throw_duplicate */")));
    }

    return OGCONN_SUCCESS;
}

static status_t ogsql_loader_make_sql(loader_t *loader)
{
    text_t sql_text = { .str = loader->insert_sql };
    char trailing_columns[MAX_LOAD_SQL_SIZE] = { 0 };
    char hint_comment[MAX_LOAD_SQL_SIZE] = { 0 };

    if (g_load_opts.obj_list.count > 0) {
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, "(", 1));
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, g_load_opts.trailing_columns,
            MAX_LOAD_SQL_SIZE - 1));
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, ")", 1));
    }

    OG_RETURN_IFERR(ogsql_loader_make_hint(hint_comment, sizeof(hint_comment)));

    if (g_load_opts.replace || g_load_opts.set_flag) {
        OG_RETURN_IFERR(ogsql_loader_make_replace_sql(loader, &sql_text, hint_comment));
    } else {
        OG_RETURN_IFERR(ogsql_loader_make_insert_sql(loader, &sql_text, hint_comment, trailing_columns));
    }
    
    CM_NULL_TERM(&sql_text);
    return OGCONN_SUCCESS;
}

static uint16 load_estimate_batch_rows(worker_t *worker)
{
    uint16 max_batch_rows;
    uint32 bnd_row_size = GET_LOADER(worker)->row_size +
        GET_LOADER(worker)->col_num * sizeof(uint16);

    max_batch_rows = g_load_opts.max_databuf_size / bnd_row_size;

    if (GET_LOADER(worker)->lob_col_num > 0) {
        max_batch_rows = MIN(max_batch_rows,
            MAX_LOAD_LOB_BATCH_CNT / (GET_LOADER(worker)->lob_col_num * g_load_opts.threads));
    }

    // if databuf is insufficient, at least 2 records is ensured to load
    if (max_batch_rows == 0) {
        max_batch_rows = 2;   // 2 denotes max batch rows
    }

    return max_batch_rows;
}

static inline int ogsql_worker_alloc_column_mem(worker_t *worker)
{
    uint32 i;
    uint32 pos = 0;
    size_t size;
    uint32 bnd_row_size = GET_LOADER(worker)->row_size +
                          GET_LOADER(worker)->col_num * sizeof(uint16);

    worker->max_batch_rows = load_estimate_batch_rows(worker);

    size = worker->max_batch_rows * bnd_row_size;
    if (size == 0) {
        OGSQL_PRINTF(ZSERR_LOAD, "max databuf(%u) is smaller than row size(%d)", g_load_opts.max_databuf_size,
                    bnd_row_size);
        return OGCONN_ERROR;
    }

    worker->col_data_buf = (char *)malloc(size);
    if (worker->col_data_buf == NULL) {
        OGSQL_PRINTF(ZSERR_LOAD, "Fail to allocate %u bytes for data buffer", g_load_opts.max_databuf_size);
        return OGCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(worker->col_data_buf, size, 0, size));

    for (i = 0; i < GET_LOADER(worker)->col_num; i++) {
        // allocate memory for col_data[i]
        worker->col_data[i] = worker->col_data_buf + pos;
        pos += worker->max_batch_rows * GET_LOADER(worker)->col_bndsz[i];

        // allocate memory for col_ind[i]
        worker->col_ind[i] = (uint16 *)(worker->col_data_buf + pos);
        pos += worker->max_batch_rows * sizeof(uint16);
    }

    return OGCONN_SUCCESS;
}

status_t ogsql_worker_open_conn(worker_t *worker)
{
    bool32 interactive_clt = OG_FALSE;
    uint32 remote_as_sysdba = OG_FALSE;
    status_t ret;

    worker->conn_info.conn = NULL;
    worker->conn_info.stmt = NULL;

    if (ogsql_alloc_conn(&worker->conn_info.conn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* set session interactive check disable */
    cm_spin_lock(&GET_LOADER(worker)->conn_lock, NULL);
    (void)ogconn_get_conn_attr(g_conn_info.conn, OGCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(uint32), NULL);
    cm_spin_unlock(&GET_LOADER(worker)->conn_lock);
    (void)ogconn_set_conn_attr(worker->conn_info.conn, OGCONN_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
    (void)ogconn_set_conn_attr(worker->conn_info.conn, OGCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));

    worker->conn_info.is_conn = OG_FALSE;

    (void)ogsql_switch_user(&worker->conn_info);

    if (ogsql_conn_to_server(&worker->conn_info, OG_FALSE, OG_TRUE) != OG_SUCCESS) {
        ogconn_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
        worker->conn_info.stmt = NULL;
        return OG_ERROR;
    }

    /* set nologging option */
    if (g_load_opts.nologging) {
        OG_RETURN_IFERR(ogconn_prepare(worker->conn_info.stmt, "ALTER SESSION ENABLE NOLOGGING"));
        OG_RETURN_IFERR(ogconn_execute(worker->conn_info.stmt));
    }

    /* set up nls attr */
    cm_spin_lock(&GET_LOADER(worker)->conn_lock, NULL);
    ret = ogsql_setup_conn_nls(&g_conn_info, &worker->conn_info);
    cm_spin_unlock(&GET_LOADER(worker)->conn_lock);
 
    return ret;
}

status_t ogsql_worker_prepare(worker_t *worker)
{
    const char *pcharset_name = NULL;

    if (ogsql_worker_alloc_column_mem(worker) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!worker->conn_info.is_conn) {
        (void)ogsql_print_disconn_error();
        return OG_ERROR;
    }

    /* Step 1. Set the charset based on the charset parameter of dump cmd */
    pcharset_name = cm_get_charset_name((charset_type_t)g_load_opts.charset_id);
    if (pcharset_name == NULL) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return OG_ERROR;
    }

    (void)ogconn_set_conn_attr(worker->conn_info.conn, OGCONN_ATTR_CHARSET_TYPE, pcharset_name,
        (uint32)strlen(pcharset_name));

    /* Step 2. Prepare insert SQL for the loader */
    (void)ogconn_set_stmt_attr(worker->conn_info.stmt, OGCONN_ATTR_ALLOWED_BATCH_ERRS, &worker->allowed_batch_errs,
                            sizeof(uint32));
    if (ogconn_prepare(worker->conn_info.stmt, ((loader_t *)(worker)->loader)->insert_sql) != OGCONN_SUCCESS) {
        ogsql_print_error(worker->conn_info.conn);
        return OG_ERROR;
    }

    /* Step 3. Binding parameters on insert SQL */
    ogconn_set_paramset_size(worker->conn_info.stmt, worker->max_batch_rows);
    for (uint32 i = 0; i < ((loader_t *)(worker)->loader)->col_num; i++) {
        if (ogconn_bind_by_pos(worker->conn_info.stmt, i, ((loader_t *)(worker)->loader)->col_bndtype[i],
                            worker->col_data[i], ((loader_t *)(worker)->loader)->col_bndsz[i],
                            worker->col_ind[i]) != OGCONN_SUCCESS) {
            ogsql_print_error(worker->conn_info.conn);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t ogsql_worker_commit(worker_t *worker, uint64 id)
{
    if (worker->actual_batch_errs > worker->allowed_batch_errs) {
        return OG_SUCCESS;
    }

    // commit the data that are loaded into table
    if (worker->locat_info.curr_line_in_block > 0) {
        /* complete row do commit */
        if (ogconn_commit(worker->conn_info.conn) != OGCONN_SUCCESS) {
            ogsql_print_error(worker->conn_info.conn);
            return OG_ERROR;
        }
        worker->committed_rows = worker->loaded_rows;
    }

    return OG_SUCCESS;
}

#define GET_NEXT_STATUS(ret, next, err) \
    (ret) == OG_SUCCESS ? (next) : (err)

void ogsql_worker_proc(thread_t *thread)
{
    worker_t *worker = (worker_t *)thread->argument;
    status_t ret = OG_SUCCESS;

    while (OG_TRUE) {
        if (worker->closed || OGSQL_CANCELING) {
            worker->status = WORKER_STATUS_END;
        }

        switch (worker->status) {
            case WORKER_STATUS_INIT: {
                ret = ogsql_worker_init(worker);
                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                break;
            }

            case WORKER_STATUS_RECV: {
                // read buffer from chan
                ret = cm_chan_recv_timeout(worker->chan, &worker->block, 2);
                if (ret == OG_TIMEDOUT) {
                    continue;
                }

                if (ret == OG_SUCCESS) {
                    worker->orig_block_buf = worker->block.buf.str;
                    OGSQL_LOAD_DEBUG("[Worker-Thread] recv block [%llu] size [%u]",
                                    worker->block.id, worker->block.buf.len);
                }

                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_LOAD, WORKER_STATUS_END);
                break;
            }

            case WORKER_STATUS_LOAD: {
                worker->start_line = worker->block.start_line;

                ogconn_set_paramset_size(worker->conn_info.stmt, worker->max_batch_rows);
                // process data buffer
                ret = ogsql_worker_load(worker->conn_info.stmt, &worker->block.buf, worker);
                if (ret == OG_SUCCESS) {
                    ret = ogsql_worker_commit(worker, worker->block.id);
                    if (ret == OG_SUCCESS && worker->locat_info.curr_line_in_block > 0) {
                        ogsql_load_report_current((loader_t *)worker->loader);
                    }

                    if (worker->orig_block_buf != NULL) {
                        ogconn_common_free_fixed_buffer(&(GET_LOADER(worker)->block_pool), worker->orig_block_buf);
                        worker->orig_block_buf = NULL;
                    }

                    worker->block.buf.str = NULL;
                    worker->block.buf.len = 0;
                    worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                } else {
                    load_worker_post_nologging(worker);
                    worker->status = WORKER_STATUS_ERR;
                }
                break;
            }

            case WORKER_STATUS_END:
            case WORKER_STATUS_ERR:
            default:
                ogsql_worker_free(worker);
                return;
        }
    }
}

// launch workers
status_t ogsql_launch_workers(loader_t *loader)
{
    uint32 i = 0;
    status_t status = OG_SUCCESS;

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->workers[i].id = i;
        loader->workers[i].chan = loader->chan[i];
        loader->workers[i].table = loader->table;
        loader->workers[i].loader = loader;
        loader->workers[i].closed = OG_FALSE;
        loader->workers[i].status = WORKER_STATUS_INIT;
        loader->workers[i].locat_info.curr_row = 0;
        loader->workers[i].locat_info.read_rows = 0;
        loader->workers[i].loaded_rows = 0;
        loader->workers[i].committed_rows = 0;
        loader->workers[i].error_rows = 0;
        loader->workers[i].allowed_batch_errs = loader->allowed_batch_errs;
        loader->workers[i].actual_batch_errs = 0;
        loader->workers[i].column_param = &loader->column_param;
        loader->workers[i].skip_rows = 0;
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        status = cm_create_thread(ogsql_worker_proc, 0, &loader->workers[i], &loader->threads[i]);
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static bool32 ogsql_if_all_workers_ok(loader_t *loader)
{
    uint32 i = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        if (loader->workers[i].status == WORKER_STATUS_ERR) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 ogsql_if_reach_allowed_errors(loader_t *loader)
{
    uint32 i = 0;
    uint32 total_batch_errs = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        total_batch_errs += loader->workers[i].actual_batch_errs;
        if (total_batch_errs > loader->allowed_batch_errs) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static uint32 ogsql_finished_workers(loader_t *loader)
{
    uint32 i = 0;
    uint32 sum = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        if (loader->workers[i].status == WORKER_STATUS_ERR) {
            loader->status = LOADER_STATUS_ERR;
            sum += 1;
        } else if (loader->workers[i].status == WORKER_STATUS_END) {
            sum += 1;
        }
    }

    return sum;
}

static int ogsql_loader_wait_workers(loader_t *loader)
{
    uint32 i = 0;
    uint32 sum = 0;
    uint32 loop = 0;

    while (OG_TRUE) {
        sum = 0;
        for (i = 0; i < g_load_opts.threads; i++) {
            if (loader->workers[i].status == WORKER_STATUS_ERR) {
                OGSQL_PRINTF(ZSERR_LOAD, "worker init failed")
                return OG_ERROR;
            }

            if (loader->workers[i].status == WORKER_STATUS_RECV) {
                sum += 1;
            }
        }

        if (sum == g_load_opts.threads) {
            break;
        }

        cm_sleep(1);
        loop += 1;

        if (loop > WAIT_WORKER_THREAD_TIME) {
            OGSQL_PRINTF(ZSERR_LOAD, "worker init timeout (%u ms)", WAIT_WORKER_THREAD_TIME)
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t ogsql_start_loading_thread(loader_t *loader)
{
    status_t ret = OG_SUCCESS;
    OG_RETURN_IFERR(ogsql_get_saved_pswd(g_load_pswd, sizeof(g_load_pswd)));

    do {
        if (ogsql_launch_workers(loader) != OG_SUCCESS) {
            OGSQL_PRINTF(ZSERR_LOAD, "launch workers failed")
            loader->status = LOADER_STATUS_ERR;
            ret = OG_ERROR;
            break;
        }

        if (ogsql_loader_wait_workers(loader) != OG_SUCCESS) {
            loader->status = LOADER_STATUS_ERR;
            ret = OG_ERROR;
            break;
        }
    } while (0);
    
    MEMS_RETURN_IFERR(memset_s(g_load_pswd, sizeof(g_load_pswd), 0, sizeof(g_load_pswd)));
    return ret;
}

static void ogsql_cancel_loading(loader_t *loader)
{
    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        (void)ogsql_conn_cancel(&loader->workers[i].conn_info);
    }
}

static void ogsql_join_loading_thread(loader_t *loader)
{
    // shutdown thread while cancel
    if (OGSQL_CANCELING) {
        ogsql_cancel_loading(loader);
        ogsql_stop_workers(loader);
        loader->status = LOADER_STATUS_ERR;
        return;
    }
    // shutdown thread while error occurs
    if (loader->status == LOADER_STATUS_ERR) {
        ogsql_stop_workers(loader);
        return;
    }
    // wait all workers to finish
    while (OG_TRUE) {
        if (LOAD_OCCUR_ERROR(loader)) {
            loader->status = LOADER_STATUS_ERR;
            ogsql_stop_workers(loader);
            break;
        }

        if (ogsql_finished_workers(loader) == g_load_opts.threads) {
            break;
        }

        cm_sleep(10);
    }

    ogsql_stop_workers(loader);
    return;
}

static void ogsql_loader_working(loader_t *loader)
{
    const uint32 file_buf_size = g_load_opts.max_filebuf_size;
    load_block_t block = { 0 };
    uint64 block_id = 0;
    EN_LOADER_READ_STATUS ret = LOADER_READ_OK;
    uint32 chan_index = 0;
    load_block_ctx_t block_ctx;
    text_t text_block;

    loader->status = LOADER_STATUS_OK;
    LOAD_RESET_BLOCK_CTX(&block_ctx);
    while (loader->status == LOADER_STATUS_OK && !OGSQL_CANCELING) {
        // malloc buffer for data.
        char *file_block = ogconn_common_alloc_fixed_buffer(&(loader->block_pool));
        if (file_block == NULL) {
            OGSQL_PRINTF(ZSERR_LOAD, "malloc failed, %u", file_buf_size);
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        MEMS_RETVOID_IFERR(memset_s(file_block, file_buf_size + 1, 0, file_buf_size + 1));

        text_block.str = file_block;
        text_block.len = 0;

        ret = ogsql_loader_read_block(loader, &text_block, file_buf_size, &block_ctx);
        // error
        if (ret == LOADER_READ_ERR) {
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        // reach end
        OG_BREAK_IF_TRUE(ret == LOADER_READ_END);

        block.start_line = loader->start_line;
        block.id = block_id;
        block.buf = text_block;

        // send data to the channel
        OGSQL_LOAD_DEBUG("[Send Block] ID %llu size %u to chan %u , start line %llu, %s row.", block.id, text_block.len,
            (chan_index % g_load_opts.threads), block.start_line,
            (block_ctx.is_complete_row ? "complete" : "part"));
        // errors occurs, stop sender
        if (LOAD_OCCUR_ERROR(loader)) {
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        while (OG_TIMEDOUT == cm_chan_send_timeout(loader->chan[chan_index % g_load_opts.threads], &block, 2)) {
            if (LOAD_OCCUR_ERROR(loader)) {
                loader->status = LOADER_STATUS_ERR;
                break;
            }
            OG_BREAK_IF_TRUE(OGSQL_CANCELING);
        }

        if (block_ctx.is_complete_row) {
            chan_index++;
        }
        block_id++;
    }
    return;
}

static status_t ogsql_pre_loading(loader_t *loader)
{
    // commit the pending transaction in main connection
    if (ogconn_commit(g_conn_info.conn) != OGCONN_SUCCESS) {
        ogsql_print_error(g_conn_info.conn);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void ogsql_start_loading(loader_t *loader)
{
    if (ogsql_pre_loading(loader) != OG_SUCCESS) {
        ogsql_stop_workers(loader);
        return;
    }

    if (ogsql_start_loading_thread(loader) != OG_SUCCESS) {
        ogsql_stop_workers(loader);
        return;
    }

    ogsql_loader_working(loader);

    // stop chan sender
    ogsql_loader_close_chan(loader);

    // wait all workers to finish
    ogsql_join_loading_thread(loader);

    return;
}

static inline int ogsql_loader_prepare(loader_t *loader)
{
    /* Set the charset based on the charset parameter of dump cmd */
    if (ogsql_reset_charset(g_load_opts.charset_id, g_local_config.charset_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Get descriptions of columns of the table */
    if (ogsql_loader_column_desc(loader) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    /*  Generate the insert SQL for the loader */
    return ogsql_loader_make_sql(loader);
}

static int ogsql_load_file(loader_t *loader)
{
    en_loader_status status;

    if (g_load_opts.threads < 1 || g_load_opts.threads > 128) {
        g_load_opts.threads = LOADER_DEFAULT_THREADS;
        OGSQL_PRINTF(ZSERR_LOAD, "threads should be in [1, 128]")
        return OGCONN_ERROR;
    }

    if (ogsql_loader_init(loader) != OGCONN_SUCCESS) {
        ogsql_loader_free(loader);
        return OGCONN_ERROR;
    }

    ogsql_loader_ignore_lines(loader);
    status = loader->status;
    if (status != LOADER_STATUS_OK) {
        ogsql_loader_free(loader);
        return status;
    }

    ogsql_start_loading(loader);

    status = loader->status;

    ogsql_load_report_summary(loader);

    ogsql_loader_free(loader);

    /* Restore OGSQL Client Character Set */
    if (ogsql_reset_charset(g_local_config.charset_id, g_load_opts.charset_id) != OG_SUCCESS) {
        return OGCONN_ERROR;
    }

    if (OGSQL_CANCELING) {
        OG_THROW_ERROR(ERR_OPERATION_CANCELED);
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    return (int)status;
}

static inline int ogsql_parse_loading_file(lex_t *lex, loader_t *loader)
{
    word_t word;
    if (lex_expected_fetch_word2(lex, "DATA", "INFILE") != OG_SUCCESS) {
        return OGCONN_ERROR;
    }

    if (lex_expected_fetch_enclosed_string(lex, &word) != OG_SUCCESS) {
        return OGCONN_ERROR;
    }
    cm_trim_text(&word.text.value);
    return cm_text2str(&word.text.value, loader->load_file, MAX_ENTITY_LEN);
}

static inline int ogsql_parse_loading_object(lex_t *lex, loader_t *loader)
{
    word_t word;
    text_buf_t tbl_name_buf;

    tbl_name_buf.max_size = MAX_ENTITY_LEN;
    tbl_name_buf.str = loader->table;
    tbl_name_buf.len = 0;

    if (lex_expected_fetch_word2(lex, "INTO", "TABLE") != OG_SUCCESS) {
        return OGCONN_ERROR;
    }

    if (lex_expected_fetch_tblname(lex, &word, &tbl_name_buf) != OG_SUCCESS) {
        return OGCONN_ERROR;
    }
    CM_NULL_TERM(&tbl_name_buf);

    return OGCONN_SUCCESS;
}

static int ogsql_insert_load_columns(load_option_t *load_opt, const text_t *obj_name, bool32 to_upper)
{
    char obj_name_buf[OGSQL_MAX_OBJECT_LEN] = "";
    char *object_name = obj_name_buf;

    if (load_opt->obj_list.count > OG_MAX_COLUMNS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the columns number exceed the maximum(%u)", OG_MAX_COLUMNS);
        return OG_ERROR;
    }

    if (obj_name->len > OGSQL_MAX_OBJECT_LEN) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the object name is too long");
        return OG_ERROR;
    }

    if (to_upper) {
        cm_text2str_with_upper(obj_name, obj_name_buf, OGSQL_MAX_OBJECT_LEN);
    } else {
        OG_RETURN_IFERR(cm_text2str(obj_name, obj_name_buf, OGSQL_MAX_OBJECT_LEN));
    }

    return ogsql_generate_obj(&load_opt->obj_list, object_name);
}

static status_t ogsql_parse_trail_columns(lex_t *lex, loader_t *loader, load_option_t *load_opt)
{
    word_t word;
    bool32 star_flag = OG_FALSE;
    bool32 end_flag = OG_FALSE;
    bool32 has_next = OG_FALSE;

    OG_RETURN_IFERR(lex_try_fetch(lex, "(", &star_flag));

    if (!star_flag) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tariling columns missing \"(\"");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        has_next = OG_FALSE;
        end_flag = OG_FALSE;
        if (!IS_VARIANT(&word)) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name was found");
            return OG_ERROR;
        }

        if (ogsql_insert_load_columns(load_opt, &word.text.value,
            !IS_DQ_STRING(word.type) && load_opt->is_case_insensitive) != OG_SUCCESS) {
            cm_set_error_loc(word.loc);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            OG_RETURN_IFERR(lex_try_fetch(lex, ")", &end_flag));
            if (!end_flag) {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tariling columns missing \")\"");
                return OG_ERROR;
            }
            break;
        }

        if (lex_fetch(lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (load_opt->obj_list.count == 0) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no columns needs to be load");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#define LOPT_FIELDS_ENCLOSED   0
#define LOPT_FIELDS_TERMINATED 10
#define LOPT_LINES_TERMINATED  20
#define LOPT_IGNORE            30
#define LOPT_THREADS           40
#define LOPT_ERRORS            50
#define LOPT_NOLOGGING         60
#define LOPT_DEBUG_ON          70
#define LOPT_CHARSET           80
#define LOPT_TRAILING_COLUMNS  90
#define LOPT_NULL_SPACE        100
#define LOPT_REPLACE           110
#define LOPT_SET_COLUMN        120
#define LOPT_DECRYPT           130
#define LOPT_CONV_JSONB        140

static inline int ogsql_parse_loading_options_ignore(lex_t *lex, load_option_t *load_opt, uint32 *matched_id)
{
    status_t ret;

    ret = lex_expected_fetch_uint64(lex, &load_opt->ignore_lines);
    if (ret == OG_SUCCESS) {
        ret = lex_expected_fetch_1of2(lex, "ROWS", "LINES", matched_id);
        OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
    } else {
        load_opt->ignore = OG_TRUE;
    }
    return OGCONN_SUCCESS;
}

static int ogsql_parse_loading_options(lex_t *lex, loader_t *loader, load_option_t *load_opt)
{
    status_t ret;
    uint32 matched_id;
    char opt_char;
    char terminate_str[TERMINATED_STR_ARRAY_SIZE] = { 0 };
    char *key_word_info = NULL;
    bool32 equal_flag = OG_TRUE;

    static const word_record_t opt_records[] = {
        { .id = LOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "fields", "enclosed", "by" } } },
        { .id = LOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "columns", "enclosed", "by" } } },
        { .id = LOPT_FIELDS_TERMINATED, .tuple = { 3, { "fields", "terminated", "by" } } },
        { .id = LOPT_FIELDS_TERMINATED, .tuple = { 3, { "columns", "terminated", "by" } } },
        { .id = LOPT_LINES_TERMINATED,  .tuple = { 3, { "lines", "terminated", "by" } } },
        { .id = LOPT_LINES_TERMINATED,  .tuple = { 3, { "rows", "terminated", "by" } } },
        { .id = LOPT_DECRYPT,           .tuple = { 2, { "decrypt", "by" } } },
        { .id = LOPT_IGNORE,            .tuple = { 1, { "IGNORE" } } },
        { .id = LOPT_THREADS,           .tuple = { 1, { "THREADS" } } },
        { .id = LOPT_ERRORS,            .tuple = { 1, { "ERRORS" } } },
        { .id = LOPT_NOLOGGING,         .tuple = { 1, { "NOLOGGING" } } },
        { .id = LOPT_DEBUG_ON,          .tuple = { 1, { "debug" } } },
        { .id = LOPT_CHARSET,           .tuple = { 1, { "CHARSET" } } },
        { .id = LOPT_TRAILING_COLUMNS,  .tuple = { 2, { "TRAILING", "COLUMNS" } } },
        { .id = LOPT_NULL_SPACE,        .tuple = { 1, { "NULL2SPACE" } } },
        { .id = LOPT_REPLACE,           .tuple = { 1, { "REPLACE" } } },
        { .id = LOPT_SET_COLUMN,        .tuple = { 1, { "SET" } } },
        { .id = LOPT_CONV_JSONB,        .tuple = { 1, { "CONVERT_JSONB" } } },
    };

#define LD_OPT_SIZE (sizeof(opt_records) / sizeof(word_record_t))

    do {
        ret = lex_try_match_records(lex, opt_records, LD_OPT_SIZE, &matched_id);
        OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);

        switch (matched_id) {
            case LOPT_FIELDS_ENCLOSED:
                ret = lex_expected_fetch_asciichar(lex, &opt_char, OG_TRUE);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);

                load_opt->fields_enclosed = opt_char;

                ret = lex_try_fetch(lex, "OPTIONALLY", &load_opt->enclosed_optionally);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
                break;

            case LOPT_FIELDS_TERMINATED:
                key_word_info = "Column terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);

                MEMS_RETURN_IFERR(strncpy_s(load_opt->fields_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case LOPT_LINES_TERMINATED:
                key_word_info = "Line terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
                MEMS_RETURN_IFERR(strncpy_s(load_opt->lines_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case LOPT_DECRYPT:
                key_word_info = "Decrypt pwd string";
                OG_RETURN_IFERR(ogsql_get_crypt_pwd(lex, load_opt->crypt_info.crypt_pwd, OG_PASSWD_MAX_LEN + 1,
                    key_word_info));
                load_opt->crypt_info.crypt_flag = OG_TRUE;
                break;

            case LOPT_IGNORE:
                OG_RETURN_IFERR(ogsql_parse_loading_options_ignore(lex, load_opt, &matched_id));
                break;

            case LOPT_THREADS:
                ret = lex_expected_fetch_uint32(lex, &load_opt->threads);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
                break;

            case LOPT_ERRORS:
                ret = lex_expected_fetch_uint32(lex, &load_opt->allowed_batch_errs);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
                break;

            case LOPT_NOLOGGING:
                ogsql_printf("nologging load need to manual check database not in HA mode and parameter _RCY_CHECK_PCN is false.\n");
                load_opt->nologging = OG_TRUE;
                break;

            case LOPT_DEBUG_ON:
                load_opt->debug_on = OG_TRUE;
                break;

            case LOPT_CHARSET:
                OG_RETURN_IFERR(lex_try_fetch(lex, "=", &equal_flag));
                ret = lex_expected_fetch_1of2(lex, "UTF8", "GBK", &matched_id);
                OG_RETVALUE_IFTRUE(ret != OG_SUCCESS, OGCONN_ERROR);
                load_opt->charset_id = (matched_id == 0) ? CHARSET_UTF8 : CHARSET_GBK;
                break;

            case LOPT_TRAILING_COLUMNS:
                OG_RETURN_IFERR(ogsql_parse_trail_columns(lex, loader, load_opt));
                break;

            case LOPT_NULL_SPACE:
                load_opt->null2space = OG_TRUE;
                break;

            case LOPT_REPLACE:
                load_opt->replace = OG_TRUE;
                break;

            case LOPT_SET_COLUMN:
                lex_trim(lex->curr_text);
                MEMS_RETURN_IFERR(strncpy_s(load_opt->set_columns, MAX_LOAD_SQL_SIZE, lex->curr_text->str,
                                            lex->curr_text->len));
    
                (void)lex_skip(lex, lex->curr_text->len);

                if (strlen(load_opt->set_columns) == 0) {
                    OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "set content is empty!");
                    return OGCONN_ERROR;
                }

                load_opt->set_flag = OG_TRUE;
                break;

            case LOPT_CONV_JSONB:
                load_opt->convert_jsonb = OG_TRUE;
                break;

            default:
                return OGCONN_SUCCESS;
        }
    } while (OG_TRUE);
}

static status_t ogsql_verify_loading_options(load_option_t *load_opts)
{
    if (strcmp(load_opts->fields_terminated, load_opts->lines_terminated) == 0) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "fields terminated string is the same to line terminated!");
        return OG_ERROR;
    }

    if (strlen(load_opts->lines_terminated) > 1 &&
        CM_STR_BEGIN_WITH(load_opts->fields_terminated, load_opts->lines_terminated)) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "fields terminated and line terminated are inclusive relationships!");
        return OG_ERROR;
    }

    if (strlen(load_opts->fields_terminated) > 1 &&
        CM_STR_BEGIN_WITH(load_opts->lines_terminated, load_opts->fields_terminated)) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "line terminated and fields terminated are inclusive relationships!");
        return OG_ERROR;
    }

    if (load_opts->replace && load_opts->ignore) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "replace and ignore can not appear at the same time!");
        return OG_ERROR;
    }

    if ((load_opts->allowed_batch_errs > 0 || load_opts->ignore) && load_opts->nologging) {
        ogsql_printf("WARNING: ERRORS or IGNORE can not be used with NOLOGGING, reset ERRORS to 0\n");
        load_opts->allowed_batch_errs = 0;
        load_opts->ignore = OG_FALSE;
    }

    return OG_SUCCESS;
}

static int ogsql_parse_loader(lex_t *lex, loader_t *loader)
{
    if (ogsql_parse_loading_file(lex, loader) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    if (ogsql_parse_loading_object(lex, loader) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    if (ogsql_parse_loading_options(lex, loader, &g_load_opts) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    OG_RETURN_IFERR(ogsql_verify_loading_options(&g_load_opts));

    return (lex_expected_end(lex) == OG_SUCCESS) ? OGCONN_SUCCESS : OGCONN_ERROR;
}

static inline int ogsql_reset_loader_charset(void)
{
    uint32 attr_len;
    uint32 buffer_len = 10;
    if (ogconn_get_conn_attr(CONN, OGCONN_ATTR_CHARSET_TYPE,
                          (void *)&g_load_opts.charset_id, buffer_len, &attr_len) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OGCONN_ERROR;
    }

    return OGCONN_SUCCESS;
}

/* init some options before loading */
static inline int ogsql_reset_loader_opts(void)
{
    errno_t errcode;
    if (ogsql_reset_loader_charset() != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    g_load_opts.enclosed_optionally = OG_FALSE;
    g_load_opts.fields_enclosed = OGSQL_DEFAULT_ENCLOSED_CHAR;
    /* default fields terminal is less than size of 'g_load_opts.fields_terminated' */
    errcode = strncpy_s(g_load_opts.fields_terminated, sizeof(g_load_opts.fields_terminated),
                        OGSQL_DEFAULT_FIELD_SEPARATOR_STR, strlen(OGSQL_DEFAULT_FIELD_SEPARATOR_STR));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OGCONN_ERROR;
    }
    g_load_opts.fields_escape = '\\';
    errcode = strncpy_s(g_load_opts.lines_terminated, sizeof(g_load_opts.lines_terminated),
                        OGSQL_DEFAULT_LINE_SEPARATOR_STR, strlen(OGSQL_DEFAULT_LINE_SEPARATOR_STR));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OGCONN_ERROR;
    }
    g_load_opts.ignore_lines = 0;
    g_load_opts.max_databuf_size = SIZE_M(1);
    g_load_opts.max_filebuf_size = FILE_BUFFER_SIZE;
    g_load_opts.auto_commit_rows = OGSQL_AUTO_COMMIT;
    g_load_opts.charset_id = OG_DEFAULT_LOCAL_CHARSET;
    g_load_opts.threads = LOADER_DEFAULT_THREADS;
    g_load_opts.allowed_batch_errs = 0;
    g_load_opts.nologging = 0;
    g_load_opts.debug_on = OG_FALSE;
    cm_reset_list(&g_load_opts.obj_list);
    cm_create_list(&g_load_opts.obj_list, OGSQL_MAX_OBJECT_LEN);
    MEMS_RETURN_IFERR(memset_s(g_load_opts.trailing_columns, MAX_LOAD_SQL_SIZE, 0, MAX_LOAD_SQL_SIZE));
    g_load_opts.null2space = OG_FALSE;
    g_load_opts.replace = OG_FALSE;
    g_load_opts.convert_jsonb = OG_FALSE;
    g_load_opts.ignore = OG_FALSE;
    MEMS_RETURN_IFERR(memset_s(g_load_opts.set_columns, MAX_LOAD_SQL_SIZE, 0, MAX_LOAD_SQL_SIZE));
    g_load_opts.set_flag = OG_FALSE;
    
    if (ogsql_reset_case_insensitive(&g_load_opts.is_case_insensitive) != OGCONN_SUCCESS) {
        return OGCONN_ERROR;
    }

    ogsql_reset_crypt_info(&g_load_opts.crypt_info);
    return OGCONN_SUCCESS;
}

static status_t ogsql_parse_load_help(lex_t *lex, bool8 *is_match)
{
    uint32 matched_id;

    *is_match = OG_FALSE;

    // devil number '6' here means 6 help command behind
    if (lex_try_fetch_1ofn(lex, &matched_id, 6, "-h", "-help", "help", "-u", "-usage", "usage") != OG_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }
    if (matched_id != OG_INVALID_ID32) {
        ogsql_show_loader_usage();
        *is_match = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t ogsql_parse_show_option(lex_t *lex, bool8 *is_match)
{
    uint32 matched_id;

    *is_match = OG_FALSE;
    
    if (lex_try_fetch_1of3(lex, "-o", "-option", "option", &matched_id) != OG_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }
    if (matched_id != OG_INVALID_ID32) {
        ogsql_show_loader_opts();
        *is_match = OG_TRUE;
    }
    return OG_SUCCESS;
}

status_t ogsql_load(text_t *cmd_text)
{
    bool8 is_match;
    loader_t loader;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    status_t ret;

    if (!IS_CONN) {
        OGSQL_PRINTF(ZSERR_LOAD, "connection is not established");
        return OG_ERROR;
    }

    cm_reset_error();

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);

    MEMS_RETURN_IFERR(memset_s(&loader, sizeof(loader_t), 0, sizeof(loader_t)));

    if (lex_expected_fetch_word(&lex, "LOAD") != OG_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    ret = ogsql_parse_load_help(&lex, &is_match);
    if (ret != OG_SUCCESS || is_match) {
        return ret;
    }

    ret = ogsql_parse_show_option(&lex, &is_match);
    if (ret != OG_SUCCESS || is_match) {
        return ret;
    }

    OG_RETURN_IFERR(ogsql_reset_loader_opts());

    if (ogsql_parse_loader(&lex, &loader) != OGCONN_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    if (ogsql_set_session_interactive_mode(OG_FALSE) != OGCONN_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    if (ogsql_load_file(&loader) != OG_SUCCESS) {
        load_post_nologging(&loader);
        ret = OG_ERROR;
    }
    
    OG_RETURN_IFERR(ogsql_set_session_interactive_mode(OG_TRUE));
    return ret;
}
