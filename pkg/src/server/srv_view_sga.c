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
 * srv_view_sga.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_sga.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "knl_log.h"
#include "knl_context.h"
#include "srv_view_sga.h"
#include "srv_instance.h"
#include "srv_param.h"
#include "dml_executor.h"
#include "knl_spm.h"
#include "dtc_database.h"
#include "expl_executor.h"

#define SGA_VALUE_BUFFER_NAME 40
#define SGA_VALUE_BUFFER_LEN 40
#define SGA_SQL_ID_LEN (uint32)10
#define SGA_PDOWN_BUFFER_LEN (uint32)1000
#define SGA_MAX_SQL_ID_NUM (uint32)90

typedef struct st_vw_ogsql_funcarea_assist {
    sql_context_t vw_ctx;
    uint32 pages;
    uint32 alloc_pos;
    char pdown_sql_buffer[SGA_PDOWN_BUFFER_LEN + 1];
    text_t pdown_sql_id;
    text_t sql_text;
    uint32 sql_hash;
    uint32 ref_count;
} vw_ogsql_funcarea_assist_t;

knl_column_t g_sga_columns[] = {
    { 0, "NAME", 0, 0, OG_TYPE_CHAR, SGA_VALUE_BUFFER_NAME, 0, 0, OG_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, OG_TYPE_CHAR, SGA_VALUE_BUFFER_LEN, 0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_system_columns[] = {
    { 0, "ID",           0, 0, OG_TYPE_INTEGER, sizeof(uint32),    0, 0, OG_FALSE, 0, { 0 } },
    { 1, "NAME",         0, 0, OG_TYPE_VARCHAR, OG_MAX_NAME_LEN,   0, 0, OG_FALSE, 0, { 0 } },
    { 2, "VALUE",        0, 0, OG_TYPE_VARCHAR, OG_MAX_NUMBER_LEN, 0, 0, OG_TRUE,  0, { 0 } },
    { 3, "COMMENTS",     0, 0, OG_TYPE_VARCHAR, OG_COMMENT_SIZE,   0, 0, OG_FALSE, 0, { 0 } },
    { 4, "ACCUMULATIVE", 0, 0, OG_TYPE_BOOLEAN, sizeof(bool32),    0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_temp_pool_columns[] = {
    { 0,  "ID",              0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 1,  "TOTAL_VIRTUAL",   0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 2,  "FREE_VIRTUAL",    0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 3,  "PAGE_SIZE",       0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 4,  "TOTAL_PAGES",     0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 5,  "FREE_PAGES",      0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 6,  "PAGE_HWM",        0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 7,  "FREE_LIST",       0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 8,  "CLOSED_LIST",     0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 9,  "DISK_EXTENTS",    0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 10, "SWAP_COUNT",      0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 11, "FREE_EXTENTS",    0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 12, "MAX_SWAP_COUNT",  0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_vm_func_stack_columns[] = {
    { 0, "FUNC_STACK", 0, 0, OG_TYPE_VARCHAR, OG_VM_FUNC_STACK_SIZE, 0, 0, OG_TRUE, 0, { 0 } },
    { 1, "REF_COUNT", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_TRUE, 0, { 0 } },
};

static knl_column_t g_sqlarea_columns[] = {
    { 0, "SQL_TEXT", 0, 0, OG_TYPE_VARCHAR, OG_MAX_COLUMN_SIZE, 0, 0, OG_TRUE, 0, { 0 } },
    { 1, "SQL_ID", 0, 0, OG_TYPE_VARCHAR, OG_MAX_UINT32_STRLEN, 0, 0, OG_FALSE, 0, { 0 } },
    { 2, "EXECUTIONS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 3, "DISK_READS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 4, "BUFFER_GETS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 5, "CR_GETS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 6, "SORTS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 7, "PARSE_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 8, "PARSE_CALLS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 9, "PROCESSED_ROWS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 10, "PARSING_USER_ID", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 11, "PARSING_USER_NAME", 0, 0, OG_TYPE_VARCHAR, OG_MAX_NAME_LEN, 0, 0, OG_FALSE, 0, { 0 } },
    { 12, "MODULE", 0, 0, OG_TYPE_VARCHAR, OG_MAX_NAME_LEN, 0, 0, OG_FALSE, 0, { 0 } },
    { 13, "IO_WAIT_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 14, "CON_WAIT_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 15, "CPU_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 16, "ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 17, "LAST_LOAD_TIME", 0, 0, OG_TYPE_DATE, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 18, "PROGRAM_ID", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 19, "PROGRAM_LINE#", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 20, "LAST_ACTIVE_TIME", 0, 0, OG_TYPE_DATE, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 21, "REF_COUNT", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 22, "IS_FREE", 0, 0, OG_TYPE_BOOLEAN, sizeof(bool32), 0, 0, OG_FALSE, 0, { 0 } },
    { 23, "CLEANED", 0, 0, OG_TYPE_BOOLEAN, sizeof(bool32), 0, 0, OG_FALSE, 0, { 0 } },
    { 24, "PAGES", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 25, "VALID", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 26, "SHARABLE_MEM", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 27, "VM_OPEN_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 28, "VM_CLOSE_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 29, "VM_SWAPIN_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 30, "VM_FREE_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 31, "NETWORK_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 32, "PDOWN_SQL_ID", 0, 0, OG_TYPE_VARCHAR, SGA_PDOWN_BUFFER_LEN, 0, 0, OG_TRUE, 0, { 0 } },
    { 33, "VM_ALLOC_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 34, "VM_MAX_OPEN_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 35, "VM_SWAPOUT_PAGES", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 36, "DCS_BUFFER_GETS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 37, "DCS_CR_GETS", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 38, "DCS_NET_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_sql_execution_plan_columns[] = {
    { 0, "SQL_ID", 0, 0, OG_TYPE_VARCHAR, OG_MAX_UINT32_STRLEN, 0, 0, OG_FALSE, 0, { 0 } },
    { 1, "PLAN_VERSION", 0, 0, OG_TYPE_VARCHAR, OG_MAX_VPEEK_VER_SIZE * 2, 0, 0, OG_FALSE, 0, { 0 } },
    { 2, "EXECUTION_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 3, "DISK_READ_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 4, "BUFFER_GET_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 5, "CR_GET_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 6, "SORT_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 7, "PARSE_ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 8, "IO_WAIT_ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 9, "CON_WAIT_ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 10, "CPU_ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 11, "TOTAL_ELAPSED_TIME", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 12, "LAST_LOAD_TIMESTAMP", 0, 0, OG_TYPE_DATE, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 13, "LAST_ACTIVE_TIMESTAMP", 0, 0, OG_TYPE_DATE, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 14, "REFERENCE_COUNT", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 15, "MEMORY_PAGES", 0, 0, OG_TYPE_INTEGER, sizeof(uint32), 0, 0, OG_FALSE, 0, { 0 } },
    { 16, "SHARED_MEMORY_SIZE", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 17, "VM_OPEN_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 18, "VM_CLOSE_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 19, "VM_SWAPIN_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 20, "VM_FREE_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 21, "PLAN_TEXT", 0, 0, OG_TYPE_VARCHAR, OG_MAX_COLUMN_SIZE, 0, 0, OG_TRUE, 0, { 0 } },
    { 22, "VM_MAX_OPEN_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 23, "VM_SWAPOUT_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 24, "VM_SWAPOUT_PAGE_COUNT", 0, 0, OG_TYPE_BIGINT, sizeof(uint64), 0, 0, OG_FALSE, 0, { 0 } },
    { 25, "SIGNATURE", 0, 0, OG_TYPE_VARCHAR, OG_MD5_SIZE, 0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_sga_stat_columns[] = {
    { 0, "AREA", 0, 0, OG_TYPE_VARCHAR, 32, 0, 0, OG_FALSE, 0, { 0 } },
    { 1, "POOL", 0, 0, OG_TYPE_VARCHAR, 32, 0, 0, OG_FALSE, 0, { 0 } },
    { 2, "NAME", 0, 0, OG_TYPE_VARCHAR, 32, 0, 0, OG_FALSE, 0, { 0 } },
    { 3, "VALUE", 0, 0, OG_TYPE_VARCHAR, 32, 0, 0, OG_FALSE, 0, { 0 } },
};

static knl_column_t g_sqlpool_columns[] = {
    { 0,  "SQL_ID",           0, 0, OG_TYPE_VARCHAR, OG_MAX_UINT32_STRLEN, 0, 0, OG_FALSE, 0, { 0 } },                                                                           // sql_context->ctrl.hash_value
    { 1,  "SQL_TYPE",         0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } },  // sql_context->type
    { 2,  "UID",              0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } },       // sql_context->ctrl.uid
    { 3,  "REF_COUNT",        0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->ctrl.ref_count
    { 4,  "VALID",            0, 0, OG_TYPE_BOOLEAN, sizeof(bool32),       0, 0, OG_FALSE, 0, { 0 } },
    { 5,  "CLEANED",          0, 0, OG_TYPE_BOOLEAN, sizeof(bool32),       0, 0, OG_FALSE, 0, { 0 } },
    { 6,  "IS_FREE",          0, 0, OG_TYPE_BOOLEAN, sizeof(bool32),       0, 0, OG_FALSE, 0, { 0 } },
    { 7,  "MCTX_PAGE_COUNT",  0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.count
    { 8,  "MCTX_PAGE_FIRST",  0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.first
    { 9,  "MCTX_PAGE_LAST",   0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.last
    { 10, "CURRENT_PAGE_ID",  0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->curr_page_id
    { 11, "MCTX_PAGES",       0, 0, OG_TYPE_VARCHAR, OG_MAX_COLUMN_SIZE,   0, 0, OG_TRUE,  0, { 0 } }, // sql_context->ctrl.memory.pool.map
    { 12, "LARGE_PAGE",       0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_TRUE,  0, { 0 } }, // sql_context->large_page_id
    { 13, "FIRST_OPTMZ_VARS", 0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } },                                                                            // sql_context->fexec_vars_cnt
    { 14, "FIRST_OPTMZ_BUFF", 0, 0, OG_TYPE_INTEGER, sizeof(uint32),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->fexec_vars_bytes
    { 15, "LAST_LOAD_TIME",   0, 0, OG_TYPE_DATE,    sizeof(date_t),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->stat.last_load_time
    { 16, "LAST_ACTIVE_TIME", 0, 0, OG_TYPE_DATE,    sizeof(date_t),       0, 0, OG_FALSE, 0, { 0 } }, // sql_context->stat.last_active_time
};

#define SGA_COLS (sizeof(g_sga_columns) / sizeof(knl_column_t))
#define SYSTEM_COLS (sizeof(g_system_columns) / sizeof(knl_column_t))
#define TEMP_POOL_COLS (sizeof(g_temp_pool_columns) / sizeof(knl_column_t))
#define SQLAREA_COLS (sizeof(g_sqlarea_columns) / sizeof(knl_column_t))
#define SGA_STAT_COLS (sizeof(g_sga_stat_columns) / sizeof(knl_column_t))
#define SQLPOOL_COLS (sizeof(g_sqlpool_columns) / sizeof(knl_column_t))
#define SQL_PLAN_COLS (sizeof(g_sql_execution_plan_columns) / sizeof(knl_column_t))

typedef struct st_sga_row {
    char *name;
    char value[SGA_VALUE_BUFFER_LEN];
} sga_row_t;

static sga_row_t g_sga_rows[] = {
    { "data buffer",       { 0 } },
    { "cr pool",           { 0 } },
    { "log buffer",        { 0 } },
    { "shared pool",       { 0 } },
    { "transaction pool",  { 0 } },
    { "dbwr buffer",       { 0 } },
    { "lgwr buffer",       { 0 } },
    { "lgwr cipher buffer", { 0 } },
    { "lgwr async buffer", { 0 } },
    { "lgwr head buffer",  { 0 } },
    { "large pool",        { 0 } },
    { "temporary buffer",  { 0 } },
    { "index buffer",      { 0 } },
    { "variant memory area",       { 0 } },
    { "large variant memory area", { 0 } },
    { "private memory area",       { 0 } },
    { "buffer iocbs", { 0 } },
    { "GMA total", { 0 } },
};

static bool32 g_sga_ready = OG_FALSE;

static spinlock_t g_sga_lock = 0;

#define SGA_ROW_COUNT (sizeof(g_sga_rows) / sizeof(sga_row_t))
#define VM_SYSTEM_ROWS (TOTAL_OS_RUN_INFO_TYPES)
#define VM_FUNC_STACK_COLS (sizeof(g_vm_func_stack_columns) / sizeof(knl_column_t))
#define VM_SGA_WRITE_VAL(idx, val)                                                                                 \
    do {                                                                                                           \
        int iret_snprintf = 0;                                                                                     \
        iret_snprintf = snprintf_s(g_sga_rows[idx].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%.2fM", \
            ((double)(val)) / SIZE_M(1));                                                                          \
        if (iret_snprintf == -1) {                                                                                 \
            cm_spin_unlock(&g_sga_lock);                                                                           \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));                                                      \
            return OG_ERROR;                                                                                       \
        }                                                                                                          \
        (idx)++;                                                                                                   \
    } while (0)

static status_t vw_sga_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id = cursor->rowid.vmid;
    row_assist_t ra;
    knl_attr_t *attr = &((knl_session_t *)session)->kernel->attr;
    uint32 idx = 0;

    if (id >= SGA_ROW_COUNT) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    if (!g_sga_ready) {
        cm_spin_lock(&g_sga_lock, NULL);

        if (!g_sga_ready) {
            g_sga_ready = OG_TRUE;
            VM_SGA_WRITE_VAL(idx, attr->data_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->cr_pool_part_size);
            VM_SGA_WRITE_VAL(idx, attr->log_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->shared_area_size);
            VM_SGA_WRITE_VAL(idx, attr->tran_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->dbwr_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_cipher_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_async_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_head_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->large_pool_size);
            VM_SGA_WRITE_VAL(idx, attr->temp_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->index_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->vma_size);
            VM_SGA_WRITE_VAL(idx, attr->large_vma_size);
            VM_SGA_WRITE_VAL(idx, attr->pma_size);
            VM_SGA_WRITE_VAL(idx, attr->buf_iocbs_size);
            VM_SGA_WRITE_VAL(idx, g_instance->sga.size);
            CM_ASSERT(idx == SGA_ROW_COUNT);
        }
        cm_spin_unlock(&g_sga_lock);
    }

    row_init(&ra, (char *)cursor->row, OG_MAX_ROW_SIZE, SGA_COLS);
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].name));
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].value));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return OG_SUCCESS;
}

#ifndef WIN32
#include <sys/param.h>

/* ----------
 * Macros of the os statistic file system path.
 * ----------
 */
#define JIFFIES_GET_CENTI_SEC(x) ((x) * (100 / HZ))
#define PROC_PATH_MAX 4096
#define VM_STAT_FILE_READ_BUF 4096
#define SYS_FILE_SYS_PATH "/sys/devices/system"
#define SYS_CPU_PATH "/sys/devices/system/cpu/cpu%u"
#define THR_SIBLING_FILE "/sys/devices/system/cpu/cpu0/topology/thread_siblings"
#define CORE_SIBLING_FILE "/sys/devices/system/cpu/cpu0/topology/core_siblings"
/*
 * this is used to represent the numbers of cpu time we should read from file.BUSY_TIME will be
 * calculate by USER_TIME plus SYS_TIME,so it wouldn't be counted.
 */
#define NUM_OF_CPU_TIME_READS (AVG_IDLE_TIME - IDLE_TIME)
/*
 * we calculate cpu numbers from sysfs, so we should make sure we can access this file system.
 */
static bool32 check_sys_file_system(void)
{
    /* Read through sysfs. */
    if (access(SYS_FILE_SYS_PATH, F_OK)) {
        return OG_FALSE;
    }

    if (access(THR_SIBLING_FILE, F_OK)) {
        return OG_FALSE;
    }

    if (access(CORE_SIBLING_FILE, F_OK)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

/*
 * check whether the SYS_CPU_PATH is accessable.one accessable path represented one logical cpu.
 */
static bool32 check_logical_cpu(uint32 cpuNum)
{
    char pathbuf[PROC_PATH_MAX] = "";
    int iret_snprintf;

    iret_snprintf = snprintf_s(pathbuf, PROC_PATH_MAX, PROC_PATH_MAX - 1, SYS_CPU_PATH, cpuNum);
    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
    }
    return access(pathbuf, F_OK) == 0;
}
/* count the set bit in a mapping file */
#define pg_isxdigit(c)                                                               \
    (((c) >= (int)'0' && (c) <= (int)'9') || ((c) >= (int)'a' && (c) <= (int)'f') || \
        ((c) >= (int)'A' && (c) <= (int)'F'))
static uint32 parse_sibling_file(const char *path)
{
    int c;
    uint32 result = 0;
    char s[2];
    FILE *fp = NULL;
    union {
        uint32 a : 4;
        struct {
            uint32 a1 : 1;
            uint32 a2 : 1;
            uint32 a3 : 1;
            uint32 a4 : 1;
        } b;
    } d;
    fp = fopen(path, "r");
    if (fp != NULL) {
        c = fgetc(fp);
        while (c != EOF) {
            if (pg_isxdigit(c)) {
                s[0] = c;
                s[1] = '\0';
                d.a = strtoul(s, NULL, 16);
                result += d.b.a1;
                result += d.b.a2;
                result += d.b.a3;
                result += d.b.a4;
            }
            c = fgetc(fp);
        }
        (void)fclose(fp);
    }

    return result;
}

/*
 * This function is to get the number of logical cpus, cores and physical cpus of the system.
 * We get these infomation by analysing sysfs file system. If we failed to get the three fields,
 * we just ignore them when we report. And if we got this field, we will not analyse the files
 * when we call this function next time.
 *
 * Note: This function must be called before getCpuTimes because we need logical cpu number
 * to calculate the avg cpu consumption.
 */
static void get_cpu_nums(void)
{
    uint32 cpuNum = 0;
    uint32 threadPerCore = 0;
    uint32 threadPerSocket = 0;

    /* if we have already got the cpu numbers. it's not necessary to read the files again. */
    if (g_instance->os_rinfo[NUM_CPUS].desc->got && g_instance->os_rinfo[NUM_CPU_CORES].desc->got &&
        g_instance->os_rinfo[NUM_CPU_SOCKETS].desc->got) {
        return;
    }

    /* if the sysfs file system is not accessable. we can't get the cpu numbers. */
    if (check_sys_file_system()) {
        /* check the SYS_CPU_PATH, one accessable path represented one logical cpu. */
        while (check_logical_cpu(cpuNum)) {
            cpuNum++;
        }

        if (cpuNum > 0) {
            /* cpu numbers */
            g_instance->os_rinfo[NUM_CPUS].int32_val = cpuNum;
            g_instance->os_rinfo[NUM_CPUS].desc->got = OG_TRUE;

            /*
            parse the mapping files ThreadSiblingFile and CoreSiblingFile.
            if we failed open the file or read wrong data, we just ignore this field.
            */
            threadPerCore = parse_sibling_file(THR_SIBLING_FILE);
            if (threadPerCore > 0) {
                /* core numbers */
                g_instance->os_rinfo[NUM_CPU_CORES].int32_val = cpuNum / threadPerCore;
                g_instance->os_rinfo[NUM_CPU_CORES].desc->got = OG_TRUE;
            }

            threadPerSocket = parse_sibling_file(CORE_SIBLING_FILE);
            if (threadPerSocket > 0) {
                /* socket numbers */
                g_instance->os_rinfo[NUM_CPU_SOCKETS].int32_val = cpuNum / threadPerSocket;
                g_instance->os_rinfo[NUM_CPU_SOCKETS].desc->got = OG_TRUE;
            }
        }
    }
}

static void get_os_run_load(void)
{
    char *loadAvgPath = "/proc/loadavg";
    FILE *fd = NULL;
    size_t len = 0;
    g_instance->os_rinfo[RUNLOAD].desc->got = OG_FALSE;

    /* reset the member "got" of osStatDescArray to false */
    /* open the /proc/loadavg file. */
    fd = fopen(loadAvgPath, "r");
    if (fd != NULL) {
        char line[OG_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = OG_PROC_LOAD_BUF_SIZE;
        if (fgets(line, len, fd) != NULL) {
            g_instance->os_rinfo[RUNLOAD].float8_val = strtod(line, NULL);
            g_instance->os_rinfo[RUNLOAD].desc->got = OG_TRUE;
        }
        fclose(fd);
    }
}

/*
 * This function is to get the system cpu time consumption details. We read /proc/stat
 * file for this infomation. If we failed to get the ten fields, we just ignore them when we
 * report.
 * Note: Remember to call getCpuNums before this function.
 */
static void get_cpu_times(void)
{
    char *statPath = "/proc/stat";
    FILE *fd = NULL;
    size_t len = 0;
    uint64 readTime[NUM_OF_CPU_TIME_READS];
    char *temp = NULL;
    int i;

    /* reset the member "got" of osStatDescArray to false */
    MEMS_RETVOID_IFERR(memset_s(readTime, sizeof(readTime), 0, sizeof(readTime)));

    for (i = IDLE_TIME; i <= AVG_NICE_TIME; i++) {
        g_instance->os_rinfo[i].desc->got = OG_FALSE;
    }

    /* open /proc/stat file. */
    fd = fopen(statPath, "r");
    if (fd != NULL) {
        char line[OG_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = OG_PROC_LOAD_BUF_SIZE;
        if (fgets(line, len, fd) != NULL) {
            /* get the second to sixth word of the line. */
            temp = line + sizeof("cpu");
            for (i = 0; i < NUM_OF_CPU_TIME_READS; i++) {
                readTime[i] = strtoul(temp, &temp, 10);
            }
            /* convert the jiffies time to centi-sec. for busy time, it equals user time plus sys time */
            g_instance->os_rinfo[USER_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[0]);
            g_instance->os_rinfo[NICE_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[1]);
            g_instance->os_rinfo[SYS_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[2]);
            g_instance->os_rinfo[IDLE_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[3]);
            g_instance->os_rinfo[IOWAIT_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[4]);
            g_instance->os_rinfo[BUSY_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[5]);

            /* as we have already got the cpu times, we set the "got" to true. */
            for (i = IDLE_TIME; i <= NICE_TIME; i++) {
                g_instance->os_rinfo[i].desc->got = OG_TRUE;
            }

            /* if the cpu numbers have been got, we can calculate the avg cpu times and set the "got" to true. */
            if (g_instance->os_rinfo[NUM_CPUS].desc->got) {
                uint32 cpu_nums = g_instance->os_rinfo[NUM_CPUS].int32_val;
                g_instance->os_rinfo[AVG_USER_TIME].int64_val = g_instance->os_rinfo[USER_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_NICE_TIME].int64_val = g_instance->os_rinfo[NICE_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_SYS_TIME].int64_val = g_instance->os_rinfo[SYS_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_IDLE_TIME].int64_val = g_instance->os_rinfo[IDLE_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_IOWAIT_TIME].int64_val =
                    g_instance->os_rinfo[IOWAIT_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_BUSY_TIME].int64_val = g_instance->os_rinfo[BUSY_TIME].int64_val / cpu_nums;

                for (i = AVG_IDLE_TIME; i <= AVG_NICE_TIME; i++) {
                    g_instance->os_rinfo[i].desc->got = OG_TRUE;
                }
            }
        }
        fclose(fd);
    }
}

/*
 * This function is to get the system virtual memory paging infomation (actually it will
 * get how many bytes paged in/out due to virtual memory paging). We read /proc/vmstat
 * file for this infomation. If we failed to get the two fields, we just ignore them when
 * we report.
 */
static void get_vm_stat(void)
{
    char *vmStatPath = "/proc/vmstat";
    int fd = -1;
    int ret;
    int len;
    char buffer[VM_STAT_FILE_READ_BUF + 1];
    char *temp = NULL;
    uint64 inPages = 0;
    uint64 outPages = 0;
    uint64 pageSize = sysconf(_SC_PAGE_SIZE);

    /* reset the member "got" of osStatDescArray to false */
    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = OG_FALSE;
    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = OG_FALSE;

    /* open /proc/vmstat file. */
    fd = open(vmStatPath, O_RDONLY, 0);
    if (fd >= 0) {
        /* read the file to local buffer. */
        len = read(fd, buffer, VM_STAT_FILE_READ_BUF);
        if (len > 0) {
            buffer[len] = '\0';
            /* find the pgpgin and pgpgout field. if failed, we just ignore this field */
            temp = strstr(buffer, "pswpin");
            if (temp != NULL) {
                temp += sizeof("pswpin");
                inPages = strtoul(temp, NULL, 10);
                if (inPages < ULONG_MAX / pageSize) {
                    g_instance->os_rinfo[VM_PAGE_IN_BYTES].int64_val = inPages * pageSize;
                    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = OG_TRUE;
                }
            }

            temp = strstr(buffer, "pswpout");
            if (temp != NULL) {
                temp += sizeof("pswpout");
                outPages = strtoul(temp, NULL, 10);
                if (outPages < ULONG_MAX / pageSize) {
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].int64_val = outPages * pageSize;
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = OG_TRUE;
                }
            }
        }
        ret = close(fd);
        if (ret != 0) {
            OG_LOG_RUN_ERR("failed to close file with handle %d, error code %d", fd, errno);
        }
    }
}

/*
 * This function is to get the total physical memory size of the system. We read /proc/meminfo
 * file for this infomation. If we failed to get this field, we just ignore it when we report. And if
 * if we got this field, we will not read the file when we call this function next time.
 */
static void get_total_mem(void)
{
    char *memInfoPath = "/proc/meminfo";
    FILE *fd = NULL;
    char line[OG_PROC_LOAD_BUF_SIZE + 1];
    char *temp = NULL;
    uint64 ret = 0;
    size_t len = OG_PROC_LOAD_BUF_SIZE;

    /* if we have already got the physical memory size. it's not necessary to read the files again. */
    if (g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].desc->got) {
        return;
    }

    /* open /proc/meminfo file. */
    fd = fopen(memInfoPath, "r");
    if (fd != NULL) {
        /* read the file to local buffer. */
        if (fgets(line, len, fd) != NULL) {
            temp = line + sizeof("MemTotal:");
            ret = strtoul(temp, NULL, 10);
            if (ret < ULONG_MAX / 1024) {
                g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].int64_val = ret * 1024;
                g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].desc->got = OG_TRUE;
            }
        }
        fclose(fd);
    }
}

#endif

static status_t vw_system_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    id = cursor->rowid.vmid;
    if (id >= VM_SYSTEM_ROWS) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }
    if (id == 0) {
#ifndef WIN32
        get_cpu_nums();
        get_cpu_times();
        get_vm_stat();
        get_total_mem();
        get_os_run_load();
#else
        // WE NEED TO FETCH IN WINDOWS
#endif
    }
    row_init(&ra, (char *)cursor->row, OG_MAX_ROW_SIZE, SYSTEM_COLS);
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    OG_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->name));

    if (g_instance->os_rinfo[id].desc->got == OG_TRUE) {
        char value[OG_MAX_NUMBER_LEN];

        switch (id) {
            case NUM_CPUS:
            case NUM_CPU_CORES:
            case NUM_CPU_SOCKETS:

                PRTS_RETURN_IFERR(sprintf_s(value, OG_MAX_NUMBER_LEN, "%u", g_instance->os_rinfo[id].int32_val));
                OG_RETURN_IFERR(row_put_str(&ra, value));
                break;

            case RUNLOAD:
                PRTS_RETURN_IFERR(sprintf_s(value, OG_MAX_NUMBER_LEN, "%lf", g_instance->os_rinfo[id].float8_val));
                OG_RETURN_IFERR(row_put_str(&ra, value));
                break;
            default:
                PRTS_RETURN_IFERR(sprintf_s(value, OG_MAX_NUMBER_LEN, "%llu", g_instance->os_rinfo[id].int64_val));
                OG_RETURN_IFERR(row_put_str(&ra, value));
                break;
        }
    } else {
        OG_RETURN_IFERR(row_put_null(&ra));
    }

    OG_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->comments));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)g_instance->os_rinfo[id].desc->comulative));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return OG_SUCCESS;
}

static status_t vw_temp_pool_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint64 id;
    uint32 count;
    row_assist_t ra;
    vm_pool_t *pool = NULL;
    knl_session_t *session = (knl_session_t *)se;

    id = cursor->rowid.vmid;

    if (id >= session->kernel->temp_ctx_count) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    pool = &session->kernel->temp_pool[id];

    row_init(&ra, (char *)cursor->row, OG_MAX_ROW_SIZE, TEMP_POOL_COLS);
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)(pool->map_count * VM_CTRLS_PER_PAGE)));

    count = pool->free_ctrls.count;
    count += pool->map_count * VM_CTRLS_PER_PAGE - pool->ctrl_hwm;
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    OG_RETURN_IFERR(row_put_int32(&ra, OG_VMEM_PAGE_SIZE));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_count));

    count = pool->free_pages.count + pool->page_count - pool->page_hwm;
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_hwm));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->free_pages.count));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)vm_close_page_cnt(pool)));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->get_swap_extents));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->swap_count));
    OG_RETURN_IFERR(
        row_put_int32(&ra, (int32)((SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count)));
    OG_RETURN_IFERR(row_put_int32(&ra, (int32)pool->max_swap_count));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return OG_SUCCESS;
}

static status_t vw_vm_func_stack_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    vm_func_stack_t *func_stack = NULL;
    vm_pool_t *pool = NULL;

    if (g_vm_max_stack_count == 0) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    for (; cursor->rowid.vmid < g_vm_max_stack_count; cursor->rowid.vmid++) {
        pool = &((knl_session_t *)session)->kernel->temp_pool[cursor->rowid.vm_slot];
        if (pool->func_stacks == NULL) {
            continue;
        }
        cm_spin_lock(&pool->lock, NULL);
        func_stack = pool->func_stacks[cursor->rowid.vmid];
        if (func_stack == NULL || (func_stack->stack[0] == '\0' && func_stack->ref_count == 0)) {
            cm_spin_unlock(&pool->lock);
            continue;
        }

        row_init(&ra, (char *)cursor->row, OG_MAX_ROW_SIZE, VM_FUNC_STACK_COLS);
        if (row_put_str(&ra, func_stack->stack) != OG_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return OG_ERROR;
        }
        if (row_put_int32(&ra, (int32)func_stack->ref_count) != OG_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return OG_ERROR;
        }

        cm_spin_unlock(&pool->lock);

        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.vmid++;
        cm_spin_unlock(&pool->lock);
        return OG_SUCCESS;
    }

    cursor->eof = OG_TRUE;
    return OG_SUCCESS;
}

typedef struct st_sga_stat_row {
    char *area;
    char *pool;
    char *name;
    char value[SGA_VALUE_BUFFER_LEN];
} sga_stat_row_t;

#define SGA_STAT_NULL_COL "-"

static sga_stat_row_t g_sga_stat_rows[] = {
    // shared area statistic
    { "shared area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // sql pool statistic
    { "shared area", "sql pool", "page count",           { 0 } },
    { "shared area", "sql pool", "page size",            { 0 } },
    { "shared area", "sql pool", "optimizer page count", { 0 } },
    { "shared area", "sql pool", "free page count",      { 0 } },
    { "shared area", "sql pool", "lru count",            { 0 } },
    { "shared area", "sql pool", "plsql lru count",      { 0 } },
    { "shared area", "sql pool", "plsql page count",     { 0 } },

    // dc pool
    { "shared area", "dc pool", "page count",           { 0 } },
    { "shared area", "dc pool", "page size",            { 0 } },
    { "shared area", "dc pool", "optimizer page count", { 0 } },
    { "shared area", "dc pool", "free page count",      { 0 } },

    // lock pool
    { "shared area", "lock pool", "page count",           { 0 } },
    { "shared area", "lock pool", "page size",            { 0 } },
    { "shared area", "lock pool", "optimizer page count", { 0 } },
    { "shared area", "lock pool", "free page count",      { 0 } },

    // lob pool
    { "shared area", "lob pool", "page count",           { 0 } },
    { "shared area", "lob pool", "page size",            { 0 } },
    { "shared area", "lob pool", "optimizer page count", { 0 } },
    { "shared area", "lob pool", "free page count",      { 0 } },

    // large pool statistic
    { SGA_STAT_NULL_COL, "large pool", "page count",           { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "page size",            { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "optimizer page count", { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "free page count",      { 0 } },

    // variant memory area
    { "variant memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // large variant memory area
    { "large variant memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // private memory area
    { "private memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },
};

#define SGA_STAT_ROW_COUNT (sizeof(g_sga_stat_rows) / sizeof(sga_stat_row_t))

static status_t vw_sga_stat_prepare_area(memory_area_t *area, uint32 *id)
{
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_count));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_size));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_hwm));
    ++(*id);

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        area->free_pages.count));
    ++(*id);
    return OG_SUCCESS;
}

static status_t vm_sga_stat_prepare_pool(memory_pool_t *pool, uint32 *id)
{
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->page_count));
    ++(*id);
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->page_size));
    ++(*id);
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->opt_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        pool->free_pages.count));
    ++(*id);
    return OG_SUCCESS;
}

static uint32 vw_sga_stat_get_pl_lru_page(pl_list_t *list)
{
    uint32 page_count = 0;
    bilist_node_t *node = NULL;
    pl_entity_t *entity = NULL;

    node = list->lst.head;
    while (node != NULL) {
        entity = (pl_entity_t *)BILIST_NODE_OF(pl_entity_t, node, lru_link);
        page_count += entity->memory->pages.count;
        node = BINODE_NEXT(node);
    }

    return page_count;
}

static status_t vw_sga_stat_prepare_pl(uint32 *id)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_list_t *list = NULL;
    uint32 entity_count = 0;
    uint32 page_count = 0;
    int iret_snprintf;
    uint32 i;

    for (i = 0; i < PL_ENTITY_LRU_SIZE; i++) {
        list = &mngr->pl_entity_lru[i];
        cm_latch_s(&list->latch, CM_THREAD_ID, OG_FALSE, NULL);
        entity_count += list->lst.count;
        page_count += vw_sga_stat_get_pl_lru_page(list);
        cm_unlatch(&list->latch, NULL);
    }

    for (i = 0; i < PL_ANONY_LRU_SIZE; i++) {
        list = &mngr->anony_lru[i];
        cm_latch_s(&list->latch, CM_THREAD_ID, OG_FALSE, NULL);
        entity_count += list->lst.count;
        page_count += vw_sga_stat_get_pl_lru_page(list);
        cm_unlatch(&list->latch, NULL);
    }

    iret_snprintf =
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", entity_count);
    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return OG_ERROR;
    }
    ++(*id);

    iret_snprintf =
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", page_count);
    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return OG_ERROR;
    }
    ++(*id);

    return OG_SUCCESS;
}

static status_t vw_sga_lock_pool_stat(lock_area_t *lock_ctx, uint32 *id)
{
    uint32 free_pages;
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.page_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.page_size));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.opt_count));
    ++(*id);

    free_pages = (lock_ctx->capacity - lock_ctx->hwm + lock_ctx->free_items.count) / LOCK_PAGE_CAPACITY;
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", free_pages));
    ++(*id);
    return OG_SUCCESS;
}

static status_t vw_sga_lob_pool_stat(lob_area_t *lob_ctx, uint32 *id)
{
    uint32 free_pages;
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.page_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.page_size));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.opt_count));
    ++(*id);

    free_pages = (lob_ctx->capacity - lob_ctx->hwm + lob_ctx->free_items.count) / LOB_ITEM_PAGE_CAPACITY;
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", free_pages));
    ++(*id);
    return OG_SUCCESS;
}

static status_t vw_sga_stat_prepare(void)
{
    uint32 id = 0;

    // shared area
    OG_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.shared_area, &id));
    // sql pool
    context_pool_t *sql_pool_val = sql_pool;
    OG_RETURN_IFERR(vm_sga_stat_prepare_pool(sql_pool_val->memory, &id));

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        ogx_pool_get_lru_cnt(sql_pool_val)));
    ++id;

    // pl lru count and page count
    OG_RETURN_IFERR(vw_sga_stat_prepare_pl(&id));
    // dc pool
    OG_RETURN_IFERR(vm_sga_stat_prepare_pool(&g_instance->kernel.dc_ctx.pool, &id));
    // lock pool
    OG_RETURN_IFERR(vw_sga_lock_pool_stat(&g_instance->kernel.lock_ctx, &id));
    // lob pool
    OG_RETURN_IFERR(vw_sga_lob_pool_stat(&g_instance->kernel.lob_ctx, &id));
    // large pool statistic
    OG_RETURN_IFERR(vm_sga_stat_prepare_pool(&g_instance->sga.large_pool, &id));
    // small vma
    OG_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.marea, &id));
    // large vma
    OG_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.large_marea, &id));
    // private area
    OG_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.pma.marea, &id));
    CM_ASSERT(id == SGA_STAT_ROW_COUNT);
    return OG_SUCCESS;
}

static status_t vw_sga_stat_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    id = cursor->rowid.vmid;
    if (id >= SGA_STAT_ROW_COUNT) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    if (id == 0) {
        cm_spin_lock(&g_sga_lock, NULL);
        if (vw_sga_stat_prepare() != OG_SUCCESS) {
            cm_spin_unlock(&g_sga_lock);
            return OG_ERROR;
        }
        cm_spin_unlock(&g_sga_lock);
    }

    row_init(&ra, (char *)cursor->row, OG_MAX_ROW_SIZE, SGA_STAT_COLS);
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].area));
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].pool));
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].name));
    OG_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].value));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return OG_SUCCESS;
}

static inline status_t vw_ogsql_funcarea_row_put_vm_ctx(row_assist_t *row, vw_ogsql_funcarea_assist_t *assist)
{
    int64 cpu_time;
    sql_context_t *vw_ctx = &assist->vw_ctx;
    OG_RETURN_IFERR(row_put_text(row, (text_t *)cs_get_login_client_name((client_kind_t)vw_ctx->module_kind)));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.io_wait_time));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.con_wait_time));
    cpu_time = (int64)(vw_ctx->stat.elapsed_time - vw_ctx->stat.io_wait_time - vw_ctx->stat.con_wait_time
        ) -
        vw_ctx->stat.dcs_wait_time;
    if (cpu_time < 0) {
        cpu_time = 0;
    }
    OG_RETURN_IFERR(row_put_int64(row, cpu_time));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.elapsed_time));
    OG_RETURN_IFERR(row_put_date(row, vw_ctx->stat.last_load_time));    /* last_load_time */
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.proc_oid));  /* program_id */
    OG_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->stat.proc_line)); /* program_line# */
    OG_RETURN_IFERR(row_put_date(row, vw_ctx->stat.last_active_time));  /* last_active_time */
    OG_RETURN_IFERR(row_put_int32(row, (int32)assist->ref_count));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.is_free));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.cleaned));
    OG_RETURN_IFERR(row_put_int32(row, (int32)assist->pages));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.valid));
    if (assist->pages > 1) {
        OG_RETURN_IFERR(
            row_put_int64(row, (int64)(((int64)assist->pages - 1) * OG_SHARED_PAGE_SIZE + assist->alloc_pos)));
    } else {
        OG_RETURN_IFERR(row_put_int64(row, (int64)assist->alloc_pos));
    }
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.open_pages));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.close_pages));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.swap_in_pages));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.free_pages));
    OG_RETURN_IFERR(row_put_int64(row, 0));

    if (IS_COORDINATOR && assist->pdown_sql_id.len > 0) {
        OG_RETURN_IFERR(row_put_text(row, &assist->pdown_sql_id)); /* pdown_sql_id */
    } else {
        OG_RETURN_IFERR(row_put_null(row));
    }
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.alloc_pages));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.max_open_pages));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.swap_out_pages));

    return OG_SUCCESS;
}

static inline status_t vw_ogsql_funcarea_row_put
    (knl_handle_t session, row_assist_t *row, vw_ogsql_funcarea_assist_t *assist)
{
    int32 errcode;
    char hash_valstr[OG_MAX_UINT32_STRLEN + 1];
    char username_buf[OG_MAX_NAME_LEN + 1];
    text_t parse_username = {
        .str = username_buf,
        .len = 0
    };
    sql_context_t *vw_ctx = &assist->vw_ctx;
    if (assist->sql_text.len > 0) {
        OG_RETURN_IFERR(row_put_text(row, &assist->sql_text));
    } else {
        OG_RETURN_IFERR(row_put_null(row));
    }

    PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (OG_MAX_UINT32_STRLEN + 1), "%010u", assist->sql_hash));
    OG_RETURN_IFERR(row_put_str(row, hash_valstr)); /* sql_id */
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.executions));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.disk_reads));
    OG_RETURN_IFERR(row_put_int64(row, (int64)(vw_ctx->stat.buffer_gets + vw_ctx->stat.cr_gets)));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.cr_gets));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.sorts));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.parse_time));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.parse_calls));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.processed_rows));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.uid)); /* parsing user id */

    if (knl_get_user_name(session, vw_ctx->ctrl.uid, &parse_username) != OG_SUCCESS) {
        const char *err_message = NULL;
        cm_get_error(&errcode, &err_message, NULL);
        OG_RETVALUE_IFTRUE(errcode != (int32)ERR_USER_NOT_EXIST, OG_ERROR);

        /*
         * we would like to keep the size of sql_context_t as little as possible.
         * so we didn't save the original user name when the sql_context_t created while the sql first hard-parsed.
         * however, when we tried to get the user name with the saved user id via knl_get_user_nmae() here,
         * the knl_get_user_name() might return an error when the user id already dropped.
         * we don't want an error here, so we ignore the error ERR_USER_NOT_EXIST
         * and fill the name with a fixed string under that circumstance
         */
        static const text_t dropped_user_const = {
            .str = "DROPPED USER",
            .len = 12
        };
        parse_username = dropped_user_const;
        cm_reset_error();
    }
    OG_RETURN_IFERR(row_put_text(row, &parse_username)); /* parsing user name */
    OG_RETURN_IFERR(vw_ogsql_funcarea_row_put_vm_ctx(row, assist));
    OG_RETURN_IFERR(row_put_int64(row, (int64)(vw_ctx->stat.dcs_buffer_gets + vw_ctx->stat.dcs_cr_gets)));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.dcs_cr_gets));
    OG_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.dcs_wait_time));
    return OG_SUCCESS;
}

static status_t vw_ogsql_funcarea_save_assist(context_ctrl_t *ctrl, char *sql_copy, vw_ogsql_funcarea_assist_t *assist)
{
    uint32 total_len = 0;
    assist->pdown_sql_id.len = 0;
    assist->vw_ctx = *((sql_context_t *)ctrl);
    assist->pages = ctrl->memory->pages.count;
    assist->alloc_pos = ctrl->memory->alloc_pos;
    assist->sql_hash = ctrl->hash_value;
    assist->ref_count = ctrl->ref_count;

    // save sql text
    ogx_read_first_page_text(sql_pool, &assist->vw_ctx.ctrl, &assist->sql_text);
    if (cm_text2str(&assist->sql_text, sql_copy, OG_MAX_COLUMN_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    assist->sql_text.str = sql_copy;
    assist->sql_text.len = (uint32)strlen(sql_copy);

    // save sql push down hash id
    if (IS_COORDINATOR && ctrl->pdown_sql_id != NULL) {
        for (uint32 i = 0; i < ctrl->pdown_sql_id->count && i < SGA_MAX_SQL_ID_NUM; i++) {
            if (total_len + SGA_SQL_ID_LEN >= SGA_PDOWN_BUFFER_LEN) {
                break;
            }
            uint32 *hash_value = (uint32 *)cm_galist_get(ctrl->pdown_sql_id, i);
            PRTS_RETURN_IFERR(sprintf_s(assist->pdown_sql_buffer + total_len, (SGA_PDOWN_BUFFER_LEN - total_len),
                "%010u", *hash_value));
            assist->pdown_sql_buffer[total_len + SGA_SQL_ID_LEN] = ',';
            total_len = total_len + SGA_SQL_ID_LEN + 1;
        }
    }
    if (total_len > 0) {
        assist->pdown_sql_id.str = assist->pdown_sql_buffer;
        assist->pdown_sql_id.len = total_len - 1;
    }
    return OG_SUCCESS;
}

static status_t vw_ogsql_funcarea_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    uint64 id = cursor->rowid.vmid;
    context_ctrl_t *ctrl = NULL;
    char *sql_copy = NULL;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    vw_ogsql_funcarea_assist_t assist;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&sql_copy));

    while (id < (sql_pool)->map->hwm) {
        if (ogx_get(g_instance->sql.pool, (uint32)id) == NULL) {
            ++id;
            continue;
        }

        cm_spin_lock(&sql_pool->lock, NULL);
        ctrl = ogx_get(g_instance->sql.pool, (uint32)id);
        if (ctrl != NULL) {
            if (vw_ogsql_funcarea_save_assist(ctrl, sql_copy, &assist) != OG_SUCCESS) {
                cm_spin_unlock(&sql_pool->lock);
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            cm_spin_unlock(&sql_pool->lock);
            break;
        }
        cm_spin_unlock(&sql_pool->lock);
        ++id;
    }

    if (id >= (sql_pool)->map->hwm) {
        OGSQL_RESTORE_STACK(stmt);
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, OG_MAX_ROW_SIZE, SQLAREA_COLS);
    if (vw_ogsql_funcarea_row_put(session, &row, &assist) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid = (++id);
    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}

static void vw_plarea_save_assist(pl_entity_t *entity, vw_ogsql_funcarea_assist_t *assist)
{
    sql_context_t *sql_ctx = entity->context;
    memory_context_t *mem_ctx = entity->memory;
    anonymous_desc_t *desc = &entity->anonymous->desc;

    assist->pdown_sql_id.len = 0;
    assist->vw_ctx = *sql_ctx;
    assist->pages = mem_ctx->pages.count;
    assist->alloc_pos = mem_ctx->alloc_pos;
    assist->sql_text = desc->sql;
    assist->sql_hash = desc->sql_hash;
    assist->ref_count = entity->ref_count;
}

static status_t vw_plarea_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_entity_t *entity = NULL;
    pl_list_t *list = NULL;
    bilist_node_t *node = NULL;
    row_assist_t row;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    uint32 bucketid = (uint32)cursor->rowid.vm_slot;
    uint32 position = (uint32)cursor->rowid.vmid;
    vw_ogsql_funcarea_assist_t assist;
    status_t status = OG_ERROR;

    while (OG_TRUE) {
        if (bucketid >= PL_ANONY_LRU_SIZE) {
            cursor->eof = OG_TRUE;
            return OG_SUCCESS;
        }

        list = &mngr->anony_lru[bucketid];
        if (list->lst.count <= position) {
            bucketid++;
            position = 0;
            continue;
        }
        cm_latch_s(&list->latch, CM_THREAD_ID, OG_FALSE, NULL);
        if (list->lst.count <= position) {
            cm_unlatch(&list->latch, NULL);
            bucketid++;
            position = 0;
            continue;
        }
        break;
    }
    node = cm_bilist_get(&list->lst, position);
    CM_ASSERT(node != NULL);
    entity = BILIST_NODE_OF(pl_entity_t, node, lru_link);

    OGSQL_SAVE_STACK(stmt);
    do {
        vw_plarea_save_assist(entity, &assist);
        row_init(&row, (char *)cursor->row, OG_MAX_ROW_SIZE, SQLAREA_COLS);
        OG_BREAK_IF_ERROR(vw_ogsql_funcarea_row_put(session, &row, &assist));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        status = OG_SUCCESS;
    } while (OG_FALSE);
    OGSQL_RESTORE_STACK(stmt);
    cm_unlatch(&list->latch, NULL);

    position++;
    cursor->rowid.vm_slot = (uint64)bucketid;
    cursor->rowid.vmid = (uint64)position;
    return status;
}

static inline status_t vm_sqlpool_row_put(sql_stmt_t *stmt, row_assist_t *row, sql_context_t *vm_ctx,
    memory_context_t *mctx, text_t *pagelist)
{
    int32 err_no;
    text_t hash_id;

    OG_RETURN_IFERR(sql_push(stmt, 24, (void **)&hash_id.str)); // 24 bytes
    // put hash id
    err_no = sprintf_s(hash_id.str, (OG_MAX_UINT32_STRLEN + 1), "%010u", vm_ctx->ctrl.hash_value);
    if (err_no == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (err_no));
        return OG_ERROR;
    }

    hash_id.len = (uint32)err_no;
    OG_RETURN_IFERR(row_put_text(row, &hash_id)); /* sql_id */

    // put ctrl info
    OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->type));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->ctrl.uid));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->ctrl.ref_count));
    OG_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.valid));
    OG_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.cleaned));
    OG_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.is_free));

    // put pages infos
    OG_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.count));
    OG_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.first));
    OG_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.last));
    OG_RETURN_IFERR(row_put_int32(row, (int32)mctx->curr_page_id));
    OG_RETURN_IFERR(row_put_text(row, pagelist));

    // put large page id
    if (vm_ctx->large_page_id == OG_INVALID_ID32) {
        OG_RETURN_IFERR(row_put_null(row));
    } else {
        OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->large_page_id));
    }

    // put the first-executable optimization information
    OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->fexec_vars_cnt));
    OG_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->fexec_vars_bytes));

    // put active time
    OG_RETURN_IFERR(row_put_date(row, vm_ctx->stat.last_load_time));
    OG_RETURN_IFERR(row_put_date(row, vm_ctx->stat.last_active_time));

    return OG_SUCCESS;
}

static status_t inline vw_format_mctx_pages(const memory_context_t *mctx, text_buf_t *txtbuf)
{
    if (mctx->pages.count == 0) {
        return OG_SUCCESS;
    }

    uint32 next_page = mctx->pages.first;

    if (next_page >= mctx->pool->opt_count) {
        (void)cm_buf_append_str(txtbuf, "invalid page");
        return OG_SUCCESS;
    }
    (void)cm_buf_append_fmt(txtbuf, "%u", next_page);

    for (uint32 i = 1; i < mctx->pages.count; i++) {
        // get the next page
        next_page = mctx->pool->maps[next_page];
        if (next_page >= mctx->pool->opt_count) {
            OG_RETURN_IFERR(cm_concat_string((text_t *)txtbuf, txtbuf->max_size, "->invalid page"));
            return OG_SUCCESS;
        }
        if (!cm_buf_append_fmt(txtbuf, "->%u", next_page)) {
            // the memory can not overflow, 20 bytes are reserved for situation
            OG_RETURN_IFERR(cm_concat_string((text_t *)txtbuf, txtbuf->max_size, "-> ..."));
            return OG_SUCCESS;
        }
    }

    return OG_SUCCESS;
}

static status_t vw_ogsql_funcpool_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    memory_context_t mctx;
    context_ctrl_t *ctrl = NULL;
    sql_context_t vm_ctx;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    uint64 id = cursor->rowid.vmid;
    text_buf_t pagelist;
    dc_user_t *user = NULL;

    OGSQL_SAVE_STACK(stmt);

    OG_RETURN_IFERR(sql_push_textbuf(stmt, OG_MAX_COLUMN_SIZE, &pagelist));
    pagelist.max_size -= 20; // reserved 20 bytes for putting ending text

    while (id < (sql_pool)->map->hwm) {
        if (ogx_get(g_instance->sql.pool, (uint32)id) == NULL) {
            ++id;
            continue;
        }
        cm_spin_lock(&sql_pool->lock, NULL);
        ctrl = ogx_get(sql_pool, (uint32)id);
        if (ctrl != NULL) { // prefetching
            // Copy, avoid unstable ptr
            vm_ctx = *((sql_context_t *)ctrl);
            mctx = *vm_ctx.ctrl.memory;

            // to print the page list of mctx, the lock of memory pool is needed
            cm_spin_lock(&mctx.pool->lock, NULL);
            (void)vw_format_mctx_pages(&mctx, &pagelist);
            cm_spin_unlock(&mctx.pool->lock);

            cm_spin_unlock(&sql_pool->lock);
            break;
        }
        cm_spin_unlock(&sql_pool->lock);
        id++;
    }

    if (id >= (sql_pool)->map->hwm) {
        cursor->eof = OG_TRUE;
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, OG_MAX_ROW_SIZE, SQLPOOL_COLS);
    if (vm_sqlpool_row_put(stmt, &row, &vm_ctx, &mctx, (text_t *)&pagelist) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(&stmt->session->knl_session, vm_ctx.ctrl.uid, &user), cursor, user);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid = (++id);
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t vw_ogsql_funcpool_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_ogsql_funcpool_fetch_core, session, cursor);
}

/**
 * Create sub-statement for SQL plan visualization
 * @note Caller MUST protect memory stack with OGSQL_SAVE_STACK/OGSQL_RESTORE_STACK
 *       before/after calling this function
 */
static status_t vw_ogsql_plan_func_push_stmt(sql_stmt_t *stmt, sql_stmt_t **ret, sql_context_t *ctx)
{
    sql_stmt_t *sub_stmt = NULL;
    OG_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    SET_STMT_CONTEXT(sub_stmt, ctx);

    status_t init_status[] = {
        sql_init_sequence(sub_stmt),
        sql_init_first_exec_info(sub_stmt),
        sql_fill_null_params(sub_stmt),
        sql_init_pl_ref_dc(stmt)
    };
    for (size_t i = 0; i < sizeof(init_status) / sizeof(init_status[0]); ++i) {
        OG_RETURN_IFERR(init_status[i]);
    }

    sub_stmt->is_explain = OG_TRUE;
    *ret = sub_stmt;

    return OG_SUCCESS;
}

/* Check whether the signature has been generated and is non-empty */
static inline bool32 is_signature_generated(const text_t *sign)
{
    return (sign != NULL && sign->str != NULL && sign->len > 0 && sign->str[0] != '\0');
}


static status_t vw_with_spin_lock(spinlock_t *lock, status_t (*operation)(void *), void *arg)
{
    cm_spin_lock(lock, NULL);
    status_t status = operation(arg);
    cm_spin_unlock(lock);
    return status;
}

typedef struct {
    text_t *plan_text;
    text_t *signature;
} md5_calc_param_t;

static status_t vw_calculate_md5_worker(void *arg)
{
    md5_calc_param_t *param = (md5_calc_param_t *)arg;
    return spm_calculate_md5_signature(param->plan_text, param->signature);
}

static status_t vw_alloc_sql_buffer(sql_stmt_t *stmt, char **buffer)
{
    return sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)buffer);
}

/**
 * Generate a new plan signature and store it in context
 */
static status_t vw_generate_and_store_signature(sql_stmt_t *stmt, sql_context_t *ctx)
{
    char *buffer = NULL;
    OG_RETURN_IFERR(vw_alloc_sql_buffer(stmt, &buffer));

    text_t plan_text = { .str = buffer, .len = OG_MAX_COLUMN_SIZE };
    status_t status = OG_SUCCESS;

    stmt->hide_plan_extras = OG_TRUE;
    status = expl_get_explain_text(stmt, &plan_text);
    stmt->hide_plan_extras = OG_FALSE;

    if (status != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return status;
    }

    plan_text.len = (uint32)(plan_text.str - buffer);
    plan_text.str = buffer;

    md5_calc_param_t md5_param = {
        .plan_text = &plan_text,
        .signature = &ctx->ctrl.signature
    };
    status = vw_with_spin_lock(&ctx->ctrl.lock, vw_calculate_md5_worker, &md5_param);

    OGSQL_POP(stmt);
    return status;
}

/* Check whether the signature is a valid MD5 hex string */
static inline bool32 vw_is_spm_signature(text_t *sign)
{
    if (sign->len == OG_MD5_SIZE) {
        if (cm_verify_hex_string(sign) == OG_SUCCESS) {
            return OG_TRUE;
        }
        cm_reset_error();
    }
    return OG_FALSE;
}

static status_t vw_put_binary_as_text(row_assist_t *row, binary_t *bin, char *text_buffer, size_t buffer_size)
{
    text_t text = { .str = text_buffer, .len = buffer_size };
    OG_RETURN_IFERR(cm_bin2text(bin, OG_FALSE, &text));
    return row_put_text(row, &text);
}

#define VPEEK_VERSION_HEX_BUF_SIZE  (2 * OG_MAX_VPEEK_VER_SIZE)

static status_t vw_put_ogsql_vpeek_func_version(row_assist_t *row, text_t *sign)
{
    char version[VPEEK_VERSION_HEX_BUF_SIZE] = { 0 };
    binary_t bin = { .bytes = (uint8 *)sign->str, .size = sign->len };
    return vw_put_binary_as_text(row, &bin, version, sizeof(version));
}

/* Write plan signature to row, generating or transforming if necessary */
static inline status_t vw_put_ogsql_plan_func_version(sql_stmt_t *stmt, sql_context_t *context, row_assist_t *row)
{
    text_t *sign = &context->ctrl.signature;

    if (!is_signature_generated(sign)) {
        OG_RETURN_IFERR(vw_generate_and_store_signature(stmt, context));
        return row_put_text(row, sign);
    }

    if (context->need_vpeek && !vw_is_spm_signature(sign)) {
        OG_RETURN_IFERR(vw_put_ogsql_vpeek_func_version(row, sign));
    }

    return row_put_text(row, sign);
}

static status_t vw_batch_put_int64(row_assist_t *row, const int64 *metrics, size_t metric_count)
{
    for (size_t i = 0; i < metric_count; ++i) {
        OG_RETURN_IFERR(row_put_int64(row, metrics[i]));
    }
    return OG_SUCCESS;
}

static status_t vw_put_plan_basic_metrics(row_assist_t *row, const sql_context_t *ctx)
{
    int64 basic_metrics[] = {
        (int64)ctx->stat.executions,
        (int64)ctx->stat.disk_reads,
        (int64)(ctx->stat.buffer_gets + ctx->stat.cr_gets),
        (int64)ctx->stat.cr_gets,
        (int64)ctx->stat.sorts
    };
    return vw_batch_put_int64(row, basic_metrics, sizeof(basic_metrics) / sizeof(basic_metrics[0]));
}

static status_t vw_put_plan_time_metrics(row_assist_t *row, const sql_context_t *ctx)
{
    int64 cpu_time = ctx->stat.elapsed_time - ctx->stat.io_wait_time - ctx->stat.con_wait_time;

    int64 time_metrics[] = {
        (int64)ctx->stat.parse_time,
        (int64)ctx->stat.io_wait_time,
        (int64)ctx->stat.con_wait_time,
        cpu_time,
        (int64)ctx->stat.elapsed_time
    };
    return vw_batch_put_int64(row, time_metrics, sizeof(time_metrics) / sizeof(time_metrics[0]));
}

static status_t vw_put_plan_memory_metrics(row_assist_t *row, const sql_context_t *ctx)
{
    uint32 pages = ctx->ctrl.memory->pages.count;
    OG_RETURN_IFERR(row_put_int32(row, (int32)pages));

    uint32 alloc_pos = ctx->ctrl.memory->alloc_pos;
    int64 memory_size = (pages > 1) ?
                                    ((int64)pages - 1) * OG_SHARED_PAGE_SIZE + alloc_pos :
                                    (int64)alloc_pos;

    return row_put_int64(row, memory_size);
}

static status_t vw_init_plan_text(sql_stmt_t *stmt, text_t *plan_text)
{
    char *buf = NULL;
    OG_RETURN_IFERR(vw_alloc_sql_buffer(stmt, &buf));

    plan_text->str = buf;
    plan_text->len = OG_MAX_COLUMN_SIZE;

    status_t status = expl_get_explain_text(stmt, plan_text);
    if (status != OG_SUCCESS) {
    OGSQL_POP(stmt);
    return OG_ERROR;
    }

    plan_text->len = (uint32)(plan_text->str - buf);
    plan_text->str = buf;
    if (plan_text->len > 0) {
        plan_text->str[plan_text->len - 1] = '\0';
    }

    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

static status_t vw_put_plan_text(sql_stmt_t *stmt, row_assist_t *row)
{
    text_t plan_text = { 0 };
    OG_RETURN_IFERR(vw_init_plan_text(stmt, &plan_text));

    return row_put_text(row, &plan_text);
}

#define VM_METRICS_TOTAL_COUNT 4
#define VM_METRICS_SWAP_START_INDEX 3

static status_t vw_put_plan_vm_metrics(row_assist_t *row, const sql_context_t *ctx, sql_stmt_t *stmt)
{
    int64 vm_metrics[] = {
        (int64)ctx->stat.vm_stat.open_pages,
        (int64)ctx->stat.vm_stat.close_pages,
        (int64)ctx->stat.vm_stat.swap_in_pages,
        (int64)ctx->stat.vm_stat.free_pages,
        (int64)ctx->stat.vm_stat.alloc_pages,
        (int64)ctx->stat.vm_stat.max_open_pages,
        (int64)ctx->stat.vm_stat.swap_out_pages
    };

    OG_RETURN_IFERR(vw_batch_put_int64(row, vm_metrics, VM_METRICS_TOTAL_COUNT));
    OG_RETURN_IFERR(vw_put_plan_text(stmt, row));
    return vw_batch_put_int64(row, &vm_metrics[VM_METRICS_TOTAL_COUNT], VM_METRICS_SWAP_START_INDEX);
}

static inline status_t vw_put_ogsql_plan_func_signature(row_assist_t *row, sql_context_t *ctx)
{
    if (is_signature_generated(&ctx->spm_sign)) {
        return row_put_text(row, &ctx->spm_sign);  // sys_spm signature
    } else if (vw_is_spm_signature(&ctx->ctrl.signature)) {
        return row_put_text(row, &ctx->ctrl.signature);  // actual signature
    } else {
        return row_put_null(row);
    }
}

static inline bool32 vw_check_pl_entity(pl_dc_t *pl_dc)
{
    return (pl_dc->entity != NULL && !pl_dc->entity->valid);
}

static int verify_table_dc_validity(knl_session_t *curr_session, sql_table_entry_t *table_item)
{
    if (NULL == table_item) {
        return OG_SUCCESS;
    }
    return knl_check_dc(curr_session, &table_item->dc);
}

static int validate_sql_table_item_by_index(galist_t *p_table_set, uint32 table_index, knl_session_t *p_current_sess)
{
    sql_table_entry_t *p_target_table_item = (sql_table_entry_t *)cm_galist_get(p_table_set, table_index);
    return verify_table_dc_validity(p_current_sess, p_target_table_item);
}

static int check_all_sql_table_dc(galist_t *p_table_set, knl_session_t *p_current_sess)
{
    if (NULL == p_table_set || NULL == p_current_sess) {
        return OG_SUCCESS;
    }

    uint32 total_table_quantity = p_table_set->count;

    for (uint32 curr_table_idx = 0; curr_table_idx < total_table_quantity; ++curr_table_idx) {
        if (validate_sql_table_item_by_index(p_table_set, curr_table_idx, p_current_sess) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static bool32 vw_validate_context_entity(sql_context_t *ctx)
{
    knl_session_t *p_current_session = (knl_session_t *)knl_get_curr_sess();

    if (NULL == ctx || NULL == ctx->tables || NULL == p_current_session) {
        return OG_TRUE;
    }

    galist_t *p_sql_table_collection = ctx->tables;

    if (check_all_sql_table_dc(p_sql_table_collection, p_current_session) != OG_SUCCESS) {
        cm_reset_error();
        return OG_FALSE;
    }

    if (ctx->dc_lst != NULL) {
        for (uint32 i = 0; i < ctx->dc_lst->count; ++i) {
            pl_dc_t *dc = (pl_dc_t *)cm_galist_get(ctx->dc_lst, i);
            if (vw_check_pl_entity(dc)) {
                return OG_FALSE;
            }
        }
    }

    return OG_TRUE;
}

static bool32 vw_validate_context(sql_context_t *ctx)
{
    return vw_validate_context_entity(ctx);
}

static inline void vw_ogsql_func_plan_switch_next_ctx(knl_cursor_t *cursor, bool32 subctx)
{
    if (!subctx) {
        cursor->rowid.vm_slot = 0;
        cursor->rowid.vmid++;
        return;
    }
    cursor->rowid.vm_slot++;
}

static inline uint32 vw_ogsql_func_plan_get_context_id(knl_cursor_t *cursor, bool32 is_subctx)
{
    return (uint32)(is_subctx ? cursor->rowid.vm_slot : cursor->rowid.vmid);
}

static context_ctrl_t *vw_ogsql_func_plan_find_next_ctrl(context_pool_t *pool, knl_cursor_t *cursor, bool32 is_subctx)
{
    context_ctrl_t *found_ctrl = NULL;
    bool found = OG_FALSE;

    cm_spin_lock(&pool->lock, NULL);
    while (!found) {
        uint32 id = vw_ogsql_func_plan_get_context_id(cursor, is_subctx);
        if (id >= pool->map->hwm) {
            break;
        }

        context_ctrl_t *ctrl = ogx_get(pool, id);
        if (ctrl == NULL || !ctrl->valid || ((sql_context_t *)ctrl)->type >= OGSQL_TYPE_DML_CEIL) {
            vw_ogsql_func_plan_switch_next_ctx(cursor, is_subctx);
            continue;
        }

        status_t validate_status = vw_with_spin_lock(&ctrl->lock,
                                                     (status_t (*)(void *))vw_validate_context, (void *)ctrl);
        if (validate_status == OG_SUCCESS && ctrl->valid) {
            ctrl->ref_count++;
            ctrl->exec_count++;
            found_ctrl = ctrl;
            found = true;
        }

        if (!found) {
            vw_ogsql_func_plan_switch_next_ctx(cursor, is_subctx);
        }
    }
    cm_spin_unlock(&pool->lock);
    return found_ctrl;
}

static inline void vw_release_ctrl_res(context_pool_t *pool, context_ctrl_t *ctrl)
{
    ogx_dec_exec(ctrl);
    ogx_dec_ref(pool, ctrl);
}

typedef struct {
    row_assist_t *row;
    sql_context_t *ctx;
    sql_stmt_t *stmt;
} plan_row_op_ctx_t;

typedef status_t (*plan_row_op_func_t)(plan_row_op_ctx_t *op_ctx);

static status_t vw_op_signature(plan_row_op_ctx_t *op_ctx)
{
    return vw_put_ogsql_plan_func_signature(op_ctx->row, op_ctx->ctx);
}

static status_t vw_common_batch_execute(plan_row_op_func_t *op_funcs, size_t func_count, plan_row_op_ctx_t *op_ctx)
{
    for (size_t i = 0; i < func_count; ++i) {
        if (op_funcs[i] == NULL) {
            continue;
        }
        OG_RETURN_IFERR(op_funcs[i](op_ctx));
    }
    return OG_SUCCESS;
}

#define PLAN_ROW_OP_FUNC_COUNT  (sizeof(op_funcs) / sizeof(*op_funcs))

static status_t vw_op_combined_core_operations(plan_row_op_ctx_t *op_ctx)
{
    OG_RETURN_IFERR(vw_put_plan_basic_metrics(op_ctx->row, op_ctx->ctx));
    OG_RETURN_IFERR(vw_put_plan_time_metrics(op_ctx->row, op_ctx->ctx));
    OG_RETURN_IFERR(row_put_date(op_ctx->row, op_ctx->ctx->stat.last_load_time));
    OG_RETURN_IFERR(row_put_date(op_ctx->row, op_ctx->ctx->stat.last_active_time));
    OG_RETURN_IFERR(row_put_int32(op_ctx->row, (int32)op_ctx->ctx->ctrl.ref_count));
    OG_RETURN_IFERR(vw_put_plan_memory_metrics(op_ctx->row, op_ctx->ctx));
    return vw_put_plan_vm_metrics(op_ctx->row, op_ctx->ctx, op_ctx->stmt);
}

static status_t vw_ogsql_plan_func_row_put_core(row_assist_t *row, sql_context_t *ctx, sql_stmt_t *stmt)
{
    plan_row_op_ctx_t op_ctx = {.row = row, .ctx = ctx, .stmt = stmt};

    plan_row_op_func_t op_funcs[] = {
        vw_op_combined_core_operations,
        vw_op_signature
    };

    const size_t func_count = sizeof(op_funcs) / sizeof(*op_funcs);
    return vw_common_batch_execute(op_funcs, func_count, &op_ctx);
}

#define SQL_ID_BUF_SIZE  (OG_MAX_UINT32_STRLEN + 1)
#define SQL_PLAN_ROW_OP_COUNT  (sizeof(row_op_status_array) / sizeof(*row_op_status_array))

static status_t vw_verify_row_status_array(status_t *status_arr, size_t arr_len)
{
    for (size_t i = 0; i < arr_len; ++i) {
        if (status_arr[i] != OG_SUCCESS) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

// Encapsulate the resource release logic for child SQL statement to avoid code duplication
static inline void deallocate_child_sql_resources(void *p_sql_child_instance)
{
    // Release LOB related information first as per the internal resource dependency
    sql_release_lob_info(p_sql_child_instance);
    // Release all associated resources with forced mode enabled
    sql_release_resource(p_sql_child_instance, OG_TRUE);
}

static int format_sql_id_by_hash(char *p_sql_id_buf, uint32 hash_val, uint32 buf_size)
{
    return sprintf_s(p_sql_id_buf, buf_size, "%010u", hash_val);
}

static void init_sql_data_row(row_assist_t *p_data_row, knl_cursor_t *p_cursor)
{
    row_init(p_data_row, (char *)p_cursor->row, OG_MAX_ROW_SIZE, SQL_PLAN_COLS);
}

static void release_child_sql_stmt_resources(void *p_sql_stmt_handle)
{
    if (p_sql_stmt_handle != NULL) {
        deallocate_child_sql_resources(p_sql_stmt_handle);
    }
}

static status_t vw_ogsql_func_plan_row_put
    (knl_handle_t session, sql_context_t *ctx, uint32 hash_value, knl_cursor_t *cursor)
{
    row_assist_t data_row;
    char stmt_sql_id[SQL_ID_BUF_SIZE] = { 0 };
    sql_stmt_t *p_curr_stmt = ((session_t *)session)->current_stmt;
    sql_stmt_t *p_child_stmt = NULL;
    status_t op_status = OG_ERROR;

    OGSQL_SAVE_STACK(p_curr_stmt);

    do {
        OG_BREAK_IF_ERROR(vw_ogsql_plan_func_push_stmt(p_curr_stmt, &p_child_stmt, ctx));

        init_sql_data_row(&data_row, cursor);

        if (format_sql_id_by_hash(stmt_sql_id, hash_value, SQL_ID_BUF_SIZE) == -1) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, -1);
            break;
        }

        // Collect all row operation statuses into an array for unified verification
        status_t row_op_status_array[] = {
            row_put_str(&data_row, stmt_sql_id),
            vw_put_ogsql_plan_func_version(p_child_stmt, ctx, &data_row),
            vw_ogsql_plan_func_row_put_core(&data_row, ctx, p_child_stmt)
        };

        // Break loop if any row operation in the status array returns an error
        if (!vw_verify_row_status_array(row_op_status_array, SQL_PLAN_ROW_OP_COUNT)) {
            break;
        }

        // Decode cursor row data with offset and length information to update data size
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

        // Update operation status to success after all operations complete normally
        op_status = OG_SUCCESS;
    } while (OG_FALSE);

    void *p_child_sql_handle = p_child_stmt;
    release_child_sql_stmt_resources(p_child_sql_handle);

    OGSQL_RESTORE_STACK(p_curr_stmt);
    return op_status;
}

static status_t vw_fetch_sub_plan(knl_handle_t session, context_ctrl_t *parent, knl_cursor_t *cursor, bool32 *result)
{
    if (parent->subpool == NULL) {
        return OG_SUCCESS;
    }

    context_ctrl_t *ctrl = vw_ogsql_func_plan_find_next_ctrl(parent->subpool, cursor, OG_TRUE);
    if (ctrl == NULL) {
        return OG_SUCCESS;
    }

    status_t status = vw_ogsql_func_plan_row_put(session, (sql_context_t *)ctrl, parent->hash_value, cursor);
    if (status == OG_SUCCESS) {
        *result = OG_TRUE;
        vw_ogsql_func_plan_switch_next_ctx(cursor, OG_TRUE);
    }

    ogx_dec_exec(ctrl);
    ogx_dec_ref(parent->subpool, ctrl);
    return status;
}

static status_t vw_ogsql_func_plan_open(knl_handle_t session, knl_cursor_t *cursor)
{
    if (cursor == NULL || cursor->stmt == NULL) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    sql_stmt_t *stmt = (sql_stmt_t *)cursor->stmt;
    sql_cursor_t *sql_cursor = OGSQL_CURR_CURSOR(stmt);

    if (sql_cursor == NULL) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    if (sql_cursor->exec_data.dv_plan_buf == NULL) {
        OG_RETURN_IFERR(vmc_alloc(&sql_cursor->vmc, OG_MAX_ROW_SIZE, (void **)&sql_cursor->exec_data.dv_plan_buf));
    }

    cursor->row = (row_head_t *)sql_cursor->exec_data.dv_plan_buf;
    cursor->rowid = (rowid_t){ .vmid = 0, .vm_slot = 0 };

    return OG_SUCCESS;
}

static int get_next_sql_plan_ctrl(knl_cursor_t *p_cursor, context_ctrl_t **pp_plan_ctrl)
{
    *pp_plan_ctrl = vw_ogsql_func_plan_find_next_ctrl(sql_pool, p_cursor, OG_FALSE);
    return (*pp_plan_ctrl != NULL) ? OG_SUCCESS : OG_ERROR;
}

static status_t vw_fetch_sql_plan(knl_handle_t session, knl_cursor_t *cursor)
{
    context_ctrl_t *p_subsequent_sql_plan_ctrl_handler = NULL;

    if (get_next_sql_plan_ctrl(cursor, &p_subsequent_sql_plan_ctrl_handler) != OG_SUCCESS) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    status_t status = OG_SUCCESS;
    bool32 result = OG_FALSE;

    do {
        status = vw_fetch_sub_plan(session,
                                   p_subsequent_sql_plan_ctrl_handler, cursor, &result);
        if (status != OG_SUCCESS) {
            break;
        }

        if (result) {
            break;
        }

        status = vw_ogsql_func_plan_row_put(session, (sql_context_t *)p_subsequent_sql_plan_ctrl_handler,
                                     p_subsequent_sql_plan_ctrl_handler->hash_value, cursor);
        if (status != OG_SUCCESS) {
            break;
        }

        vw_ogsql_func_plan_switch_next_ctx(cursor, OG_FALSE);
    } while (OG_FALSE);

    vw_release_ctrl_res(sql_pool, p_subsequent_sql_plan_ctrl_handler);
    return status;
}

VW_DECL dv_sga = { "SYS", "DV_GMA", SGA_COLS, g_sga_columns, vw_common_open, vw_sga_fetch };
VW_DECL dv_system = { "SYS", "DV_SYSTEM", SYSTEM_COLS, g_system_columns, vw_common_open, vw_system_fetch };
VW_DECL dv_temp_pool = {
    "SYS", "DV_TEMP_POOLS", TEMP_POOL_COLS, g_temp_pool_columns, vw_common_open, vw_temp_pool_fetch
};
VW_DECL dv_vm_func_stack = { "SYS",          "DV_VM_FUNC_STACK",    VM_FUNC_STACK_COLS, g_vm_func_stack_columns,
                             vw_common_open, vw_vm_func_stack_fetch };
VW_DECL dv_sqlarea = { "SYS", "DV_SQLS", SQLAREA_COLS, g_sqlarea_columns, vw_common_open, vw_ogsql_funcarea_fetch };
VW_DECL dv_anonymous = { "SYS", "DV_ANONYMOUS", SQLAREA_COLS, g_sqlarea_columns, vw_common_open, vw_plarea_fetch };
VW_DECL dv_sgastat = { "SYS", "DV_GMA_STATS", SGA_STAT_COLS, g_sga_stat_columns, vw_common_open, vw_sga_stat_fetch };
VW_DECL dv_sqlpool = { "SYS", "DV_SQL_POOL", SQLPOOL_COLS, g_sqlpool_columns, vw_common_open, vw_ogsql_funcpool_fetch };
VW_DECL dv_sql_execution_plan = { "SYS",
                                  "DV_SQL_EXECUTION_PLAN", SQL_PLAN_COLS,
      g_sql_execution_plan_columns, vw_ogsql_func_plan_open, vw_fetch_sql_plan };

dynview_desc_t *vw_describe_sga(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_SGA:
            return &dv_sga;

        case DYN_VIEW_SYSTEM:
            return &dv_system;

        case DYN_VIEW_TEMP_POOL:
            return &dv_temp_pool;

        case DYN_VIEW_SQLAREA:
            return &dv_sqlarea;

        case DYN_VIEW_SGASTAT:
            return &dv_sgastat;

        case DYN_VIEW_VM_FUNC_STACK:
            return &dv_vm_func_stack;

        case DYN_VIEW_SQLPOOL:
            return &dv_sqlpool;

        case DYN_VIEW_SQL_EXECUTION_PLAN:
            return &dv_sql_execution_plan;

        case DYN_VIEW_PLAREA:
            return &dv_anonymous;

        default:
            return NULL;
    }
}

