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
 * srv_param.h
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_PARAM_H__
#define __SRV_PARAM_H__
#include "cm_defs.h"
#include "cm_config.h"
#include "srv_param_def.h"
#include "ogsql_service.h"
#ifndef WIN32
#include <sys/sysinfo.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void srv_print_params(void);
void srv_get_debug_config_info(debug_config_item_t **params, uint32 *count);
status_t srv_param_change_notify(const char *name, const char *value);
char *srv_get_param(const char *name);
status_t srv_alter_arch_dest(void *arch_attr, int slot, char *value);
bool32 srv_have_ssl(void);
status_t srv_save_factor_key_file(const char *file_name, const char *value);
status_t sql_verify_als_res_recycle_ratio(void *se, void *lex, void *def);
status_t sql_verify_als_create_index_parallelism(void *se, void *lex, void *def);
status_t sql_verify_als_cpu_inf_str(void *se, void *lex, void *def);

status_t verify_uds_file_path(const char *path);
status_t verify_file_path(const char *path);
status_t verify_uds_file_permission(uint16 permission);
status_t srv_apply_param_plan_display_format(sql_instance_t *sql);
status_t sql_verify_als_plan_display_format(void *se, void *lex, void *def);
status_t sql_notify_als_plan_display_format(void *se, void *item, char *value);
status_t sql_verify_rcy_read_buf_size(void *se, void *lex, void *def);
status_t sql_verify_dtc_rcy_paral_buf_list_size(void *se, void *lex, void *def);

void srv_get_config_info(config_item_t **params, uint32 *count);
void init_runtime_params(void);
void sql_set_plan_display_format(char *str, uint32 *value);
status_t sql_normalize_plan_display_format_value(char *value, uint32 format_index, bool32 *option_flag);
status_t sql_get_plan_display_format_info(void *lex_in, uint32 *format_index, bool32 *option_flag);
#define IS_DEADLOCK_INTERVAL_PARAM_VALID(num) ((num) == 1 || (num) == 10 || (num) == 100 || (num) == 1000)

typedef enum en_plan_format_mask {
    FORMAT_MASK_ID = 0x00000001,
    FORMAT_MASK_OPERATION = 0x00000002,
    FORMAT_MASK_OWNER = 0x00000004,
    FORMAT_MASK_TABLE = 0x00000008,
    FORMAT_MASK_ROWS = 0x00000010,
    FORMAT_MASK_COST = 0x00000020,
    FORMAT_MASK_START_COST = 0x00000040,
    FORMAT_MASK_BYTES = 0x00000080,
    FORMAT_MASK_REMARK = 0x00000100,

    FORMAT_MASK_PREDICATE = 0x00000200,
    FORMAT_MASK_QUERY_BLOCK = 0x00000400,
    FORMAT_MASK_OUTLINE = 0x00000800,
} plan_format_mask_t;

#define FORMAT_MASK_CBO (FORMAT_MASK_ROWS | FORMAT_MASK_COST | FORMAT_MASK_START_COST)
#define FORMAT_MASK_SIMPLE (FORMAT_MASK_ID | FORMAT_MASK_OPERATION | FORMAT_MASK_TABLE)
#define FORMAT_MASK_BASIC (FORMAT_MASK_SIMPLE | FORMAT_MASK_OWNER | FORMAT_MASK_BYTES | FORMAT_MASK_REMARK | \
    FORMAT_MASK_CBO)
#define FORMAT_MASK_TYPICAL (FORMAT_MASK_BASIC | FORMAT_MASK_PREDICATE)
#define FORMAT_MASK_ALL (FORMAT_MASK_TYPICAL | FORMAT_MASK_QUERY_BLOCK | FORMAT_MASK_OUTLINE)

typedef struct st_plan_format {
    text_t text;
    plan_format_mask_t mask;
} plan_format_t;

#ifdef __cplusplus
}
#endif

#endif
