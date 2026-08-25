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
 * srv_param_common.h
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_PARAM_COMMON_H__
#define __SRV_PARAM_COMMON_H__

#include "cm_config.h"
#include "knl_context.h"

#define RBP_ASSEMBLE_MAX_SCAN_RANGE "[" OG_STR(RBP_ASSEMBLE_MAX_SCAN_MIN) ", " \
    OG_STR(RBP_ASSEMBLE_MAX_SCAN_MAX) "]"

#define BISON_PARAM_TOKEN_BUFFER_SIZE OG_PARAM_BUFFER_SIZE

typedef struct st_bison_sys_param_value {
    text_t text;
    text_t decoded_string;
    bool32 is_string;
    source_location_t loc;
    source_location_t extra_token_loc;
    uint32 token_count;
} bison_sys_param_value_t;

typedef struct st_bison_param_reader {
    text_t remaining;
    source_location_t loc;
} bison_param_reader_t;

typedef enum en_bison_param_token_type {
    BISON_PARAM_TOKEN_WORD = 0,
    /* SCONST/E-string/dollar-quote and a raw single-quoted token share native string semantics. */
    BISON_PARAM_TOKEN_STRING,
    /* Keep the two native DQ-style delimiters distinct so adapters can reject them explicitly. */
    BISON_PARAM_TOKEN_DQ_STRING,
    BISON_PARAM_TOKEN_BACKTICK_STRING,
    BISON_PARAM_TOKEN_PUNCTUATION
} bison_param_token_type_t;

typedef struct st_bison_param_token {
    char value[BISON_PARAM_TOKEN_BUFFER_SIZE];
    text_t text;
    bison_param_token_type_t type;
} bison_param_token_t;

#ifdef WIN32
#define SQL_BISON_VERIFY_ARGS \
    void *se, void *source, void *def, int64 min_value, int64 max_value
#else
#define SQL_BISON_VERIFY_ARGS \
    void *se, void *source, void *def, int64 min_value __attribute__((unused)), \
    int64 max_value __attribute__((unused))
#endif

typedef status_t (*sql_bison_sys_param_verify_t)(SQL_BISON_VERIFY_ARGS);

typedef struct st_sql_bison_sys_param_verifier {
    const char *name;
    sql_bison_sys_param_verify_t bison_verify;
    int64 min_value;
    int64 max_value;
} sql_bison_sys_param_verifier_t;

#ifdef __cplusplus
extern "C"
#endif

status_t sql_verify_uint32(void *lex, void *def, uint32 *num);
status_t sql_verify_als_comm(void *se, void *lex, void *def);
status_t sql_verify_als_onoff(void *se, void *lex, void *def);
status_t sql_verify_als_uint32(void *se, void *lex, void *def);
bool32 srv_match_bool_text_ext(const text_t *bool_text, bool32 *bool_value);
status_t sql_verify_als_bool(void *se, void *lex, void *def);
status_t sql_verify_als_zero_one(void *se, void *lex, void *def);
status_t sql_notify_als_bool(void *se, void *item, char *value);
status_t sql_notify_als_onoff(void *se, void *item, char *value);
char *srv_get_param(const char *name);
status_t srv_get_param_bool32(char *param_name, bool32 *param_value);
status_t srv_get_param_onoff(char *param_name, bool32 *param_value);
status_t srv_get_param_uint16(char *param_name, uint16 *param_value);
status_t srv_get_param_uint32(char *param_name, uint32 *param_value);
status_t srv_get_param_uint64(char *param_name, uint64 *param_value);
status_t srv_get_param_second(char *param_name, uint64 *param_value);
status_t srv_get_param_double(char *param_name, double *param_value);
status_t srv_get_param_size_uint32(char *param_name, uint32 *param_value);
status_t srv_get_param_size_uint64(char *param_name, uint64 *param_value);
status_t srv_verf_param_uint64(char *param_name, uint64 param_value, uint64 min_value, uint64 max_value);
status_t sql_verify_pool_size(void *lex, void *def, int64 min_size, int64 max_size);
status_t srv_get_index_auto_rebuild(char *time_str, knl_attr_t *attr);

status_t sql_bison_copy_sys_param_value(bison_sys_param_value_t *source, knl_alter_sys_def_t *def);
status_t sql_bison_store_sys_param_text(const text_t *value, knl_alter_sys_def_t *def);
status_t sql_bison_reset_sys_param_value(knl_alter_sys_def_t *def);
void sql_bison_extra_init_reader(bison_param_reader_t *reader, const text_t *value, source_location_t loc);
status_t sql_bison_extra_fetch_token(bison_param_reader_t *reader, bison_param_token_t *token, bool32 *found);
status_t sql_bison_extra_expected_end(bison_param_reader_t *reader);
status_t sql_bison_extra_get_single_token(const bison_sys_param_value_t *source, bison_param_token_t *token);
status_t sql_bison_extra_get_decoded_single_token(const bison_sys_param_value_t *source,
    bison_param_token_t *token);
status_t sql_bison_extra_expected_fetch_1of2(const bison_sys_param_value_t *source, const char *word1,
    const char *word2, uint32 *matched_id);
status_t sql_bison_extra_expected_fetch_1of3(const bison_sys_param_value_t *source, const char *word1,
    const char *word2, const char *word3, uint32 *matched_id);
status_t sql_bison_extra_expected_fetch_1ofn(const bison_sys_param_value_t *source, uint32 *matched_id,
    int num, ...);
status_t sql_bison_extra_expected_fetch_word(const bison_sys_param_value_t *source, const char *word);
status_t sql_bison_extra_parse_uint32(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def, uint32 *value);
status_t sql_bison_extra_verify_pool_size(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def,
    int64 min_size, int64 max_size);
status_t sql_bison_verify_pool_size(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_parse_plan_display_format(const bison_sys_param_value_t *source, uint32 *value);
status_t sql_bison_extra_parse_real(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def, double *value);
status_t sql_bison_extra_parse_size(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def, int64 *value);
status_t sql_bison_skip_sys_param_separators(text_t *remaining, source_location_t loc);
status_t sql_bison_verify_bool(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_zero_one(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_comm(SQL_BISON_VERIFY_ARGS);

/* Common. */
status_t sql_bison_verify_uint32_range(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_onoff(SQL_BISON_VERIFY_ARGS);

/* Kernel. */
status_t sql_bison_verify_cpu_node_bind(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_active_undo_segments(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_auto_index_recycle(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_auton_trans_segments(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_checkpoint_io_capacity(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_commit_logging(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_commit_wait(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_compress_algo(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_compress_buf_size(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_cr_mode(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_ctrllog_backup_level(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_db_block_checksum(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_db_isolevel(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_default_extents(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_default_space_type(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_filesystemio_options(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_idx_duplicate_enable(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_index_auto_rebuild_start_time(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_max_column_count(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_max_rm_count(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_page_clean_mode(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_page_clean_ratio(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_page_size(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_qos_ctrl_fat(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_repl_max_pkg_size(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_row_format(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_sql_pool_fat(SQL_BISON_VERIFY_ARGS);

/* Other server parameters. */
status_t sql_bison_verify_repl_port(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_rbp_ip(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_local_rbp_host(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_verify_rbp_bool(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_arch_lower_limit(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_arch_upper_limit(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_convert(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_have_ssl(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_ip(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_lob_max_exec_size(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_log_archive_config(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_node_lock_status(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_quorum_any(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_reserved_sql_cursors(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_sql_compat(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_ssl_cipher(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_ssl_file(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_statistics_level(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_withas_subquery(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_ssl_alt_threshold(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_ssl_period_detection(SQL_BISON_VERIFY_ARGS);

/* Server. */
status_t sql_bison_extra_als_bool_only_sys_allowed(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_db_tz(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_deadlock_detect_interval(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_encryption_alg(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_factor_key(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_interconnect_port(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_interconnect_type(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_local_key(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_mes_task_ratio(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_sessions(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_sys_password(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_uds_file_path(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_uds_file_permissions(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_xa_format_id(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_normal_emerge_sess_factor(SQL_BISON_VERIFY_ARGS);

/* Raft and log. */
status_t sql_bison_verify_log_level(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_audit_syslog_level(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_audit_trail_mode(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_file_dir(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_log_archive_dest_n(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_log_archive_dest_state_n(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_log_file(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_log_path(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_raft_priority_type(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_raft_tls_dir(SQL_BISON_VERIFY_ARGS);
status_t sql_bison_extra_als_raft_token_verify(SQL_BISON_VERIFY_ARGS);
/* DDL-owned parameters. */
status_t sql_bison_extra_als_cpu_inf_str(SQL_BISON_VERIFY_ARGS);

#ifdef __cplusplus
}
#endif

#endif
