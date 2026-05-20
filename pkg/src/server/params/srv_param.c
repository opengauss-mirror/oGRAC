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
 * srv_param.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "ogsql_stmt.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "set_kernel.h"
#include "set_server.h"
#include "set_others.h"
#include "cbo_base.h"
#include "srv_device_adpt.h"
#include "srv_params_raft_and_log.h"
#include "ddl_parser.h"
#include "dtc_rbp_rt_aly.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RBP_RT_PARSE_WORKERS_RANGE "[1, " OG_STR(DTC_RBP_RT_MAX_PARSE_WORKERS) "]"
#define RBP_RT_PAGE_OWNER_WORKERS_RANGE "[1, " OG_STR(DTC_RBP_RT_MAX_OWNER_WORKERS) "]"

// CAUTION !!! if add/del/modify g_parameter in srv_param.c,please reorder the id in srv_param_def.h
config_item_t g_parameters[] = {
    // name (30B)                    isdefault attr  defaultvalue     value runtime_value description range datatype
    // comment
    // -------------                 --------- ----  ------------     ----- ------------- ----------- ----- --------
    // -------
    { "LSNR_ADDR", OG_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LSNR_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "LSNR_PORT", OG_TRUE, ATTR_NONE, "1611", NULL, NULL, "-", "[1024,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM_LSNR_PORT, EFFECT_REBOOT, CFG_INS, sql_verify_als_port, NULL, NULL, NULL },
    { "WORKER_THREADS", OG_TRUE, ATTR_HIDDEN, "100", NULL, NULL, "-", "[0,10000)", "OG_TYPE_INTEGER", NULL,
      PARAM_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_worker_threads, NULL, NULL, NULL },
    { "OPTIMIZED_WORKER_THREADS", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[2,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_OPTIMIZED_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_optimized_worker_threads, NULL, NULL,
      NULL },
    { "MAX_WORKER_THREADS", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[2,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_worker_threads, NULL, NULL, NULL },
    { "REACTOR_THREADS", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_REACTOR_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_reactor_threads, NULL, NULL, NULL },
    { "SQL_COMPAT", OG_TRUE, ATTR_NONE, "OGDB", NULL, NULL, "-", "OGDB", "OG_TYPE_VARCHAR", NULL, PARAM_SQL_COMPAT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_sql_compat, sql_notify_als_sql_compat, sql_notify_als_sql_compat, NULL },
    { "DATA_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[64M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_DATA_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_data_buffer_size, NULL, NULL, NULL },
    { "VARIANT_MEMORY_AREA_SIZE", OG_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[4M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_VMA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_vma_size, NULL, NULL, NULL },
    { "LARGE_VARIANT_MEMORY_AREA_SIZE", OG_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[1M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_LARGE_VMA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_large_vma_size, NULL, NULL, NULL },
    { "_VMP_CACHES_EACH_SESSION", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM__VMP_CACHES_EACH_SESS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_vmp_caches, NULL,
      NULL },
    { "_VMA_MEM_CHECK", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_VMA_MEM_CHECK, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "PMA_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[0,1T]", "OG_TYPE_INTEGER", NULL, PARAM_PMA_SIZE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_pma_buf_size, NULL, NULL, NULL },
    { "HASH_AREA_SIZE", OG_TRUE, ATTR_NONE, "4M", NULL, NULL, "-", "[0,1T]", "OG_TYPE_INTEGER", NULL,
      PARAM_HASH_AREA_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_hash_area_size, sql_notify_als_hash_area_size,
      NULL, NULL },
    { "SHARED_POOL_SIZE", OG_TRUE, ATTR_NONE, "192M", NULL, NULL, "-", "[82M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_SHARED_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_shared_pool_size, NULL, NULL, NULL },
    { "_SQL_POOL_FACTOR", OG_TRUE, ATTR_NONE, "0.3", NULL, NULL, "-", "[0.001,0.999]", "OG_TYPE_REAL", NULL,
      PARAM_SQL_POOL_FACTOR, EFFECT_REBOOT, CFG_INS, sql_verify_als_sql_pool_fat, NULL, NULL, NULL },
    { "LARGE_POOL_SIZE", OG_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[4M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_LARGE_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_large_pool_size, NULL, NULL, NULL },
    { "LOG_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "4M", NULL, NULL, "-", "[1M,1024M]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_buffer_size, NULL, NULL, NULL },
    { "LOG_BUFFER_COUNT", OG_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "(0,64]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_BUFFER_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_buffer_count, NULL, NULL, NULL },
    { "TEMP_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[32M,4T]", "OG_TYPE_INTEGER", NULL,
      PARAM_TEMP_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_temp_buffer_size, NULL, NULL, NULL },
    { "USE_LARGE_PAGES", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_USE_LARGE_PAGES, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "USE_NATIVE_DATATYPE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_USE_NATIVE_DATATYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "JOB_THREADS", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,200]", "OG_TYPE_INTEGER", NULL,
      PARAM_JOB_QUEUE_PROCESSES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_job_queue_processes, NULL, NULL,
      "JOB_QUEUE_PROCESSES" },
    { "CR_POOL_SIZE", OG_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[16M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_CR_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_pool_size, NULL, NULL, NULL },
    { "CR_POOL_COUNT", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,256]", "OG_TYPE_INTEGER", NULL,
      PARAM_CR_POOL_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_pool_count, NULL, NULL, NULL },
    { "DEFAULT_TABLESPACE_TYPE", OG_TRUE, ATTR_NONE, "NORMAL", NULL, NULL, "-", "NORMAL,BITMAP", "OG_TYPE_VARCHAR",
      NULL, PARAM_DEFAULT_SPACE_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_default_space_type, NULL, NULL, NULL },
    { "BUFFER_PAGE_CLEAN_PERIOD", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_BUFFER_PAGE_CLEAN_PERIOD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_period,
      sql_notify_als_page_clean_period, NULL, NULL },
    { "BUFFER_LRU_SEARCH_THRE", OG_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[1,100]", "OG_TYPE_INTEGER", NULL,
      PARAM_BUFFER_LRU_SEARCH_THRE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lru_search_threshold,
      sql_notify_als_lru_search_threshold, NULL, NULL },
    { "BUFFER_PAGE_CLEAN_RATIO", OG_TRUE, ATTR_NONE, "0.4", NULL, NULL, "-", "[0.0001,1]", "OG_TYPE_REAL", NULL,
      PARAM_BUFFER_PAGE_CLEAN_RATIO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_ratio,
      sql_notify_als_page_clean_ratio, NULL, NULL },
    { "_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER",
      NULL, PARAM_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_wait_timeout,
      sql_notify_als_page_clean_wait_timeout, NULL, NULL },
    { "_CHECKPOINT_TIMED_TASK_DELAY", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER",
      NULL, PARAM_CKPT_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_wait_timeout,
      sql_notify_als_ckpt_wait_timeout, NULL, NULL },
    // hidden parameter
    { "_SPIN_COUNT", OG_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM__SPIN_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "_ENABLE_QOS", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__ENABLE_QOS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_qos,
      sql_notify_als_bool, NULL },
    { "_QOS_CTRL_FACTOR", OG_TRUE, ATTR_NONE, "0.75", NULL, NULL, "-", "(0,5]", "OG_TYPE_REAL", NULL,
      PARAM__QOS_CTRL_FACTOR, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_ctrl_fat, sql_notify_als_qos_ctrl, NULL,
      NULL },
    { "_QOS_SLEEP_TIME", OG_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM__QOS_SLEEP_TIME, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_slee_time, sql_notify_als_qos_sleep_time, NULL,
      NULL },
    { "_QOS_RANDOM_RANGE", OG_TRUE, ATTR_NONE, "64", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM__QOS_RANDOM_RANGE, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_rand_range, sql_notify_als_qos_random_range,
      NULL, NULL },
    { "_INDEX_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "8M", NULL, NULL, "-", "[16K,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM__INDEX_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_index_buffer_size, NULL, NULL, NULL },
    { "_INDEX_AUTO_REBUILD", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "_", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__INDEX_AUTO_REBUILD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_index_auto_rebuild,
      sql_notify_als_bool, NULL },
    { "_INDEX_AUTO_REBUILD_START_TIME", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM__INDEX_AUTO_REBUILD_START_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_auto_rebuild_start_time,
      NULL, NULL, NULL },
    { "_AUTO_INDEX_RECYCLE", OG_TRUE, ATTR_NONE, "ON", NULL, NULL, "_", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM__AUTO_INDEX_RECYCLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_auto_index_recycle,
      sql_notify_als_auto_index_recycle, NULL, NULL },
    { "_INDEX_RECYCLE_PERCENT", OG_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,100]", "OG_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_PERCENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_percent,
      sql_notify_als_index_recycle_percent, NULL, NULL },
    { "_INDEX_RECYCLE_SIZE", OG_TRUE, ATTR_NONE, "2G", NULL, NULL, "_", "[4M,1T]", "OG_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_size,
      sql_notify_als_index_recycle_size, NULL, NULL },
    { "_FORCE_INDEX_RECYCLE", OG_TRUE, ATTR_NONE, "14400", NULL, NULL, "_", "[0,172800]", "OG_TYPE_INTEGER", NULL,
      PARAM__FORCE_INDEX_RECYCLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_force_index_recycle,
      sql_notify_als_force_index_recycle, NULL, NULL },
    { "_INDEX_RECYCLE_REUSE", OG_TRUE, ATTR_NONE, "512", NULL, NULL, "_", "[0,172800000]", "OG_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_REUSE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_reuse,
      sql_notify_als_index_recycle_reuse, NULL, NULL },
    { "_INDEX_REBUILD_KEEP_STORAGE", OG_TRUE, ATTR_NONE, "43200", NULL, NULL, "_", "[0,172800]", "OG_TYPE_INTEGER",
      NULL, PARAM__INDEX_REBUILD_KEEP_STORAGE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_rebuild_keep_storage,
      sql_notify_als_index_rebuild_keep_storage, NULL, NULL },
    { "_DOUBLEWRITE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__DOUBLEWRITE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_double_write,
      sql_notify_als_bool, NULL },
    { "_THREAD_STACK_SIZE", OG_TRUE, ATTR_NONE, "512K", NULL, NULL, "-", "[256K,7.5M]", "OG_TYPE_INTEGER", NULL,
      PARAM__THREAD_STACK_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_thread_stack_size, NULL, NULL, NULL },
    { "_BLACKBOX_STACK_DEPTH", OG_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[2, 40]", "OG_TYPE_INTEGER", NULL,
      PARAM__BLACK_BOX_DEPTH, EFFECT_REBOOT, CFG_INS, sql_verify_als_black_box_depth, NULL, NULL, NULL },
    { "_HINT_FORCE", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-",
      "0 disables, [1,2,4,8]=[ORDERED,USE_NL,USE_MERGE,USE_HASH]", "OG_TYPE_INTEGER", NULL, PARAM__FORCE_HINT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als__hint_force, NULL, NULL },
    { "_RCY_CHECK_PCN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__RCY_CHECK_PCN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_rcy_check_pcn,
      sql_notify_als_bool, NULL },
    { "_SGA_CORE_DUMP_CONFIG", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM__SGA_CORE_DUMP_CONFIG, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sga_core_dump_config,
      sql_notify_als_sga_core_dump_config, NULL, NULL },
    { "_MAX_RM_COUNT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,24480]", "OG_TYPE_INTEGER", NULL,
      PARAM__MAX_RM_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_rm_count, NULL, NULL, NULL },
    { "_SMALL_TABLE_SAMPLING_THRESHOLD", OG_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[0,100000]", "OG_TYPE_INTEGER",
      NULL, PARAM__SMALL_TABLE_SAMPLING_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_small_table_sampling_threshold, sql_notify_als_small_table_sampling_threshold, NULL, NULL },
    { "_ASHRINK_WAIT_TIME", OG_TRUE, ATTR_NONE, "21600", NULL, NULL, "-", "[1,172800]", "OG_TYPE_INTEGER", NULL,
      PARAM__ASHRINK_WAIT_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ashrink_wait_time,
      sql_notify_als_ashrink_wait_time, NULL, NULL },
    { "_SHRINK_WAIT_RECYCLED_PAGES", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[0,13107200]", "OG_TYPE_INTEGER",
      NULL, PARAM__SHRINK_WAIT_RECYCLED_PAGES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_shrink_wait_recycled_pages,
      sql_notify_als_shrink_wait_recycled_pages, NULL, NULL },
    { "_TEMPTABLE_SUPPORT_BATCH_INSERT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM__TEMPTABLE_SUPPORT_BATCH_INSERT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_temptable_support_batch, sql_notify_als_bool, NULL },
    /* *************************************************************************
    agent parameters,
    private area size = (_AGENT_STACK_SIZE
    + PLOG_PAGES * PAGE_SIZE(8K) + _VARIANT_AREA_SIZE + _INIT_SQL_CURSORS * 1K
    + _INIT_TABLE_CURSORS * (2 * PAGE_SIZE(8K) + 12K))
    if page size is 8K, about 2M
    ************************************************************************* */
    { "_AGENT_STACK_SIZE", OG_TRUE, ATTR_NONE, "2M", NULL, NULL, "-", "[512K,4G)", "OG_TYPE_INTEGER", NULL,
      PARAM__AGENT_STACK_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_stack_size, NULL, NULL, NULL },
    { "_LOB_MAX_EXEC_SIZE", OG_TRUE, ATTR_NONE, "65534", NULL, NULL, "-", "[0,4G)", "OG_TYPE_INTEGER", NULL,
      PARAM__LOB_MAX_EXEC_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lob_max_exec_size, NULL, NULL, NULL },
    // parameter/scan_range variants for stmt which have pending result set
    { "_VARIANT_AREA_SIZE", OG_TRUE, ATTR_NONE, "256K", NULL, NULL, "-", "[256K,64M]", "OG_TYPE_INTEGER", NULL,
      PARAM__VARIANT_AREA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_variant_size, NULL, NULL, NULL },
    // cached knl_cursor
    { "_INIT_CURSORS", OG_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[0,256]", "OG_TYPE_INTEGER", NULL,
      PARAM__INIT_CURSORS, EFFECT_REBOOT, CFG_INS, sql_verify_als_init_cursors, NULL, NULL, NULL },
    { "_DISABLE_SOFT_PARSE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__DISABLE_SOFT_PARSE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_disable_soft_parse,
      sql_notify_als_bool, NULL },
    /* limitations */
    { "SESSIONS", OG_TRUE, ATTR_NONE, "200", NULL, NULL, "-", "[59,19380]", "OG_TYPE_INTEGER", NULL, PARAM_SESSIONS,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sessions, NULL, NULL, NULL },
    { "KNL_AUTONOMOUS_SESSIONS", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "(0,256]", "OG_TYPE_INTEGER", NULL,
      PARAM_KNL_AUTONOMOUS_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_autonomous_sessions, NULL, NULL, NULL },
    { "AUTONOMOUS_SESSIONS", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "(0,256]", "OG_TYPE_INTEGER", NULL,
      PARAM_AUTONOMOUS_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_autonomous_sessions, NULL, NULL, NULL },
    { "SUPER_USER_RESERVED_SESSIONS", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[1,32]", "OG_TYPE_INTEGER", NULL,
      PARAM_SUPER_USER_RESERVED_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_super_user_sessions, NULL },
    { "NORMAL_USER_RESERVED_SESSIONS_FACTOR", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,1]", "OG_TYPE_REAL", NULL,
      PARAM_NORMAL_USER_RESERVED_SESSION_FACTOR, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_normal_emerge_sess_factor,
      sql_notify_als_normal_emerge_sess_factor, NULL, NULL },
    // same with oracle, max statements per session
    { "OPEN_CURSORS", OG_TRUE, ATTR_NONE, "2000", NULL, NULL, "-", "[1,16384]", "OG_TYPE_INTEGER", NULL,
      PARAM_OPEN_CURSORS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_open_curs, sql_notify_als_open_curs, NULL, NULL },
    { "_PREFETCH_ROWS", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM_PREFETCH_ROWS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_prefetch_rows, sql_notify_als_prefetch_rows,
      NULL, NULL },
    /* database */
    { "PAGE_SIZE", OG_TRUE, ATTR_READONLY, "8K", NULL, NULL, "-", "8K,16K,32K", "OG_TYPE_VARCHAR", NULL,
      PARAM_PAGE_SIZE, EFFECT_REBOOT, CFG_DB, sql_verify_als_page_size, NULL, NULL, NULL }, // read only, must be same
                                                                                            // with the page size which
                                                                                            // d
    { "COMMIT_MODE", OG_TRUE, ATTR_NONE, "IMMEDIATE", NULL, NULL, "-", "BATCH,IMMEDIATE", "OG_TYPE_VARCHAR", NULL,
      PARAM_COMMIT_LOGGING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_commit_logging, sql_notify_als_commit_mode,
      NULL, "COMMIT_LOGGING" }, // same with oracle, IMMEDIATE | BATCH
    { "COMMIT_WAIT_LOGGING", OG_TRUE, ATTR_NONE, "WAIT", NULL, NULL, "-", "WAIT,NOWAIT", "OG_TYPE_VARCHAR", NULL,
      PARAM_COMMIT_WAIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_commit_wait, sql_notify_als_commit_wait_logging,
      NULL, "COMMIT_WAIT" }, // same with oracle, WAIT | NOWAIT
    { "CONTROL_FILES", OG_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_CONTROL_FILES,
      EFFECT_REBOOT, CFG_DB, sql_verify_als_comm, NULL, NULL, NULL },
    { "KMC_KEY_FILES", OG_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_KMC_KEY_FILES,
      EFFECT_REBOOT, CFG_DB, sql_verify_als_comm, NULL, NULL, NULL },
    { "PAGE_CHECKSUM", OG_TRUE, ATTR_NONE, "TYPICAL", NULL, NULL, "-", "OFF,TYPICAL,FULL", "OG_TYPE_VARCHAR", NULL,
      PARAM_DB_BLOCK_CHECKSUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_db_block_checksum, NULL, NULL,
      "DB_BLOCK_CHECKSUM" }, // OFF | TYPICAL | FULL
    { "DB_ISOLEVEL", OG_TRUE, ATTR_NONE, "RC", NULL, NULL, "-", "RC,CC", "OG_TYPE_VARCHAR", NULL, PARAM_DB_ISOLEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_db_isolevel, sql_notify_als_db_isolevel,
      sql_notify_als_db_isolevel_value, NULL },
    { "_SERIALIZED_COMMIT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__SERIALIZED_COMMIT, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "ARCHIVE_CONFIG", OG_TRUE, ATTR_READONLY, "SEND,RECEIVE,NODG_CONFIG", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR",
      NULL, PARAM_LOG_ARCHIVE_CONFIG, EFFECT_REBOOT, CFG_DB, sql_verify_als_log_archive_config, NULL, NULL,
      "LOG_ARCHIVE_CONFIG" },
    { "ARCHIVE_DEST_1", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_1,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_1" },
    { "ARCHIVE_DEST_2", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_2,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_2" },
    { "ARCHIVE_DEST_3", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_3,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_3" },
    { "ARCHIVE_DEST_4", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_4,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_4" },
    { "ARCHIVE_DEST_5", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_5,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_5" },
    { "ARCHIVE_DEST_6", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_6,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_6" },
    { "ARCHIVE_DEST_7", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_7,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_7" },
    { "ARCHIVE_DEST_8", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_8,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_8" },
    { "ARCHIVE_DEST_9", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_9,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_9" },
    { "ARCHIVE_DEST_10", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_LOG_ARCHIVE_DEST_10, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n,
      sql_notify_als_archive_dest_n, NULL, "LOG_ARCHIVE_DEST_10" },
    { "ARCHIVE_DEST_STATE_1", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_1, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_1" },
    { "ARCHIVE_DEST_STATE_2", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_2, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_2" },
    { "ARCHIVE_DEST_STATE_3", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_3, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_3" },
    { "ARCHIVE_DEST_STATE_4", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_4, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_4" },
    { "ARCHIVE_DEST_STATE_5", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_5, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_5" },
    { "ARCHIVE_DEST_STATE_6", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_6, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_6" },
    { "ARCHIVE_DEST_STATE_7", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_7, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_7" },
    { "ARCHIVE_DEST_STATE_8", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_8, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_8" },
    { "ARCHIVE_DEST_STATE_9", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_9, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_9" },
    { "ARCHIVE_DEST_STATE_10", OG_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_10, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_10" },
    { "ARCHIVE_FORMAT", OG_TRUE, ATTR_NONE, "arch_%t_%r_%s.arc", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_LOG_ARCHIVE_FORMAT, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_archive_format, NULL,
      "LOG_ARCHIVE_FORMAT" },
    { "ARCHIVE_FORMAT_WITH_LSN", OG_TRUE, ATTR_NONE, "arch_%t_%r_%s_%d_%e.arc", NULL, NULL, "-", "-",
      "OG_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_FORMAT_WITH_LSN, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm,
      sql_notify_als_archive_format_with_lsn, NULL, "LOG_ARCHIVE_FORMAT"},
    { "ARCHIVE_MAX_THREADS", OG_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_MAX_PROCESSES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_max_min,
      sql_notify_als_archive_max_processes, NULL, "LOG_ARCHIVE_MAX_PROCESSES" },
    { "ARCHIVE_MIN_SUCCEED_DEST", OG_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_MIN_SUCCEED_DEST, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_archive_max_min,
      sql_notify_als_archive_min_succeed, NULL, "LOG_ARCHIVE_MIN_SUCCEED_DEST" },
    { "ARCHIVE_TRACE", OG_TRUE, ATTR_READONLY, "0", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_TRACE, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, sql_notify_als_archive_trace, NULL,
      "LOG_ARCHIVE_TRACE" },
    { "ENABLE_ARCH_COMPRESS", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ARCH_COMPRESS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_arch_compressed, sql_notify_als_enable_arch_compressed, NULL },
    { "QUORUM_ANY", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 9]", "OG_TYPE_INTEGER", NULL, PARAM_QUORUM_ANY,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_quorum_any, sql_notify_als_quorum_any, NULL, NULL },
    /* checkpoint */
    { "CHECKPOINT_PERIOD", OG_TRUE, ATTR_NONE, "300", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_timeout,
      sql_notify_als_ckpt_period, NULL, "CHECKPOINT_TIMEOUT" }, // awake checkpoint thread if interval reached
    { "CHECKPOINT_PAGES", OG_TRUE, ATTR_NONE, "100000", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_INTERVAL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_interval,
      sql_notify_als_ckpt_pages, NULL, "CHECKPOINT_INTERVAL" }, // awake checkpoint thread if dirty page count reached
    { "CHECKPOINT_IO_CAPACITY", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[1,4096]", "OG_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_IO_CAPACITY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_io_capacity,
      sql_notify_als_ckpt_io_capacity, NULL, NULL },
    { "_CHECKPOINT_MERGE_IO", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM__CHECKPOINT_MERGE_IO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ckpt_merge_io,
      sql_notify_als_bool, NULL },
    { "CHECKPOINT_GROUP_SIZE", OG_TRUE, ATTR_NONE, "4096", NULL, NULL, "-", "[1,8192]", "OG_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_GROUP_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_ckpt_group_size,
      NULL, NULL, NULL },
    { "LOG_REPLAY_PROCESSES", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_REPLAY_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_rcy_params, NULL, NULL, NULL },
    { "REPLAY_PRELOAD_PROCESSES", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_REPLAY_PRELOAD_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_rcy_preload_process, NULL, NULL, NULL },
    { "_RCY_SLEEP_INTERVAL", OG_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[1,1024]", "OG_TYPE_INTEGER", NULL,
      PARAM__RCY_SLEEP_INTERVAL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_rcy_sleep_interval,
      sql_notify_als_rcy_sleep_interval, NULL, NULL },
    { "TIMED_STATS", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_TIMED_STATISTICS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_timed_stat,
      sql_notify_als_bool, "TIMED_STATISTICS" }, // same with oracle
    { "STATS_LEVEL", OG_TRUE, ATTR_NONE, "TYPICAL", NULL, NULL, "-", "ALL,TYPICAL,BASIC", "OG_TYPE_VARCHAR", NULL,
      PARAM_STATISTICS_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_statistics_level, sql_notify_als_stats_level,
      NULL, "STATISTICS_LEVEL" }, // same with oracle
    { "DBWR_PROCESSES", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[1,36]", "OG_TYPE_INTEGER", NULL,
      PARAM_DBWR_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_dbwr_processes, NULL, NULL, NULL },
    { "SQL_STAT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL, PARAM_SQL_STAT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_sql_stat, sql_notify_als_bool, NULL },
    { "INSTANCE_NAME", OG_TRUE, ATTR_NONE, "oGRAC", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_INSTANCE_NAME,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "ALARM_LOG_DIR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_ALARM_LOG_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "REPL_ADDR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_REPL_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "REPL_PORT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "0,[1024,65535]", "OG_TYPE_INTEGER", NULL, PARAM_REPL_PORT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_repl_port, NULL, NULL, NULL },
    { "REPL_TRUST_HOST", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_REPL_TRUST_HOST,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ip, sql_notify_als_repl_host, NULL, NULL },
    { "REPL_AUTH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL, PARAM_REPL_AUTH,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "REPL_SCRAM_AUTH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_REPL_SCRAM_AUTH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "_REPL_MAX_PKG_SIZE", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "0,[512K,8M]", "OG_TYPE_INTEGER", NULL,
      PARAM__REPL_MAX_PKG_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_repl_max_pkg_size,
      sql_notify_als_repl_max_pkg_size, NULL, NULL },
    /* file & space */
    { "FILE_OPTIONS", OG_TRUE, ATTR_NONE, "NONE", NULL, NULL, "",
      "NONE,DIRECTIO,FULLDIRECTIO,ASYNCH,DSYNC,FDATASYNC,SETALL", "OG_TYPE_VARCHAR", NULL, PARAM_FILESYSTEMIO_OPTIONS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_filesystemio_options, NULL, NULL, "FILESYSTEMIO_OPTIONS" },
    { "BUILD_DATAFILE_PARALLEL", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_BUILD_DATAFILE_PARALLEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_build_datafile_paral,
      sql_notify_als_bool, NULL },
    { "ENABLE_TEMP_SPACE_BITMAP", OG_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_ENABLE_TEMP_SPACE_BITMAP, EFFECT_REBOOT, CFG_DB, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "BUILD_DATAFILE_PREALLOCATE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_BUILD_DATAFILE_PREALLOCATE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_build_datafile_prealloc, sql_notify_als_bool, NULL },
    /* auth */
    { "_ENCRYPTION_ALG", OG_TRUE, ATTR_NONE, "SCRAM_SHA256", NULL, NULL, "-", "SCRAM_SHA256", "OG_TYPE_VARCHAR", NULL,
      PARAM_ENCRYPTION_ALG, EFFECT_REBOOT, CFG_INS, sql_verify_als_encryption_alg, NULL, NULL, NULL },
    { "_SYS_PASSWORD", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SYS_PASSWORD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_sys_password, sql_notify_als_sys_password, NULL, NULL },
    { "TC_LEVEL", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL, PARAM_TC_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_tc_level, NULL, NULL },
    /* audit */
    { "AUDIT_LEVEL", OG_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[0,255]", "OG_TYPE_INTEGER", NULL, PARAM_AUDIT_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_level, sql_notify_als_audit_level, NULL, NULL },
    { "AUDIT_TRAIL_MODE", OG_TRUE, ATTR_NONE, "FILE", NULL, NULL, "-", "ALL,FILE,DB,SYSLOG,NONE", "OG_TYPE_VARCHAR",
      NULL, PARAM_AUDIT_TRAIL_MODE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_trail_mode,
      sql_notify_als_audit_trail_mode, NULL, NULL },
    { "AUDIT_SYSLOG_LEVEL", OG_TRUE, ATTR_NONE, "LOCAL0.DEBUG", NULL, NULL, "-", "", "OG_TYPE_VARCHAR", NULL,
      PARAM_AUDIT_SYSLOG_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_syslog_level,
      sql_notify_als_audit_syslog_level, NULL, NULL },
    { "LOG_HOME", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_LOG_HOME, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "_LOG_BACKUP_FILE_COUNT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_BACKUP_FILE_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_backup_file_count,
      sql_notify_als_log_backup_file_count, NULL, NULL },
    { "_AUDIT_BACKUP_FILE_COUNT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_AUDIT_BACKUP_FILE_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_backup_file_count,
      sql_notify_als_audit_backup_file_count, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE", OG_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_MAX_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_log_file_size, sql_notify_als_log_max_file_size,
      NULL, NULL },
    { "_AUDIT_MAX_FILE_SIZE", OG_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "OG_TYPE_INTEGER", NULL,
      PARAM_AUDIT_MAX_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_audit_file_size,
      sql_notify_als_audit_max_file_size, NULL, NULL },
    { "_LOG_LEVEL", OG_TRUE, ATTR_NONE, "7", NULL, NULL, "-", "[0,16712567]", "OG_TYPE_INTEGER", NULL, PARAM_LOG_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_level, sql_notify_als_log_level, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS", OG_TRUE, ATTR_NONE, "640", NULL, NULL, "-", "[600-777]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_FILE_PERMISSIONS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_file,
      sql_notify_als_log_file_permissions, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS", OG_TRUE, ATTR_NONE, "750", NULL, NULL, "-", "[700-777]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOG_PATH_PERMISSIONS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_path,
      sql_notify_als_log_path_permissions, NULL, NULL },
    { "UNDO_RESERVE_SIZE", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[64,1024]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_RESERVE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_reserve_size,
      sql_notify_als_undo_reserve_size, NULL, NULL },
    { "UNDO_RETENTION_TIME", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "(0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_RETENTION_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_retention_time,
      sql_notify_als_undo_retention_time, NULL, NULL },
    { "INDEX_DEFER_RECYCLE_TIME", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0, -)", "OG_TYPE_INTEGER", NULL,
      PARAM_INDEX_DEFER_RECYCLE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_index_defer_recycle_time, NULL, NULL },
    { "_UNDO_SEGMENTS", OG_TRUE, ATTR_READONLY, "32", NULL, NULL, "-", "(1, 4096]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_SEGMENTS, EFFECT_REBOOT, CFG_DB, sql_verify_als_undo_segments, NULL, NULL, NULL },
    { "_UNDO_ACTIVE_SEGMENTS", OG_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "(1, 4096]", "OG_TYPE_INTEGER", NULL,
      PARAM_ACTIVE_UNDO_SEGMENTS, EFFECT_IMMEDIATELY, CFG_DB, sql_verify_als_active_undo_segments,
      sql_notify_als_active_undo_segments, NULL, NULL },
    { "_UNDO_AUTON_TRANS_SEGMENTS", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1, 1024)", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_AUTON_TRANS_SEGMENTS, EFFECT_IMMEDIATELY, CFG_DB, sql_verify_als_auton_trans_segments,
      sql_notify_als_auton_trans_segments, NULL, NULL },
    { "_UNDO_AUTON_BIND_OWN_SEGMENT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_UNDO_AUTON_BIND_OWN_SEGMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_undo_auton_bind_own_seg, sql_notify_als_bool, NULL },
    { "_UNDO_AUTO_SHRINK", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_UNDO_AUTO_SHRINK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_undo_auto_shrink,
      sql_notify_als_bool, NULL },
    { "_UNDO_AUTO_SHRINK_INACTIVE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_UNDO_AUTO_SHRINK_INACTIVE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_undo_auto_shrink_inactive, sql_notify_als_bool, NULL },
    { "UNDO_PREFETCH_PAGE_NUM", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "(0,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_PREFETCH_PAGE_NUM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_prefetch_pages,
      sql_notify_als_undo_prefetch_pages, NULL, NULL },
    { "_UNDO_PERF_PREALLOC", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_UNDO_PERF_PREALLOC, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_undo_perf_prealloc, sql_notify_als_bool, NULL },
    { "_UNDO_PREALLOC_PAGES", OG_TRUE, ATTR_NONE, "4096", NULL, NULL, "-", "[0,65536]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_PREALLOC_PAGES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_prealloc_pages,
      sql_notify_als_undo_prealloc_pages, NULL, NULL },
    { "_TX_ROLLBACK_PROC_NUM", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1, 2]", "OG_TYPE_INTEGER", NULL,
      PARAM_TX_ROLLBACK_PROC, EFFECT_REBOOT, CFG_INS, sql_verify_als_rollback_proc_num, NULL, NULL, NULL },
    { "REPL_WAIT_TIMEOUT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[3, -)", "OG_TYPE_INTEGER", NULL,
      PARAM_REPL_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_repl_wait_timeout,
      sql_notify_als_repl_timeout, NULL, NULL },
    { "COMMIT_ON_DISCONNECT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_COMMIT_ON_DISCONN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_commit_on_disconn,
      sql_notify_als_bool, NULL },
    { "_MAX_CONNECT_BY_LEVEL", OG_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM_MAX_CONNECT_BY_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_max_connect_by_level, NULL, NULL },
    { "BACKUP_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[8M,512M]", "OG_TYPE_INTEGER", NULL,
      PARAM_BACKUP_BUFFER_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_backup_buf_size,
      sql_notify_als_backup_buf_size, NULL, NULL },
    { "RESTORE_ARCH_COMPRESSED", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_RESTORE_ARCH_COMPRESSED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_restore_arch_compressed, sql_notify_als_bool, NULL },
    { "_INDEX_SCAN_RANGE_CACHE", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,2000]", "OG_TYPE_INTEGER", NULL,
      PARAM_INDEX_SCAN_RANGE_CACHE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_range_cache,
      sql_notify_als_min_range_cache, NULL, NULL },

    { "_RESTORE_CHECK_VERSION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_RESTORE_CHECK_VERSION, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "RESTOR_ARCH_PREFER_BAK_SET", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_RESTOR_ARCH_PREFER_BAK_SET, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "NBU_BACKUP_TIMEOUT", OG_TRUE, ATTR_NONE, "90", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_NBU_BACKUP_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_nbu_backup_timeout,
      sql_notify_als_nbu_backup_timeout, NULL, NULL },
    { "_CHECK_SYSDATA_VERSION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_CHECK_SYSDATA_VERSION, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "MAX_ARCH_FILES_SIZE", OG_TRUE, ATTR_NONE, "60G", NULL, NULL, "-", "[0,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_ARCHIVE_FILES_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_size, sql_notify_als_arch_size, NULL,
      NULL },
    { "ARCH_LOG_CHECK", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_LOG_CHECK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "ARCH_FILE_SIZE", OG_TRUE, ATTR_NONE, "10G", NULL, NULL, "-", "[512M,10G]", "OG_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_file_size,
      sql_notify_als_need_arch_file_size, NULL, NULL },
    { "ARCH_SIZE", OG_TRUE, ATTR_NONE, "512M", NULL, NULL, "-", "[0,512MB]", "OG_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_size, sql_notify_als_need_arch_size, NULL,
      NULL },
    { "ARCH_TIME", OG_TRUE, ATTR_NONE, "60000000", NULL, NULL, "-", "[100000,300000000]", "OG_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_time, sql_notify_als_need_arch_time, NULL, NULL },
    { "ARCH_CLEAN_UPPER_LIMIT", OG_TRUE, ATTR_NONE, "85", NULL, NULL, "-", "[1,100]", "OG_TYPE_INTEGER", NULL,
      PARAM_ARCH_CLEAN_UPPER_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_upper_limit,
      sql_notify_als_arch_upper_limit, NULL, NULL },
    { "ARCH_CLEAN_LOWER_LIMIT", OG_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[0,100]", "OG_TYPE_INTEGER", NULL,
      PARAM_ARCH_CLEAN_LOWER_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_lower_limit,
      sql_notify_als_arch_lower_limit, NULL, NULL },
    { "ARCH_CLEAN_IGNORE_BACKUP", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_CLEAN_IGNORE_BACKUP, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ignore_backup,
      sql_notify_als_bool, NULL },
    { "ARCH_CLEAN_IGNORE_STANDBY", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_CLEAN_IGNORE_STANDBY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ignore_standby,
      sql_notify_als_bool, NULL },
    { "XA_SUSPEND_TIMEOUT", OG_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "(0,3600]", "OG_TYPE_INTEGER", NULL,
      PARAM_XA_SUSPEND_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_xa_suspend_timeout,
      sql_notify_als_xa_suspend_timeout, NULL, NULL },
    { "BUILD_KEEP_ALIVE_TIMEOUT", OG_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[3, -)", "OG_TYPE_INTEGER", NULL,
      PARAM_KEEP_ALIVE_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_build_timeout, NULL,
      NULL },
    { "_BACKUP_LOG_PARALLEL", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_BACKUP_LOG_PARALLEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_backup_log_parallel,
      sql_notify_als_bool, NULL },
    /* ip whitelist */
    { "TCP_VALID_NODE_CHECKING", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_TCP_VALID_NODE_CHECKING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_valid_node_checking, sql_notify_als_bool, NULL },
    { "TCP_INVITED_NODES", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_TCP_INVITED_NODES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_invited_nodes, NULL,
      NULL },
    { "TCP_EXCLUDED_NODES", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_TCP_EXCLUDED_NODES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_excluded_nodes, NULL,
      NULL },
    { "LOCK_WAIT_TIMEOUT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_LOCK_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_lock_wait_timeout,
      NULL, NULL },
    { "ENABLE_RAFT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL, PARAM_RAFT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "RAFT_START_MODE", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,3]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_START_MODE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_start_mode, NULL, NULL, NULL },
    { "RAFT_NODE_ID", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "[1,-)", "OG_TYPE_INTEGER", NULL, PARAM_RAFT_NODE_ID,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_node_id, NULL, NULL, NULL },
    { "RAFT_PEER_IDS", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_PEER_IDS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_LOCAL_ADDR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_LOCAL_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PEER_ADDRS", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_PEER_ADDRS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_LOG_LEVEL", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[0,6]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_LOG_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_log_level, NULL, NULL, NULL },
    { "RAFT_KUDU_DIR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_KUDU_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PRIORITY_TYPE", OG_TRUE, ATTR_NONE, "External", NULL, NULL, "-", "External,Random,Static,AZFirst",
      "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_PRIORITY_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_priority_type,
      NULL, NULL, NULL },
    { "RAFT_PRIORITY_LEVEL", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,16]", "OG_TYPE_VARCHAR", NULL,
      PARAM_RAFT_PRIORITY_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_priority_level, NULL, NULL, NULL },
    { "RAFT_LAYOUT_INFO", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_LAYOUT_INFO,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PENDING_CMDS_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[1,-)", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_PENDING_CMDS_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_pending_cmds_buffer_size, NULL,
      NULL, NULL },
    { "RAFT_SEND_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_SEND_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_send_buffer_size, NULL, NULL, NULL },
    { "RAFT_RECEIVE_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_RECEIVE_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_receive_buffer_size, NULL, NULL,
      NULL },
    { "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", OG_TRUE, ATTR_NONE, "2G", NULL, NULL, "-", "[1,-)", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm,
      sql_notify_als_entry_cache_memory_size, NULL, NULL },
    { "RAFT_MAX_SIZE_PER_MSG", OG_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[64M,-)", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_MAX_SIZE_PER_MSG, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_max_size_per_msg, NULL,
      NULL },
    { "RAFT_ELECTION_TIMEOUT", OG_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "[3,60]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_ELECTION_TIMEOUT, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_election_timeout,
      sql_notify_als_raft_election_timeout, NULL, NULL },
    { "RAFT_MEMORY_THRESHOLD", OG_TRUE, ATTR_NONE, "5G", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_MEM_THRESHOLD, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_raft_mem_threshold, NULL,
      NULL },
    { "RAFT_LOG_ASYNC_BUF_NUM", OG_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[1,128]", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_LOG_ASYNC_BUF_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_log_async_buf_num, NULL, NULL, NULL },
    { "RAFT_FAILOVER_LIB_TIMEOUT", OG_TRUE, ATTR_NONE, "600", NULL, NULL, "-", "[5,-)", "OG_TYPE_INTEGER", NULL,
      PARAM_RAFT_FAILOVER_LIB_TIMEOUT, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_failover_lib_timeout, NULL, NULL,
      NULL },
    { "RAFT_TLS_DIR", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RAFT_TLS_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_tls_dir, NULL, NULL, NULL },
    { "RAFT_TOKEN_VERIFY", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_RAFT_TOKEN_VERIFY, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_token_verify, NULL, NULL, NULL },
    { "LOCAL_KEY", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "88", "OG_TYPE_VARCHAR", NULL, PARAM_LOCAL_KEY,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_local_key, sql_notify_als_local_key, NULL, NULL },
    { "BUF_POOL_NUM", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,4096]", "OG_TYPE_INTEGER", NULL, PARAM_BUF_POOL_NUM,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_buf_pool_num, NULL, NULL, NULL },
    { "DEFAULT_EXTENTS", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "8, 16, 32, 64, 128", "OG_TYPE_INTEGER", NULL,
      PARAM_DEFAULT_EXTENTS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_default_extents,
      sql_notify_als_default_extents, NULL, NULL },
    { "_MAX_VM_FUNC_STACK_COUNT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM_MAX_VM_FUNC_STACK_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_vm_func_stack_count, NULL, NULL },
    { "TEMP_POOL_NUM", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1, 128]", "OG_TYPE_INTEGER", NULL,
      PARAM_TEMP_POOL_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_temp_pool_num, NULL, NULL, NULL },

    /* merge join */
    { "MERGE_SORT_BATCH_SIZE", OG_TRUE, ATTR_NONE, "100000", NULL, NULL, "-", "[100000,4294967295]", "OG_TYPE_UINT32",
      NULL, PARAM_MERGE_SORT_BATCH_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_merge_batch_size,
      sql_notify_als_merge_sort_batch_size, NULL, NULL },
    { "ENABLE_NESTLOOP_JOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_NESTLOOP_JOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_nestloop_join, sql_notify_als_bool, NULL },
    { "ENABLE_HASH_JOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_HASH_JOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_hash_join, sql_notify_als_bool, NULL },
    { "ENABLE_MERGE_JOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_MERGE_JOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_merge_join, sql_notify_als_bool, NULL },
    { "MAX_ALLOWED_PACKET", OG_TRUE, ATTR_NONE, "64M", NULL, NULL, "-", "[96K, 64M]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_ALLOWED_PACKET, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_allowed_packet,
      sql_notify_als_max_allowed_packet, NULL, NULL },
    { "DB_FILE_NAME_CONVERT", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_DB_FILE_NAME_CONVERT, EFFECT_REBOOT, CFG_INS, sql_verify_als_convert, sql_notify_als_datefile_convert, NULL,
      NULL },
    { "LOG_FILE_NAME_CONVERT", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_LOG_FILE_NAME_CONVERT, EFFECT_REBOOT, CFG_INS, sql_verify_als_convert, sql_notify_als_logfile_convert, NULL,
      NULL },
    { "INTERACTIVE_TIMEOUT", OG_TRUE, ATTR_NONE, "1800", NULL, NULL, "-", "[1,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM_INTERACTIVE_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_interactive_timeout,
      sql_notify_als_interactive_timeout, NULL, NULL },
    { "SQL_STAGE_THRESHOLD", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_SQL_STAGE_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sql_stage_threshold,
      sql_notify_als_sql_stage_threshold, NULL, NULL },
    /* ssl */
    { "SSL_CA", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_CA, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_CERT", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_CERT, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_KEY", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_KEY, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_CRL", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_CRL, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_VERIFY_PEER", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_SSL_VERIFY_PEER, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "SSL_KEY_PASSWORD", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_KEY_PASSWORD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "SSL_CIPHER", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_SSL_CIPHER,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ssl_cipher, NULL, NULL, NULL },
    { "SSL_EXPIRE_ALERT_THRESHOLD", OG_TRUE, ATTR_NONE, "90", NULL, NULL, "-", "[7,180]", "OG_TYPE_INTEGER", NULL,
      PARAM_SSL_EXPIRE_ALERT_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_ssl_alt_threshold, NULL, NULL, NULL },
    { "SSL_PERIOD_DETECTION", OG_TRUE, ATTR_NONE, "7", NULL, NULL, "-", "[1,180]", "OG_TYPE_INTEGER", NULL,
      PARAM_SSL_PERIOD_DETECTION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_ssl_period_detection, NULL, NULL, NULL },
    { "LOCAL_TEMPORARY_TABLE_ENABLED", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_LOCAL_TEMPORARY_TABLE_ENABLED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_local_tmp_tbl_enabled, sql_notify_als_bool, NULL },
    { "UPPER_CASE_TABLE_NAMES", OG_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_UPPER_CASE_TABLE_NAMES, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_upper_case_table_names,
      sql_notify_als_bool, NULL },
    { "UNAUTH_SESSION_EXPIRE_TIME", OG_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_UINT32", NULL,
      PARAM_UNAUTH_SESSION_EXPIRE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_unauth_session_expire_time, NULL, NULL },
    { "ENABLE_SYSDBA_LOGIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYSDBA_LOGIN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_login_as_sysdba, sql_notify_als_bool, NULL },
    { "ENABLE_SYS_REMOTE_LOGIN", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYS_REMOTE_LOGIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_sys_remote_login, sql_notify_als_bool, NULL },
    { "ENABLE_SYSDBA_REMOTE_LOGIN", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYSDBA_REMOTE_LOGIN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_sysdba_remote_login, sql_notify_als_bool, NULL },
    { "RESOURCE_LIMIT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_RESOURCE_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_resource_limit,
      sql_notify_als_bool, NULL },
    { "_FACTOR_KEY", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "24", "OG_TYPE_VARCHAR", NULL, PARAM__FACTOR_KEY,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_factor_key, sql_notify_als_factor_key, NULL, NULL },
    /* err superposed switch */
    { "ENABLE_ERR_SUPERPOSED", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ERR_SUPERPOSED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_err_superposed, sql_notify_als_bool, NULL },
    { "EMPTY_STRING_AS_NULL", OG_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_EMPTY_STRING_AS_NULL, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_empty_string_null,
      sql_notify_als_bool, NULL },
    { "ZERO_DIVISOR_ACCEPTED", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ZERO_DIVISOR_ACCEPTED, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_zero_divisor_accepted,
      sql_notify_als_bool, NULL },
    { "STRING_AS_HEX_FOR_BINARY", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_STRING_AS_HEX_BINARY, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_string_as_hex_binary,
      sql_notify_als_bool, NULL },
    { "DROP_NOLOGGING", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_DROP_NOLOGGING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_drop_nologging,
      sql_notify_als_bool, NULL },
    { "RECYCLEBIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_RECYCLEBIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_recyclebin, sql_notify_als_bool,
      NULL },
    { "HAVE_SSL", OG_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_HAVE_SSL, EFFECT_REBOOT, CFG_INS, sql_verify_als_have_ssl, NULL, NULL, NULL },
    { "_ENCRYPTION_ITERATION", OG_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[1000,10000000]", "OG_TYPE_INTEGER", NULL,
      PARAM_ENCRYPTION_ITER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_encrypt_iteration,
      sql_notify_als_encrypt_iteration, sql_notify_als_encrypt_iteration, NULL },
    { "MAX_TEMP_TABLES", OG_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[64,8192]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_TEMP_TABLES, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_temp_tables, NULL, NULL, NULL },
    { "ENABLE_IDX_CONFS_NAME_DUPL", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_IDX_CONFS_NAME_DUPL, EFFECT_REBOOT, CFG_INS, sql_verify_als_idx_duplicate_enable,
      sql_notify_als_idx_duplicate, sql_notify_als_idx_duplicate, NULL },
    { "ENABLE_IDX_KEY_LEN_CHECK", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_IDX_KEY_LEN_CHECK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_idx_key_len_check,
      sql_notify_als_bool, NULL },
    { "CBO", OG_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "ON", "OG_TYPE_VARCHAR", NULL, PARAM_CBO,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_cbo, sql_notify_als_onoff, NULL },
    { "MAX_COLUMN_COUNT", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "1024,2048,3072,4096", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_COLUMN_COUNT, EFFECT_REBOOT, CFG_DB, sql_verify_als_max_column_count, NULL, NULL, NULL },
    { "STATISTICS_SAMPLE_SIZE", OG_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[32M,4G)", "OG_TYPE_INTEGER", NULL,
      PARAM_SAMPLE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_stats_sample_size, sql_notify_als_sample_size,
      NULL, NULL },
    // initial sql_cursors for each session
    { "_SQL_CURSORS_EACH_SESSION", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[0,300]", "OG_TYPE_INTEGER", NULL,
      PARAM__SQL_CURSORS_EACH_SESSION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sql_cursors_each_sess,
      sql_notify_als_sql_cursors_each_sess, NULL, NULL },
    // reserved sql_cursors for all sessions
    { "_RESERVED_SQL_CURSORS", OG_TRUE, ATTR_NONE, "80", NULL, NULL, "-", "[0,1000]", "OG_TYPE_INTEGER", NULL,
      PARAM__RESERVED_SQL_CURSORS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_reserved_sql_cursors,
      sql_notify_als_reserved_sql_cursors, NULL, NULL },
    { "COVERAGE_ENABLE", OG_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_COVERAGE_ENABLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_coverage_enable,
      sql_notify_als_bool, NULL },
    { "TYPE_MAP_FILE", OG_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_TYPE_MAP_FILE,
      EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "INI_TRANS", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1, 255]", "OG_TYPE_INTEGER", NULL, PARAM_INI_TRANS,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ini_trans, sql_notify_als_ini_trans, NULL, NULL },
    { "INT_SYSINDEX_TRANS", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[2, 128]", "OG_TYPE_INTEGER", NULL,
      PARAM_INT_SYSINDEX_TRANS, EFFECT_REBOOT, CFG_INS, sql_verify_als_ini_sysindex_trans, NULL, NULL, NULL },
    { "CR_MODE", OG_TRUE, ATTR_NONE, "PAGE", NULL, NULL, "-", "PAGE,ROW", "OG_TYPE_VARCHAR", NULL, PARAM_CR_MODE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_mode, NULL, NULL, NULL },
    { "ROW_FORMAT", OG_TRUE, ATTR_NONE, "ASF", NULL, NULL, "-", "ASF,CSF", "OG_TYPE_VARCHAR", NULL, PARAM_ROW_FORMAT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_row_format, sql_notify_als_row_format, NULL, NULL },
    { "_LNS_WAIT_TIME", OG_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM__LSND_WAIT_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_lsnd_wait_time, NULL,
      NULL },
    { "_PRIVATE_KEY_LOCKS", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "_", "[8, 128]", "OG_TYPE_INTEGER", NULL,
      PARAM_PRIVATE_KEY_LOCKS, EFFECT_REBOOT, CFG_INS, sql_verify_als_private_key_locks,
      sql_notify_als_private_key_locks, NULL, NULL },
    { "_PRIVATE_ROW_LOCKS", OG_TRUE, ATTR_NONE, "8", NULL, NULL, "_", "[8, 128]", "OG_TYPE_INTEGER", NULL,
      PARAM_PRIVATE_ROW_LOCKS, EFFECT_REBOOT, CFG_INS, sql_verify_als_private_row_locks,
      sql_notify_als_private_row_locks, NULL, NULL },
    { "DDL_LOCK_TIMEOUT", OG_TRUE, ATTR_NONE, "30", NULL, NULL, "_", "[0, 1000000]", "OG_TYPE_INTEGER", NULL,
      PARAM_DDL_LOCK_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ddl_lock_timeout,
      sql_notify_als_ddl_lock_timeout, NULL, NULL },
    { "MAX_REMOTE_PARAMS", OG_TRUE, ATTR_NONE, "300", NULL, NULL, "_", "[0, 32768]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_REMOTE_PARAMS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_max_remote_params,
      sql_notify_als_max_remote_params, NULL, NULL },
    { "DB_TIMEZONE", OG_TRUE, ATTR_READONLY, "+00:00", NULL, NULL, "-", "[-12:00,[+]14:00]", "OG_TYPE_VARCHAR", NULL,
      PARAM_DB_TIMEZONE, EFFECT_REBOOT, CFG_DB, sql_verify_als_db_tz, NULL, NULL, NULL },
    // alarm
    { "TABLESPACE_USAGE_ALARM_THRESHOLD", OG_TRUE, ATTR_NONE, "80", NULL, NULL, "_", "[0, 100]", "OG_TYPE_INTEGER",
      NULL, PARAM_TABLESPACE_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_tablespace_alarm_threshold,
      sql_notify_als_tablespace_alarm_threshold, NULL, NULL },
    { "UNDO_USAGE_ALARM_THRESHOLD", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 100]", "OG_TYPE_INTEGER", NULL,
      PARAM_UNDO_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_alarm_threshold,
      sql_notify_als_undo_alarm_threshold, NULL, NULL },
    { "TXN_UNDO_USAGE_ALARM_THRESHOLD", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 100]", "OG_TYPE_INTEGER", NULL,
      PARAM_TXN_UNDO_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_txn_undo_alarm_threshold,
      sql_notify_als_txn_undo_alarm_threshold, NULL, NULL },
    { "_SYSTIME_INCREASE_THREASHOLD", OG_TRUE, ATTR_NONE, "365", NULL, NULL, "_", "[0, 3600]", "OG_TYPE_INTEGER", NULL,
      PARAM_SYSTIME_INCREASE_THREASHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_systime_increase_threshold,
      sql_notify_als_systime_increase_threshold, NULL, NULL },
    /* auto block repair */
    { "BLOCK_REPAIR_ENABLE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_BLOCK_REPAIR_ENABLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_block_repair_enable,
      sql_notify_als_bool, NULL },
    { "BLOCK_REPAIR_TIMEOUT", OG_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[1,3600]", "OG_TYPE_INTEGER", NULL,
      PARAM_BLOCK_REPAIR_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_block_repair_timeout,
      sql_notify_als_block_repair_timeout, NULL, NULL },
    { "UDS_FILE_PATH", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_UDS_FILE_PATH,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_path, NULL, NULL, NULL },
    { "UDS_FILE_PERMISSIONS", OG_TRUE, ATTR_NONE, "600", NULL, NULL, "-", "[600-777]", "OG_TYPE_INTEGER", NULL,
      PARAM_UDS_FILE_PERMISSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_permissions, NULL, NULL, NULL },
    { "STATS_COST_LIMIT", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_STATS_COST_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_cost_limit, NULL,
      NULL },
    { "STATS_COST_DELAY", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_STATS_COST_DELAY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_cost_delay, NULL,
      NULL },
    { "ENABLE_SAMPLE_LIMIT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SAMPLE_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_sample_limit,
      sql_notify_als_bool, NULL },
    /* parameters between master and slave */
    { "MASTER_SLAVE_DIFFTIME", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,4294967295]", "OG_TYPE_INTEGER", NULL,
      PARAM_MASTER_SLAVE_DIFFTIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_master_backup_synctime, NULL, NULL },
    { "WORKER_THREADS_SHRINK_THRESHOLD", OG_TRUE, ATTR_NONE, "1800", NULL, NULL, "-", "[0,4000000]", "OG_TYPE_INTEGER",
      NULL, PARAM_WORKER_THREADS_SHRINK_THRESHOLD, EFFECT_REBOOT, CFG_INS, sql_verify_als_agent_shrink_threshold, NULL,
      NULL, NULL },
    /* XA */
    { "XA_FORMAT_ID", OG_TRUE, ATTR_READONLY, "247", NULL, NULL, "-", "[0-9223372036854775807]", "OG_TYPE_BIGINT", NULL,
      PARAM_XA_FORMAT_ID, EFFECT_REBOOT, CFG_INS, sql_verify_als_xa_format_id, NULL, NULL, NULL },
    { "DEGRADE_SEARCH_MAP", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_DEGRADE_SEARCH_MAP, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_degrade_search,
      sql_notify_als_bool, NULL },
    /* bind CPUs resource manager can use */
    { "CPU_NODE_BIND", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_CPU_NODE_BIND,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cpu_node_bind, sql_notify_als_cpu_node_bind, NULL, NULL },
    /* resource management plan */
    { "RESOURCE_PLAN", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RESOURCE_PLAN,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_resource_plan, NULL, NULL },
    { "STATS_MAX_BUCKET_SIZE", OG_TRUE, ATTR_NONE, "254", NULL, NULL, "-", "[75,254]", "OG_TYPE_INTEGER", NULL,
      PARAM_STATS_MAX_BUCKET_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_bucket_size, NULL,
      NULL },

    { "PARALLEL_POLICY", OG_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM_PARALLEL_POLICY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_parallel_policy,
      sql_notify_als_onoff, NULL },
    { "DELAY_CLEANOUT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_DELAY_CLEANOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_delay_cleanout,
      sql_notify_als_bool, NULL },
    { "ENABLE_ACCESS_DC", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ACCESS_DC, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_access_dc_enable_bool, sql_notify_als_bool, NULL },
    { "_VIEW_ACCESS_DC", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_VIEW_ACCESS_DC, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_view_access_dc_bool, sql_notify_als_bool, NULL },
    /* shard force rollback when execute IDU sql in trans failed */
    { "ENABLE_PERMISSIVE_UNICODE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_PERMISSIVE_UNICODE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_permissive_unicode, sql_notify_als_bool, NULL },
    { "NODE_LOCK_STATUS", OG_TRUE, ATTR_READONLY, "NOLOCK", NULL, NULL, "-", "NOLOCK,SHARE,EXCLUSIVE",
      "OG_TYPE_VARCHAR", NULL, PARAM_NODE_LOCK_STATUS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_node_lock_status,
      NULL, NULL, NULL },
    { "UNDO_TABLESPACE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_UNDO_TABLESPACE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_undo_space, NULL, NULL },
    { "LOB_REUSE_THRESHOLD", OG_TRUE, ATTR_NONE, "80M", NULL, NULL, "-", "[4M,4G)", "OG_TYPE_INTEGER", NULL,
      PARAM_LOB_REUSE_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lob_reuse_threshold,
      sql_notify_als_lob_reuse_threshold, NULL, NULL },
    { "ENABLE_LOCAL_INFILE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_LOCAL_INFILE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_enable_local_infile, NULL,
      NULL },


    // array datatype
    { "ARRAY_STORAGE_OPTIMIZATION", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ARRAY_STORAGE_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_arr_store_opt, sql_notify_als_bool, NULL },

    // JSON
    { "_MAX_JSON_DYNAMIC_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "1G", NULL, NULL, "-", "[1M,32T]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_JSON_DYNAMIC_BUFFER_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_json_dyn_buf_size,
      sql_notify_json_dyn_buf_size, NULL, NULL },
    // slow sql stats print or not
    { "SLOWSQL_STATS_ENABLE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "[FALSE,TRUE]", "OG_TYPE_BOOLEAN", NULL,
      PARAM_SLOWSQL_STATS_ENABLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_enable_slowsql_stats,
      sql_notify_als_bool, NULL },
    { "STATS_PARALL_THREADS", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[2,8]", "OG_TYPE_INTEGER", NULL,
      PARAM_STATS_PARALL_THREADS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_stats_parall_threads,
      sql_notify_als_stats_parall_threads, NULL, NULL },
    { "STATS_ENABLE_PARALL", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_STATS_ENABLE_PARALL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_stats_enable_parall,
      sql_notify_als_bool, NULL },
    { "_OUTER_JOIN_OPTIMIZATION", OG_TRUE, ATTR_NONE, "OFF", NULL, NULL, "-", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM_OUTER_JOIN_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_outer_join_opt,
      sql_notify_als_onoff, NULL },
    { "CBO_INDEX_CACHING", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,100]", "OG_TYPE_INTEGER", NULL,
      PARAM_CBO_INDEX_CACHING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_index_caching,
      sql_notify_als_cbo_index_caching, NULL, NULL },
    { "CBO_INDEX_COST_ADJ", OG_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_CBO_INDEX_COST_ADJ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_index_cost_adj,
      sql_notify_als_cbo_index_cost_adj, NULL, NULL },
    { "CBO_PATH_CACHING", OG_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[1,16]", "OG_TYPE_INTEGER", NULL,
      PARAM_CBO_PATH_CACHING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_path_caching,
      sql_notify_als_cbo_path_caching, NULL, NULL },
    { "_WITHAS_SUBQUERY", OG_TRUE, ATTR_NONE, "OPTIMIZER", NULL, NULL, "-", "OPTIMIZER,MATERIALIZE,INLINE",
      "OG_TYPE_VARCHAR", NULL, PARAM__WITHAS_SUBQUERY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_withas_subquery,
      sql_notify_als_withas_subquery, NULL, NULL },
    { "MAX_PBL_FILE_SIZE", OG_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[10M,100M]", "OG_TYPE_INTEGER", NULL,
      PARAM_PBL_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_pbl_file_size, sql_notify_als_pbl_max_file_size,
      NULL, NULL },
    { "_DISTINCT_PRUNING", OG_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM_DISTINCT_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_distinct_pruning,
      sql_notify_als_onoff, NULL },
    { "_QUERY_TOPN_THRESHOLD", OG_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[0,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_QUERY_TOPN_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_topn_threshold,
      sql_notify_als_topn_threshold, NULL, NULL },
    { "_CONNECT_BY_MATERIALIZE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_CONNECT_BY_MTRL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_connect_by_mtrl,
      sql_notify_als_bool, NULL },
    { "INIT_LOCK_POOL_PAGES", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[128,32K]", "OG_TYPE_INTEGER", NULL,
      PARAM_INIT_LOCKPOOL_PAGES, EFFECT_REBOOT, CFG_INS, sql_verify_init_lockpool_pages, sql_notify_init_lockpool_pages,
      NULL, NULL },
    { "_OPTIMIZER_AGGR_PLACEMENT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_AGGR_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_aggr_placement,
      sql_notify_als_bool, NULL },
    { "_OPTIM_OR_EXPANSION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_OR_EXPANSION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_or_expansion,
      sql_notify_als_bool, NULL },
    { "_OPTIM_DISTINCT_ELIMINATION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_DISTINCT_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_distinct_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_PROJECT_LIST_PRUNING", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PROJECT_LIST_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_project_list_pruning, sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_MOVE_AROUND", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_MOVE_AROUND, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_move_around,
      sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_DELIVERY", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_DELIVERY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_delivery,
      sql_notify_als_bool, NULL },
    { "_OPTIM_HASH_MATERIALIZE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_HASH_MTRL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_hash_mtrl,
      sql_notify_als_bool, NULL },
    { "_OPTIM_WINMAGIC_REWRITE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_WINMAGIC_REWRITE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_winmagic_rewrite,
      sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_REORDER", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_REORDER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_reorder,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ORDER_BY_PLACEMENT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ORDER_BY_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_order_by_placement, sql_notify_als_bool, NULL },
    { "_OPTIM_SUBQUERY_ELIMINATION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SUBQUERY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_subquery_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_JOIN_ELIMINATION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_JOIN_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_join_elimination,
      sql_notify_als_bool, NULL },
    { "_OPTIM_CONNECT_BY_PLACEMENT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_CONNECT_BY_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_connect_by_placement, sql_notify_als_bool, NULL },
    { "_OPTIM_GROUP_BY_ELIMINATION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_GROUP_BY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_group_by_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_ANY_TRANSFORM", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ANY_TRANSFORM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_optim_any_transform,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ALL_TRANSFORM", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ALL_TRANSFORM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_optim_all_transform,
      sql_notify_als_bool, NULL },
    { "_ENABLE_MULTI_INDEX_SCAN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_MULTI_INDEX_SCAN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_multi_index_scan,
      sql_notify_als_bool, NULL },
    { "_OPTIM_JOIN_PRED_PUSHDOWN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_JOIN_PRED_PUSHDOWN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_join_pred_pushdown, sql_notify_als_bool, NULL },
    { "_OPTIM_FILTER_PUSHDOWN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_FILTER_PUSHDOWN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_filter_pushdown,
      sql_notify_als_bool, NULL },
    { "_OPTIM_INDEX_SCAN_MAX_PARTS", OG_TRUE, ATTR_NONE, "200", NULL, NULL, "-", "[0, 900]", "OG_TYPE_INTEGER", NULL,
      PARAM_OPTIM_INDEX_SCAN_MAX_PARTS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_multi_parts_scan,
      sql_notify_als_multi_parts_scan, NULL, NULL },
    { "_OPTIM_ORDER_BY_ELIMINATION", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ORDER_BY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_order_by_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_UNNEST_SET_SUBQUERY", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_UNNEST_SET_SUBQ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_unnest_set_subquery,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_SEMIJOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_SEMIJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_semijoin, sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_ANTIJOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_ANTIJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_antijoin, sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_LEFTJOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_LEFTJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_leftjoin, sql_notify_als_bool, NULL },
    { "SEGMENT_PAGES_HOLD", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_SEGMENT_PAGES_HOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_seg_pages_hold,
      sql_notify_als_seg_pages_hold, NULL, NULL },
    { "HASH_TABLE_PAGES_HOLD", OG_TRUE, ATTR_NONE, "128", NULL, NULL, "-", "[0,10000]", "OG_TYPE_INTEGER", NULL,
      PARAM_HASH_PAGES_HOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_hash_pages_hold,
      sql_notify_als_hash_pages_hold, NULL, NULL },
    { "_OPTIM_SIMPLIFY_EXISTS_SUBQ", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SIMPLIFY_EXISTS_SUBQ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_simplify_exists_subq, sql_notify_als_bool, NULL },
    { "_OPTIM_SUBQUERY_REWRITE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SUBQUERY_REWRITE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_subquery_rewrite,
      sql_notify_als_bool, NULL },
    { "_OPTIM_SEMI2INNER", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SEMI2INNER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_semi2inner,
      sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_PUSHDOWN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_PUSHDOWN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_pushdown,
      sql_notify_als_bool, NULL },
    { "_OPTIM_IN_TRANSFORM", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_IN_TRANSFORM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_in_transform,
      sql_notify_als_bool, NULL },
    // ctrl info backup parameter
    { "CTRLLOG_BACKUP_LEVEL", OG_TRUE, ATTR_NONE, "NONE", NULL, NULL, "-", "NONE,TYPICAL,FULL", "OG_TYPE_VARCHAR",
      NULL, PARAM_CTRLLOG_BACKUP_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_ctrllog_backup_level,
      sql_notify_ctrllog_backup_level, NULL, NULL },
    { "_OPTIM_FUNC_INDEX_SCAN_ONLY", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_FUNC_INDEX_SCAN_ONLY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_func_index_scan, sql_notify_als_bool, NULL },
    { "_OPTIM_INDEX_COND_PRUNING", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_INDEX_COND_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_index_cond_pruning, sql_notify_als_bool, NULL },
    { "_OPTIM_VM_VIEW_ENABLED", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_VM_VIEW_ENABLED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_vm_view_mtrl,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ADAPTIVE_FULL_OUTER_JOIN", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_ENABLE_NL_FULL_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_nl_full_opt, sql_notify_als_bool, NULL },
    { "_TABLE_COMPRESS_ALGO", OG_TRUE, ATTR_NONE, "NONE", NULL, NULL, "-", "NONE,ZSTD", "OG_TYPE_VARCHAR", NULL,
      PARAM_TABLE_COMPRESS_ALGO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_compress_algo,
      sql_notify_als_compress_algo, NULL, NULL },
    { "_TABLE_COMPRESS_BUFFER_SIZE", OG_TRUE, ATTR_NONE, "16M", NULL, NULL, "-", "[16M,1G]", "OG_TYPE_INTEGER", NULL,
      PARAM_TABLE_COMPRESS_BUF_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_compress_buf_size,
      sql_notify_als_compress_buf_size, NULL, NULL },
    { "_TABLE_COMPRESS_ENABLE_BUFFER", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN",
      NULL, PARAM_TABLE_COMPRESS_ENABLE_BUF, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool,
      sql_notify_als_compress_enable_buf, sql_notify_als_bool, NULL },
    { "ENABLE_PASSWORD_CIPHER", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE, TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_PASSWORD_CIPHER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_password_cipher, sql_notify_als_bool, NULL },
    { "CBO_HINT_ENABLED", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE, TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_CBO_HINT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_cbo_hint,
      sql_notify_als_bool, NULL },
    { "PARALLEL_MAX_THREADS", OG_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[0,4096]", "OG_TYPE_INTEGER", NULL,
      PARAM_PARALLEL_MAX_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_parall_max_threads,
      sql_notify_als_parall_max_threads, NULL, NULL },
    { "_OPT_CBO_STAT_SAMPLING_LEVEL", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,9]", "OG_TYPE_INTEGER", NULL,
      PARAM_OPT_CBO_STAT_SAMPLING_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_dyn_sampling,
      sql_notify_als_cbo_dyn_sampling, NULL, NULL },
    { "_STRICT_CASE_DATATYPE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE, TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_STRICT_CASE_DATATYPE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_strict_case_datatype,
      sql_notify_als_bool, NULL },

    // dblink
    { "MAX_LINK_TABLES", OG_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[0,1024]", "OG_TYPE_INTEGER", NULL,
      PARAM_MAX_LINK_TABLES, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_link_tables, NULL, NULL, NULL },
    // priv
    { "AUTO_INHERIT_USER", OG_TRUE, ATTR_NONE, "OFF", NULL, NULL, "-", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM_AUTO_INHERIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_auto_inherit,
      sql_notify_als_onoff, NULL },
    { "REPLACE_PASSWORD_VERIFY", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE, TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_REPLACE_PASSWORD_VERIFY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_password_verify,
      sql_notify_als_bool, NULL },

    // DTC
    { "CLUSTER_DATABASE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_CLUSTER_DATABASE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "INTERCONNECT_ADDR", OG_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_INTERCONNECT_ADDR, EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "INTERCONNECT_PORT", OG_TRUE, ATTR_NONE, "1611", NULL, NULL, "-", "[1024,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM_INTERCONNECT_PORT, EFFECT_REBOOT, CFG_INS, sql_verify_als_interconnect_port, NULL, NULL, NULL },
    { "INTERCONNECT_TYPE", OG_TRUE, ATTR_NONE, "TCP", NULL, NULL, "-", "TCP,UC,UC_RDMA", "OG_TYPE_VARCHAR", NULL,
      PARAM_INTERCONNECT_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_interconnect_type, NULL, NULL, NULL },
    { "INTERCONNECT_CHANNEL_NUM", OG_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,32]", "OG_TYPE_INTEGER", NULL,
      PARAM_INTERCONNECT_CHANNEL_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "REACTOR_THREAD_NUM", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1,32]", "OG_TYPE_INTEGER", NULL,
      PARAM_REACTOR_THREAD_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "MES_CPU_INFO", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_MES_CPU_INFO, EFFECT_REBOOT, CFG_INS, sql_verify_als_cpu_inf_str, NULL, NULL, NULL },
    { "ENABLE_TX_FREE_PAGE_LIST", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_TX_FREE_PAGE_LIST, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_tx_free_page_list, sql_notify_als_bool, NULL},
    { "OGRAC_TASK_NUM", OG_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[1,500]", "OG_TYPE_INTEGER", NULL,
      PARAM_OGRAC_TASK_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "INSTANCE_ID", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,63]", "OG_TYPE_INTEGER", NULL, PARAM_INSTANCE_ID,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "MES_POOL_SIZE", OG_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[256,16384]", "OG_TYPE_INTEGER", NULL,
      PARAM_MES_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "OGSTORE_INST_PATH", OG_TRUE, ATTR_NONE, "UDS:/tmp/.ogstore_unix_d_socket", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_OGSTORE_INST_PATH, EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_path, NULL, NULL, NULL },
    { "INTERCONNECT_BY_PROFILE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_INTERCONNECT_BY_PROFILE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "MES_ELAPSED_SWITCH", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_MES_ELAPSED_SWITCH, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_mes_elapsed_switch,
      sql_notify_als_bool, NULL },
    { "MES_CRC_CHECK_SWITCH", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_MES_CRC_CHECK_SWITCH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "OGSTORE_MAX_OPEN_FILES", OG_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "(0, 1000000]", "OG_TYPE_INTEGER", NULL,
      PARAM_OGSTORE_MAX_OPEN_FILES, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "DSS_LOG_LEVEL", OG_TRUE, ATTR_NONE, "7", NULL, NULL, "-", "[0,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM_DSS_LOG_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_dss_log_level, NULL, NULL, NULL },
    { "_ENABLE_RMO_CR", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_RMO_CR, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_rmo_cr,
      sql_notify_als_bool, NULL },
    { "_REMOTE_ACCESS_LIMIT", OG_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "[0, 255]", "OG_TYPE_INTEGER", NULL,
      PARAM_REMOTE_ACCESS_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_remote_access_limit,
      sql_notify_als_remote_access_limit, NULL, NULL },
    { "OG_GDV_SQL_SESS_TMOUT", OG_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0, 1000]", "OG_TYPE_INTEGER", NULL,
      PARAM_GDV_SQL_SESS_TMOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_gdv_sess_tmout,
      NULL, NULL },
    { "DTC_CKPT_NOTIFY_TASK_RATIO", OG_TRUE, ATTR_NONE, "0.125", NULL, NULL, "-", "[0.001,0.999]", "OG_TYPE_REAL", NULL,
      PARAM_DTC_CKPT_NOTIFY_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "DTC_CLEAN_EDP_TASK_RATIO", OG_TRUE, ATTR_NONE, "0.125", NULL, NULL, "-", "[0.001,0.999]", "OG_TYPE_REAL", NULL,
      PARAM_DTC_CLEAN_EDP_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "DTC_TXN_INFO_TASK_RATIO", OG_TRUE, ATTR_NONE, "0.25", NULL, NULL, "-", "[0.001,0.999]", "OG_TYPE_REAL", NULL,
      PARAM_DTC_TXN_INFO_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "RCY_NODE_READ_BUF_SIZE", OG_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "[2,10]", "OG_TYPE_INTEGER", NULL,
    PARAM_RCY_NODE_READ_BUF_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_rcy_read_buf_size, NULL,
    NULL, NULL },
    { "DTC_RCY_PARAL_BUF_LIST_SIZE", OG_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[2,256]", "OG_TYPE_INTEGER", NULL,
      PARAM_DTC_RCY_PARAL_BUF_LIST_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_dtc_rcy_paral_buf_list_size, NULL,
      NULL, NULL },
    { "CPU_GROUP_INFO",     OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_CPU_GROUP_INFO, EFFECT_REBOOT, CFG_INS, sql_verify_als_cpu_inf_str, NULL, NULL, NULL },

    /* deadlock */
    { "_DEADLOCK_DETECT_INTERVAL",    OG_TRUE, ATTR_NONE,     "1000",    NULL, NULL, "-", "1,10,100,1000",    "OG_TYPE_INTEGER", NULL, PARAM_DEADLOCK_DETECT_INTERVAL,     EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_deadlock_detect_interval,   sql_notify_als_deadlock_detect_interval,   NULL, NULL },

    { "_AUTO_UNDO_RETENTION",    OG_TRUE, ATTR_NONE,     "3",    NULL, NULL, "-", "[0, -)",    "OG_TYPE_INTEGER", NULL,
      PARAM_AUTO_UNDO_RETENTION,     EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_auto_undo_retention,
      sql_notify_als_auto_undo_retention,   NULL, NULL },

    { "SHARED_PATH",            OG_TRUE, ATTR_READONLY, "",     NULL, NULL, "-", "-",                      "OG_TYPE_VARCHAR", NULL, PARAM_SHARED_PATH, EFFECT_REBOOT, CFG_DB,  sql_verify_als_comm,                    NULL,                        NULL, NULL },
    /* dbstor */
    { "ENABLE_DBSTOR", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_DBSTOR, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "DBSTOR_DEPLOY_MODE", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,1]", "OG_TYPE_INTEGER", NULL,
      PARAM_DBSTOR_DEPLOY_MODE, EFFECT_REBOOT, CFG_INS, sql_verify_als_zero_one, NULL, NULL, NULL },
    { "DBSTOR_NAMESPACE", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_DBSTOR_NAMESPACE, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "ENABLE_OGRAC_STATS", OG_TRUE, ATTR_NONE, "OFF", NULL, NULL, "-", "OFF,ON", "OG_TYPE_VARCHAR", NULL,
      PARAM_ENABLE_OGRAC_STATS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_ograc_stats,
      sql_notify_ograc_stats, NULL },
    { "PAGE_CLEAN_MODE", OG_TRUE, ATTR_NONE, "SINGLE", NULL, NULL, "-", "SINGLE,ALL", "OG_TYPE_VARCHAR", NULL,
      PARAM_PAGE_CLEAN_MODE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_mode, sql_notify_als_page_clean_mode,
      NULL, NULL },
    { "ENABLE_DBSTOR_BATCH_FLUSH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_DBSTOR_BATCH_FLUSH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "CLUSTER_ID", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM_CLUSTER_ID, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL},
    { "BACKUP_RETRY", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_BACKUP_RETRY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "BATCH_FLUSH_CAPACITY", OG_TRUE, ATTR_NONE, "160", NULL, NULL, "-", "[1,4096]", "OG_TYPE_INTEGER", NULL,
      PARAM_BATCH_FLUSH_CAPACITY, EFFECT_REBOOT, CFG_INS, sql_verify_als_batch_flush_capacity,
      NULL, NULL, NULL },
    { "ENABLE_HWN_CHANGE", OG_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_HWN_CHANGE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "MES_CHANNEL_UPGRADE_TIME_MS", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_MES_CHANNEL_UPGRADE_TIME_MS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "MES_CHANNEL_DEGRADE_TIME_MS", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL,
      PARAM_MES_CHANNEL_DEGRADE_TIME_MS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "ENABLE_FDSA", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_FDSA, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "ENABLE_BROADCAST_ON_COMMIT", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_BROADCAST_ON_COMMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_broadcast_on_commit, sql_notify_als_bool, NULL },
    /* if you need add param here, position must keep pace with enum param_global_t */
    { "MES_SSL_SWITCH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_MES_SSL_SWITCH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "MES_SSL_CRT_KEY_PATH", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_MES_SSL_CRT_KEY_PATH, EFFECT_REBOOT, CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "MES_SSL_KEY_PWD", OG_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_MES_SSL_KEY_PWD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "ENABLE_CHECK_SECURITY_LOG", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_CHECK_SECURITY_LOG, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_enable_check_security_log, sql_notify_als_bool, NULL },
    { "ENABLE_SYS_CRC_CHECK", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYS_CRC_CHECK, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_crc_check, sql_notify_als_bool, NULL },
    { "CLUSTER_NO_CMS", OG_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_CLUSTER_NO_CMS, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "OG_CLUSTER_STRICT_CHECK", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE",
      "OG_TYPE_BOOLEAN", NULL, PARAM_OG_CLUSTER_STRICT_CHECK, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "DRC_IN_REFORMER_MODE", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_DRC_IN_REFORMER_MODE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL},
    { "RES_RECYCLE_RATIO", OG_TRUE, ATTR_NONE, "50", NULL, NULL, "-", "[50, 95]", "OG_TYPE_INTEGER", NULL,
      PARAM_RES_RECYCLE_RATIO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_res_recycle_ratio,
      sql_notify_als_res_recycle_ratio, NULL, NULL },
    { "CREATE_INDEX_PARALLELISM", OG_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0, 10]", "OG_TYPE_INTEGER", NULL,
      PARAM_CREATE_INDEX_PARALLELISM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_create_index_parallelism,
      sql_notify_als_create_index_parallelism, NULL, NULL },
    { "ENABLE_DSS", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_DSS, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "USE_BISON_PARSER", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_USE_BISON_PARSER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_use_bison_parser, sql_notify_als_bool, NULL },
    { "RBP_IP", OG_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, PARAM_RBP_IP,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_ip, NULL, NULL, NULL },
    { "RBP_PORT", OG_TRUE, ATTR_NONE, "2611", NULL, NULL, "-", "[1024,65535]", "OG_TYPE_INTEGER", NULL,
      PARAM_RBP_PORT, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_port, NULL, NULL, NULL },
    { "LOCAL_RBP_HOST", OG_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL,
      PARAM_LOCAL_RBP_HOST, EFFECT_REBOOT, CFG_INS, sql_verify_als_local_rbp_host, NULL, NULL, NULL },
    { "USE_RBP", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE,OFF,ON,0,1", "OG_TYPE_BOOLEAN", NULL,
      PARAM_USE_RBP, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_bool, sql_notify_als_use_rbp,
      sql_notify_als_rbp_bool,
      NULL },
    { "RBP_FOR_RECOVERY", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE,OFF,ON,0,1",
      "OG_TYPE_BOOLEAN", NULL,
      PARAM_RBP_FOR_RECOVERY, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_bool, sql_notify_als_rbp_bool,
      sql_notify_als_rbp_bool,
      NULL },
    { "RBP_RT_ANALYSIS", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE,OFF,ON,0,1",
      "OG_TYPE_BOOLEAN", NULL,
      PARAM_RBP_RT_ANALYSIS, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_bool, sql_notify_als_rbp_bool,
      sql_notify_als_rbp_bool,
      NULL },
    { "RBP_RT_PARSE_WORKERS", OG_TRUE, ATTR_NONE, "2", NULL, NULL, "-", RBP_RT_PARSE_WORKERS_RANGE,
      "OG_TYPE_INTEGER", NULL,
      PARAM_RBP_RT_PARSE_WORKERS, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_rt_parse_workers, NULL, NULL, NULL },
    { "RBP_RT_PAGE_OWNER_WORKERS", OG_TRUE, ATTR_NONE, "4", NULL, NULL, "-", RBP_RT_PAGE_OWNER_WORKERS_RANGE,
      "OG_TYPE_INTEGER", NULL,
      PARAM_RBP_RT_PAGE_OWNER_WORKERS, EFFECT_REBOOT, CFG_INS, sql_verify_als_rbp_rt_page_owner_workers, NULL, NULL,
      NULL },
    { "RBP_ASSEMBLE_MAX_SCAN", OG_TRUE, ATTR_NONE, "300", NULL, NULL, "-", RBP_ASSEMBLE_MAX_SCAN_RANGE,
      "OG_TYPE_INTEGER", NULL,
      PARAM_RBP_ASSEMBLE_MAX_SCAN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_rbp_assemble_max_scan,
      sql_notify_als_rbp_assemble_max_scan, NULL, NULL },
    // EXPLAIN
    { "PLAN_DISPLAY_FORMAT", OG_TRUE, ATTR_NONE, "TYPICAL", NULL, NULL, "-", "SIMPLE,BASIC,TYPICAL,ALL",
      "CT_TYPE_VARCHAR", NULL, PARAM_PLAN_DISPLAY_FORMAT, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_plan_display_format, sql_notify_als_plan_display_format, NULL, NULL },
    { "_SHOW_EXPLAIN_PREDICATE", OG_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_SHOW_EXPLAIN_PREDICATE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_predicate,
      sql_notify_als_bool, NULL },
    { "ENABLE_QUICK_CKPT", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_QUICK_CKPT, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_quick_ckpt,
      sql_notify_als_bool, NULL },
    { "ENABLE_PARA_LOG_FLUSH", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_PARA_LOG_FLUSH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL,
      sql_notify_als_bool, NULL },
    { "ENABLE_PARA_LOG_DFX", OG_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "OG_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_PARA_LOG_DFX, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_para_log_dfx,
      sql_notify_als_bool, NULL },
};

void srv_get_config_info(config_item_t **params, uint32 *count)
{
    *params = g_parameters;
    *count = sizeof(g_parameters) / sizeof(config_item_t);
}

void init_runtime_params(void)
{
    config_t g_instance_conf = g_instance->config;
    config_item_t *item = NULL;
    int params_size = sizeof(g_parameters) / sizeof(config_item_t);

    for (int i = 0; i < params_size; ++i) {
        item = &g_instance_conf.items[i];
        if (item == NULL) {
            continue;
        }

        if (item->is_default) {
            item->runtime_value = item->default_value;
        }
    }
}

/* these parameters are only used for testing, effect immediately and do not write config file. */
debug_config_item_t g_debug_parameters[] = {
        /* name                  default value    current value    range           type                  verify notify
         */
    { "_MRP_RES_LOGSIZE",    "0",             "0",             "[0,32T]",      "OG_TYPE_INTEGER",
      sql_verify_als_lrpl_res_logsize,    sql_notify_als_lrpl_res_logsize },
    { "_PAGE_PROTECT_CHECK", "0",             "0",             "[0,3]",        "OG_TYPE_INTEGER",
      sql_verify_als_page_protect_check, sql_notify_als_page_protect_check },
};

void srv_get_debug_config_info(debug_config_item_t **params, uint32 *count)
{
    *params = g_debug_parameters;
    *count = sizeof(g_debug_parameters) / sizeof(debug_config_item_t);
}

status_t sql_verify_dtc_rcy_paral_buf_list_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_DTC_RCY_PARAL_BUF_LIST_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)OG_MIN_DTC_RCY_PARAL_BUF_LIST_SIZE);
        return OG_ERROR;
    }
    if (num > OG_MAX_DTC_RCY_PARAL_BUF_LIST_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)OG_MAX_DTC_RCY_PARAL_BUF_LIST_SIZE);
        return OG_ERROR;
    }
    if ((num & (num - 1)) != 0) {
        OG_THROW_ERROR(ERR_PARAMETER_NOT_POWER_OF_TWO, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)num);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_rcy_read_buf_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_RCY_NODE_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RCY_NODE_READ_BUF_SIZE", (int64)OG_MIN_RCY_NODE_BUF_SIZE);
        return OG_ERROR;
    }
    if (num > OG_MAX_RCY_NODE_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "RCY_NODE_READ_BUF_SIZE", (int64)OG_MAX_RCY_NODE_BUF_SIZE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t verify_uds_temp_path(const char *path, char *input_path, char *temp_path, uint32 len)
{
    char dir_path[OG_UNIX_PATH_MAX];
    if (temp_path[1] == ' ') {
        OG_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return OG_ERROR;
    }
    if (strlen(temp_path) == 2 && (temp_path[1] == '.' || temp_path[1] == '\t')) {
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    if (strlen(temp_path) == len) {
        if (access("/", W_OK | R_OK) != 0) {
            OG_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, temp_path);
            return OG_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strncpy_s(dir_path, OG_UNIX_PATH_MAX, path, len - strlen(temp_path)));

        if (!cm_dir_exist(dir_path)) {
            OG_THROW_ERROR(ERR_PATH_NOT_EXIST, dir_path);
            return OG_ERROR;
        }
        char buffer_path[OG_UNIX_PATH_MAX];
        OG_RETURN_IFERR(realpath_file(dir_path, buffer_path, OG_UNIX_PATH_MAX));
        if (access(buffer_path, W_OK | R_OK) != 0) {
            OG_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, dir_path);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t verify_uds_file_path(const char *path)
{
    char realfile[OG_UNIX_PATH_MAX];
    char input_path_buffer[OG_UNIX_PATH_MAX];
    char *input_path;
    uint32 len;
    len = (uint32)strlen(path);
    OG_RETSUC_IFTRUE(len == 0);
    if (len >= OG_UNIX_PATH_MAX) {
        OG_THROW_ERROR(ERR_INVALID_FILE_NAME, path, OG_UNIX_PATH_MAX);
        return OG_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, OG_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= 2;
    }

    if (len == 0 || input_path[0] == ' ' || input_path[len - 1] == '/') {
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_uds_path_special_char(input_path, len)) {
        OG_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(realpath_file(input_path, realfile, OG_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        OG_THROW_ERROR(ERR_FILE_HAS_EXIST, realfile);
        return OG_ERROR;
    }

    char *temp_path = strrchr(input_path, '/');
    if (temp_path != NULL) {
        OG_RETURN_IFERR(verify_uds_temp_path(path, input_path, temp_path, len));
    }
    return OG_SUCCESS;
}

status_t verify_uds_file_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;
    if (usr_perm > OG_MAX_LOG_USER_PERMISSION || grp_perm > OG_MAX_LOG_USER_PERMISSION ||
        oth_perm > OG_MAX_LOG_USER_PERMISSION) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "UDS_FILE_PERMISSIONS");
        return OG_ERROR;
    }

    if (num < OG_DEF_UDS_FILE_PERMISSIONS || num > OG_MAX_UDS_FILE_PERMISSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "UDS_FILE_PERMISSIONS", (int64)OG_DEF_UDS_FILE_PERMISSIONS,
            (int64)OG_MAX_UDS_FILE_PERMISSIONS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t verify_file_path(const char *path)
{
    char input_path_buffer[OG_FILE_NAME_BUFFER_SIZE];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= OG_FILE_NAME_BUFFER_SIZE) {
        OG_THROW_ERROR(ERR_INVALID_FILE_NAME, path, OG_FILE_NAME_BUFFER_SIZE);
        return OG_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, OG_FILE_NAME_BUFFER_SIZE, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        OG_THROW_ERROR(ERR_INVALID_DIR, path);
        return OG_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        OG_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return OG_ERROR;
    }

    char buffer_path[OG_FILE_NAME_BUFFER_SIZE];
    OG_RETURN_IFERR(realpath_file(input_path, buffer_path, OG_FILE_NAME_BUFFER_SIZE));
    if (!cm_dir_exist(input_path) || (access(buffer_path, W_OK | R_OK) != 0)) {
        OG_THROW_ERROR(ERR_PATH_NOT_EXIST_OR_ACCESSABLE, input_path);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

plan_format_t g_plan_format_tab[] = {
    { { (char *)"SIMPLE", 6 }, FORMAT_MASK_SIMPLE },
    { { (char *)"BASIC", 5 }, FORMAT_MASK_BASIC },
    { { (char *)"TYPICAL", 7 }, FORMAT_MASK_TYPICAL },
    { { (char *)"ALL", 3 }, FORMAT_MASK_ALL },
};

plan_format_t g_plan_option_tab[] = {
    { { (char *)"PREDICATE", 9 }, FORMAT_MASK_PREDICATE },
    { { (char *)"QUERY_BLOCK", 11 }, FORMAT_MASK_QUERY_BLOCK },
    { { (char *)"OUTLINE", 7 }, FORMAT_MASK_OUTLINE },
};

#define PLAN_DISPLAY_FORMAT_COUNT ELEMENT_COUNT(g_plan_format_tab)
#define PLAN_DISPLAY_OPTION_COUNT ELEMENT_COUNT(g_plan_option_tab)

status_t sql_notify_als_plan_display_format(void *se, void *item, char *value)
{
    sql_set_plan_display_format(value, &g_instance->sql.plan_display_format);
    return OG_SUCCESS;
}

status_t sql_verify_als_plan_display_format(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    uint32 format_index = OG_INVALID_ID32;
    // 3 is PLAN_DISPLAY_OPTION_COUNT
    bool32 option_flag[3] = { OG_FALSE };
    OG_RETURN_IFERR(sql_get_plan_display_format_info(lex, &format_index, option_flag));
    OG_RETURN_IFERR(sql_normalize_plan_display_format_value(sys_def->value, format_index, option_flag));
    return OG_SUCCESS;
}

void sql_set_plan_display_format(char *str, uint32 *value)
{
    text_t text;
    cm_str2text(str, &text);
    text_t left = { 0 };
    text_t right = { 0 };

    *value = 0;

    cm_split_text(&text, ',', '\0', &left, &right);
    for (uint32 i = 0; i < PLAN_DISPLAY_FORMAT_COUNT; i++) {
        if (cm_text_equal_ins(&left, &g_plan_format_tab[i].text)) {
            OG_BIT_SET(*value, g_plan_format_tab[i].mask);
            cm_text_skip(&text, g_plan_format_tab[i].text.len);
            break;
        }
    }

    if (text.len == 0) {
        return;
    }

    cm_text_skip(&text, 1);

    for (;;) {
        cm_split_text(&text, ',', '\0', &left, &right);
        for (uint32 i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
            if (cm_text_equal_ins(&left, &g_plan_option_tab[i].text)) {
                OG_BIT_SET(*value, g_plan_option_tab[i].mask);
                cm_text_skip(&text, g_plan_option_tab[i].text.len);
                break;
            }
        }

        if (right.len == 0) {
            break;
        }

        cm_text_skip(&text, 1);
    }
}

static status_t sql_get_plan_format_index(text_t *left, uint32 *format_index, bool32 *format_mismatch)
{
    uint32 i;
    for (i = 0; i < PLAN_DISPLAY_FORMAT_COUNT; i++) {
        if (!cm_text_equal_ins(left, &g_plan_format_tab[i].text)) {
            continue;
        }
        if (*format_index != OG_INVALID_ID32 && *format_index != i) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s and %s cannot be set at the same time",
                g_plan_format_tab[i].text.str, g_plan_format_tab[*format_index].text.str);
            return OG_ERROR;
        }
        *format_index = i;
        break;
    }
    if (i == PLAN_DISPLAY_FORMAT_COUNT) {
        *format_mismatch = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t sql_get_plan_option_flag(text_t *left, bool32 *option_flag, bool32 *option_mismatch)
{
    uint32 i;
    for (i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
        if (cm_text_equal_ins(left, &g_plan_option_tab[i].text)) {
            option_flag[i] = OG_TRUE;
            break;
        }
    }
    if (i == PLAN_DISPLAY_OPTION_COUNT) {
        *option_mismatch = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t get_plan_display_format_value_len(lex_t *lex, uint32 *len)
{
    word_t word;
    LEX_SAVE(lex);
    for (;;) {
        if (lex_fetch(lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word.type == WORD_TYPE_VARIANT && cm_text_str_equal_ins(&word.text.value, "SCOPE")) {
            break;
        }

        if (word.type == WORD_TYPE_EOF) {
            break;
        }
    }
    LEX_RESTORE(lex);
    *len = (uint32)(word.text.str - lex->curr_text->str);
    return OG_SUCCESS;
}

status_t sql_get_plan_display_format_info(void *lex_in, uint32 *format_index, bool32 *option_flag)
{
    text_t left = { 0 };
    text_t right = { 0 };
    lex_t *lex = (lex_t *)lex_in;
    word_t word;
    uint32 value_len;
    lex_trim(lex->curr_text);
    word.text.str = lex->curr_text->str;
    if (LEX_CURR(lex) == '\'') {
        OG_RETURN_IFERR(lex_fetch_string(lex, &word));
        CM_REMOVE_ENCLOSED_CHAR(&word.text.value);
    } else {
        OG_RETURN_IFERR(get_plan_display_format_value_len(lex, &value_len));
        word.text.len = value_len;
        lex_skip(lex, value_len);
    }

    for (;;) {
        bool32 format_mismatch = OG_FALSE;
        bool32 option_mismatch = OG_FALSE;
        cm_ltrim_text(&word.text.value);
        if (word.text.len == 0) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return OG_ERROR;
        }

        cm_split_text(&word.text.value, ',', '\0', &left, &right);
        cm_text_skip(&word.text.value, left.len);
        cm_rtrim_text(&left);
        if ((left.len == 0 && right.len != 0) || (right.len == 0 && word.text.len != 0)) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_get_plan_format_index(&left, format_index, &format_mismatch));
        OG_RETURN_IFERR(sql_get_plan_option_flag(&left, option_flag, &option_mismatch));
        if (format_mismatch && option_mismatch) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Invalid value %s for PLAN_DISPLAY_FORMAT", T2S(&left));
            return OG_ERROR;
        }

        if (right.len == 0) {
            break;
        }

        cm_text_skip(&word.text.value, 1);
    }
    return OG_SUCCESS;
}

status_t sql_normalize_plan_display_format_value(char *value, uint32 format_index, bool32 *option_flag)
{
    uint32 len = 0;
    if (format_index == OG_INVALID_ID32) {
        len = g_plan_format_tab[0].text.len;
        MEMS_RETURN_IFERR(memcpy_s(value, OG_PARAM_BUFFER_SIZE, g_plan_format_tab[0].text.str, len));
    } else {
        len = g_plan_format_tab[format_index].text.len;
        MEMS_RETURN_IFERR(memcpy_s(value, OG_PARAM_BUFFER_SIZE, g_plan_format_tab[format_index].text.str, len));
    }

    if (format_index == PLAN_DISPLAY_FORMAT_COUNT - 1) {
        value[len++] = '\0';
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
        if (!option_flag[i]) {
            continue;
        }
        if (i == 0 && format_index == 1) {
            continue;
        }
        MEMS_RETURN_IFERR(memcpy_s(value + len, OG_PARAM_BUFFER_SIZE, ",", 1));
        len += 1;
        MEMS_RETURN_IFERR(
            memcpy_s(value + len, OG_PARAM_BUFFER_SIZE, g_plan_option_tab[i].text.str, g_plan_option_tab[i].text.len));
        len += g_plan_option_tab[i].text.len;
    }

    value[len++] = '\0';
    return OG_SUCCESS;
}

status_t srv_apply_param_plan_display_format(sql_instance_t *sql)
{
    char *value = srv_get_param("PLAN_DISPLAY_FORMAT");
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "PLAN_DISPLAY_FORMAT");
        return OG_ERROR;
    }

    lex_t lex = { 0 };
    sql_text_t sql_text = { .str = value, .len = (uint32)strlen(value), .loc = { .line = 1, .column = 1 } };
    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    uint32 format_index = OG_INVALID_ID32;
    bool32 options[PLAN_DISPLAY_OPTION_COUNT] = { OG_FALSE };
    OG_RETURN_IFERR(sql_get_plan_display_format_info(&lex, &format_index, options));

    char format_str[OG_PARAM_BUFFER_SIZE] = { 0 };
    OG_RETURN_IFERR(sql_normalize_plan_display_format_value(format_str, format_index, options));
    (void)sql_set_plan_display_format(format_str, &sql->plan_display_format);
    return OG_SUCCESS;
}


/* Bison ALTER SYSTEM verifier adapters. */
static status_t sql_bison_get_plan_display_format_value(const bison_sys_param_value_t *source,
    bison_param_token_t *token)
{
    text_t value = source->is_string ? source->decoded_string : source->text;

    MEMS_RETURN_IFERR(memset_s(token, sizeof(*token), 0, sizeof(*token)));
    token->text.str = token->value;
    token->type = source->is_string ? BISON_PARAM_TOKEN_STRING : BISON_PARAM_TOKEN_WORD;
    cm_trim_text(&value);
    if (value.len >= sizeof(token->value)) {
        OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, value.len, sizeof(token->value) - 1);
        return OG_ERROR;
    }
    if (value.len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(token->value, sizeof(token->value), value.str, value.len));
    }
    token->value[value.len] = '\0';
    token->text.len = value.len;
    return OG_SUCCESS;
}

static status_t sql_bison_extra_dtc_rcy_paral_buf_list_size(SQL_BISON_VERIFY_ARGS)
{
    uint32 num;
    if (sql_bison_extra_parse_uint32(source, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_DTC_RCY_PARAL_BUF_LIST_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)OG_MIN_DTC_RCY_PARAL_BUF_LIST_SIZE);
        return OG_ERROR;
    }
    if (num > OG_MAX_DTC_RCY_PARAL_BUF_LIST_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)OG_MAX_DTC_RCY_PARAL_BUF_LIST_SIZE);
        return OG_ERROR;
    }
    if ((num & (num - 1)) != 0) {
        OG_THROW_ERROR(ERR_PARAMETER_NOT_POWER_OF_TWO, "DTC_RCY_PARAL_BUF_LIST_SIZE", (int64)num);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_bison_get_plan_display_format_info(const bison_sys_param_value_t *source, uint32 *format_index,
    bool32 *option_flag)
{
    text_t left = { 0 };
    text_t right = { 0 };
    bison_param_token_t word;
    OG_RETURN_IFERR(sql_bison_get_plan_display_format_value(source, &word));

    for (;;) {
        bool32 format_mismatch = OG_FALSE;
        bool32 option_mismatch = OG_FALSE;
        cm_ltrim_text(&word.text);
        if (word.text.len == 0) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return OG_ERROR;
        }

        cm_split_text(&word.text, ',', '\0', &left, &right);
        cm_text_skip(&word.text, left.len);
        cm_rtrim_text(&left);
        if ((left.len == 0 && right.len != 0) || (right.len == 0 && word.text.len != 0)) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_get_plan_format_index(&left, format_index, &format_mismatch));
        OG_RETURN_IFERR(sql_get_plan_option_flag(&left, option_flag, &option_mismatch));
        if (format_mismatch && option_mismatch) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Invalid value %s for PLAN_DISPLAY_FORMAT", T2S(&left));
            return OG_ERROR;
        }

        if (right.len == 0) {
            break;
        }

        cm_text_skip(&word.text, 1);
    }
    return OG_SUCCESS;
}

status_t sql_bison_parse_plan_display_format(const bison_sys_param_value_t *source, uint32 *value)
{
    uint32 format_index = OG_INVALID_ID32;
    // 3 is PLAN_DISPLAY_OPTION_COUNT
    bool32 option_flag[3] = { OG_FALSE };
    char normalized_value[OG_PARAM_BUFFER_SIZE];

    OG_RETURN_IFERR(sql_bison_get_plan_display_format_info(source, &format_index, option_flag));
    OG_RETURN_IFERR(sql_normalize_plan_display_format_value(normalized_value, format_index, option_flag));
    sql_set_plan_display_format(normalized_value, value);
    return OG_SUCCESS;
}

static status_t sql_bison_extra_als_plan_display_format(SQL_BISON_VERIFY_ARGS)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    uint32 format_index = OG_INVALID_ID32;
    // 3 is PLAN_DISPLAY_OPTION_COUNT
    bool32 option_flag[3] = { OG_FALSE };
    OG_RETURN_IFERR(sql_bison_get_plan_display_format_info(source, &format_index, option_flag));
    OG_RETURN_IFERR(sql_normalize_plan_display_format_value(sys_def->value, format_index, option_flag));
    return OG_SUCCESS;
}

#define SQL_BISON_PARAM(name, verifier) \
    { name, verifier, 0, 0 }
#define SQL_BISON_PARAM_RANGE(name, verifier, min_value, max_value) \
    { name, verifier, (int64)(min_value), (int64)(max_value) }

/* Bison-only copy of the ALTER SYSTEM verifier registry. Use canonical config names. */
/* Names must remain in cm_compare_text_ins dictionary order for binary lookup. */
static const sql_bison_sys_param_verifier_t g_bison_sys_param_verifiers[] = {
    SQL_BISON_PARAM("ALARM_LOG_DIR", sql_bison_extra_als_file_dir),
    SQL_BISON_PARAM("ARCHIVE_CONFIG", sql_bison_extra_als_log_archive_config),
    SQL_BISON_PARAM("ARCHIVE_DEST_1", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_10", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_2", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_3", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_4", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_5", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_6", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_7", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_8", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_9", sql_bison_extra_als_log_archive_dest_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_1", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_10", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_2", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_3", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_4", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_5", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_6", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_7", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_8", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_DEST_STATE_9", sql_bison_extra_als_log_archive_dest_state_n),
    SQL_BISON_PARAM("ARCHIVE_FORMAT", sql_bison_verify_comm),
    SQL_BISON_PARAM("ARCHIVE_FORMAT_WITH_LSN", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("ARCHIVE_MAX_THREADS", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("ARCHIVE_MIN_SUCCEED_DEST", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("ARCHIVE_TRACE", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("ARCH_CLEAN_IGNORE_BACKUP", sql_bison_verify_bool),
    SQL_BISON_PARAM("ARCH_CLEAN_IGNORE_STANDBY", sql_bison_verify_bool),
    SQL_BISON_PARAM("ARCH_CLEAN_LOWER_LIMIT", sql_bison_extra_als_arch_lower_limit),
    SQL_BISON_PARAM("ARCH_CLEAN_UPPER_LIMIT", sql_bison_extra_als_arch_upper_limit),
    SQL_BISON_PARAM_RANGE("ARCH_FILE_SIZE", sql_bison_verify_pool_size,
        BUDDY_MIN_ARCH_FILE_SIZE, BUDDY_MAX_ARCH_FILE_SIZE),
    SQL_BISON_PARAM("ARCH_LOG_CHECK", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("ARCH_SIZE", sql_bison_verify_pool_size,
        0, OG_MAX_BACKUP_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("ARCH_TIME", sql_bison_verify_pool_size,
        OG_MIN_ARCH_TIME, OG_MAX_ARCH_TIME),
    SQL_BISON_PARAM("ARRAY_STORAGE_OPTIMIZATION", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("AUDIT_LEVEL", sql_bison_verify_uint32_range,
        0, DDL_AUDIT_ALL),
    SQL_BISON_PARAM("AUDIT_SYSLOG_LEVEL", sql_bison_extra_als_audit_syslog_level),
    SQL_BISON_PARAM("AUDIT_TRAIL_MODE", sql_bison_extra_als_audit_trail_mode),
    SQL_BISON_PARAM_RANGE("AUTONOMOUS_SESSIONS", sql_bison_verify_uint32_range,
        1, OG_MAX_AUTON_SESSIONS),
    SQL_BISON_PARAM("AUTO_INHERIT_USER", sql_bison_verify_onoff),
    SQL_BISON_PARAM_RANGE("BACKUP_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_MIN_BACKUP_BUF_SIZE, OG_MAX_BACKUP_BUF_SIZE),
    SQL_BISON_PARAM("BACKUP_RETRY", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("BATCH_FLUSH_CAPACITY", sql_bison_verify_uint32_range,
        OG_MIN_BATCH_FLUSH_CAPACITY, OG_MAX_BATCH_FLUSH_CAPACITY),
    SQL_BISON_PARAM("BLOCK_REPAIR_ENABLE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("BLOCK_REPAIR_TIMEOUT", sql_bison_verify_uint32_range,
        1, ABR_MAX_TIMEOUT),
    SQL_BISON_PARAM_RANGE("BUFFER_LRU_SEARCH_THRE", sql_bison_verify_uint32_range,
        OG_MIN_LRU_SEARCH_THRESHOLD, OG_MAX_LRU_SEARCH_THRESHOLD),
    SQL_BISON_PARAM_RANGE("BUFFER_PAGE_CLEAN_PERIOD", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("BUFFER_PAGE_CLEAN_RATIO", sql_bison_extra_als_page_clean_ratio),
    SQL_BISON_PARAM_RANGE("BUF_POOL_NUM", sql_bison_verify_uint32_range,
        1, OG_MAX_BUF_POOL_NUM),
    SQL_BISON_PARAM("BUILD_DATAFILE_PARALLEL", sql_bison_verify_bool),
    SQL_BISON_PARAM("BUILD_DATAFILE_PREALLOCATE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("BUILD_KEEP_ALIVE_TIMEOUT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("CBO", sql_bison_verify_onoff),
    SQL_BISON_PARAM("CBO_HINT_ENABLED", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("CBO_INDEX_CACHING", sql_bison_verify_uint32_range,
        0, CBO_MAX_INDEX_CACHING),
    SQL_BISON_PARAM_RANGE("CBO_INDEX_COST_ADJ", sql_bison_verify_uint32_range,
        CBO_MIN_INDEX_COST_ADJ, CBO_MAX_INDEX_COST_ADJ),
    SQL_BISON_PARAM_RANGE("CBO_PATH_CACHING", sql_bison_verify_uint32_range,
        CBO_MIN_PATH_CACHING, CBO_MAX_PATH_CACHING),
    SQL_BISON_PARAM_RANGE("CHECKPOINT_GROUP_SIZE", sql_bison_verify_uint32_range,
        OG_MIN_CKPT_GROUP_SIZE, OG_MAX_CKPT_GROUP_SIZE),
    SQL_BISON_PARAM("CHECKPOINT_IO_CAPACITY", sql_bison_extra_als_checkpoint_io_capacity),
    SQL_BISON_PARAM_RANGE("CHECKPOINT_PAGES", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("CHECKPOINT_PERIOD", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM("CLUSTER_DATABASE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("CLUSTER_ID", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("CLUSTER_NO_CMS", sql_bison_verify_bool),
    SQL_BISON_PARAM("COMMIT_MODE", sql_bison_extra_als_commit_logging),
    SQL_BISON_PARAM("COMMIT_ON_DISCONNECT", sql_bison_verify_bool),
    SQL_BISON_PARAM("COMMIT_WAIT_LOGGING", sql_bison_extra_als_commit_wait),
    SQL_BISON_PARAM("CONTROL_FILES", sql_bison_verify_comm),
    SQL_BISON_PARAM("COVERAGE_ENABLE", sql_bison_verify_bool),
    SQL_BISON_PARAM("CPU_GROUP_INFO", sql_bison_extra_als_cpu_inf_str),
    SQL_BISON_PARAM("CPU_NODE_BIND", sql_bison_verify_cpu_node_bind),
    SQL_BISON_PARAM_RANGE("CREATE_INDEX_PARALLELISM", sql_bison_verify_uint32_range,
        OG_MIN_CREATE_INDEX_PARALLELISM, OG_MAX_CREATE_INDEX_PARALLELISM),
    SQL_BISON_PARAM("CR_MODE", sql_bison_extra_als_cr_mode),
    SQL_BISON_PARAM_RANGE("CR_POOL_COUNT", sql_bison_verify_uint32_range,
        1, OG_MAX_CR_POOL_COUNT),
    SQL_BISON_PARAM_RANGE("CR_POOL_SIZE", sql_bison_verify_pool_size,
        OG_MIN_CR_POOL_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM("CTRLLOG_BACKUP_LEVEL", sql_bison_extra_als_ctrllog_backup_level),
    SQL_BISON_PARAM_RANGE("DATA_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_MIN_DATA_BUFFER_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM("DBSTOR_DEPLOY_MODE", sql_bison_verify_zero_one),
    SQL_BISON_PARAM("DBSTOR_NAMESPACE", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("DBWR_PROCESSES", sql_bison_verify_uint32_range,
        1, OG_MAX_DBWR_PROCESS),
    SQL_BISON_PARAM("DB_FILE_NAME_CONVERT", sql_bison_extra_als_convert),
    SQL_BISON_PARAM("DB_ISOLEVEL", sql_bison_extra_als_db_isolevel),
    SQL_BISON_PARAM("DB_TIMEZONE", sql_bison_extra_als_db_tz),
    SQL_BISON_PARAM_RANGE("DDL_LOCK_TIMEOUT", sql_bison_verify_uint32_range,
        OG_MIN_DDL_LOCK_TIMEOUT, OG_MAX_DDL_LOCK_TIMEOUT),
    SQL_BISON_PARAM("DEFAULT_EXTENTS", sql_bison_extra_als_default_extents),
    SQL_BISON_PARAM("DEFAULT_TABLESPACE_TYPE", sql_bison_extra_als_default_space_type),
    SQL_BISON_PARAM("DEGRADE_SEARCH_MAP", sql_bison_verify_bool),
    SQL_BISON_PARAM("DELAY_CLEANOUT", sql_bison_verify_bool),
    SQL_BISON_PARAM("DRC_IN_REFORMER_MODE", sql_bison_verify_bool),
    SQL_BISON_PARAM("DROP_NOLOGGING", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("DSS_LOG_LEVEL", sql_bison_verify_uint32_range,
        0, OG_MAX_DSS_LOG_LEVEL),
    SQL_BISON_PARAM("DTC_CKPT_NOTIFY_TASK_RATIO", sql_bison_extra_als_mes_task_ratio),
    SQL_BISON_PARAM("DTC_CLEAN_EDP_TASK_RATIO", sql_bison_extra_als_mes_task_ratio),
    SQL_BISON_PARAM("DTC_RCY_PARAL_BUF_LIST_SIZE", sql_bison_extra_dtc_rcy_paral_buf_list_size),
    SQL_BISON_PARAM("DTC_TXN_INFO_TASK_RATIO", sql_bison_extra_als_mes_task_ratio),
    SQL_BISON_PARAM("EMPTY_STRING_AS_NULL", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_ACCESS_DC", sql_bison_extra_als_bool_only_sys_allowed),
    SQL_BISON_PARAM("ENABLE_ARCH_COMPRESS", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_BROADCAST_ON_COMMIT", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_CHECK_SECURITY_LOG", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_DBSTOR", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_DBSTOR_BATCH_FLUSH", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_DSS", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_ERR_SUPERPOSED", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_FDSA", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_HASH_JOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_HWN_CHANGE", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_IDX_CONFS_NAME_DUPL", sql_bison_extra_als_idx_duplicate_enable),
    SQL_BISON_PARAM("ENABLE_IDX_KEY_LEN_CHECK", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_LOCAL_INFILE", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_MERGE_JOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_NESTLOOP_JOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_OGRAC_STATS", sql_bison_verify_onoff),
    SQL_BISON_PARAM("ENABLE_PASSWORD_CIPHER", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_PERMISSIVE_UNICODE", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_QUICK_CKPT", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_RAFT", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_SAMPLE_LIMIT", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_SYSDBA_LOGIN", sql_bison_extra_als_bool_only_sys_allowed),
    SQL_BISON_PARAM("ENABLE_SYSDBA_REMOTE_LOGIN", sql_bison_extra_als_bool_only_sys_allowed),
    SQL_BISON_PARAM("ENABLE_SYS_CRC_CHECK", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_SYS_REMOTE_LOGIN", sql_bison_extra_als_bool_only_sys_allowed),
    SQL_BISON_PARAM("ENABLE_TEMP_SPACE_BITMAP", sql_bison_verify_bool),
    SQL_BISON_PARAM("ENABLE_TX_FREE_PAGE_LIST", sql_bison_verify_bool),
    SQL_BISON_PARAM("FILE_OPTIONS", sql_bison_extra_als_filesystemio_options),
    SQL_BISON_PARAM_RANGE("HASH_AREA_SIZE", sql_bison_verify_pool_size,
        0, PMA_MAX_SIZE),
    SQL_BISON_PARAM_RANGE("HASH_TABLE_PAGES_HOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_HASH_PAGES_HOLD),
    SQL_BISON_PARAM("HAVE_SSL", sql_bison_extra_als_have_ssl),
    SQL_BISON_PARAM_RANGE("INDEX_DEFER_RECYCLE_TIME", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("INIT_LOCK_POOL_PAGES", sql_bison_verify_uint32_range,
        OG_MIN_LOCK_PAGES, OG_MAX_LOCK_PAGES),
    SQL_BISON_PARAM_RANGE("INI_TRANS", sql_bison_verify_uint32_range,
        1, OG_MAX_TRANS),
    SQL_BISON_PARAM_RANGE("INSTANCE_ID", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("INSTANCE_NAME", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("INTERACTIVE_TIMEOUT", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM("INTERCONNECT_ADDR", sql_bison_extra_als_ip),
    SQL_BISON_PARAM("INTERCONNECT_BY_PROFILE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("INTERCONNECT_CHANNEL_NUM", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("INTERCONNECT_PORT", sql_bison_extra_als_interconnect_port),
    SQL_BISON_PARAM("INTERCONNECT_TYPE", sql_bison_extra_als_interconnect_type),
    SQL_BISON_PARAM_RANGE("INT_SYSINDEX_TRANS", sql_bison_verify_uint32_range,
        OG_INI_TRANS, OG_MAX_SYSINDEX_TRANS),
    SQL_BISON_PARAM_RANGE("JOB_THREADS", sql_bison_verify_uint32_range,
        0, OG_MAX_JOB_THREADS),
    SQL_BISON_PARAM("KMC_KEY_FILES", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("KNL_AUTONOMOUS_SESSIONS", sql_bison_verify_uint32_range,
        1, OG_MAX_AUTON_SESSIONS),
    SQL_BISON_PARAM_RANGE("LARGE_POOL_SIZE", sql_bison_verify_pool_size,
        OG_MIN_LARGE_POOL_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("LARGE_VARIANT_MEMORY_AREA_SIZE", sql_bison_verify_pool_size,
        OG_MIN_LARGE_VMA_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("LOB_REUSE_THRESHOLD", sql_bison_verify_pool_size,
        OG_MIN_LOB_REUSE_SIZE, OG_INVALID_ID32),
    SQL_BISON_PARAM("LOCAL_KEY", sql_bison_extra_als_local_key),
    SQL_BISON_PARAM("LOCAL_RBP_HOST", sql_bison_verify_local_rbp_host),
    SQL_BISON_PARAM("LOCAL_TEMPORARY_TABLE_ENABLED", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("LOCK_WAIT_TIMEOUT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("LOG_BUFFER_COUNT", sql_bison_verify_uint32_range,
        OG_MIN_LOG_BUFFERS, OG_MAX_LOG_BUFFERS),
    SQL_BISON_PARAM_RANGE("LOG_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_MIN_LOG_BUFFER_SIZE, OG_MAX_LOG_BUFFER_SIZE),
    SQL_BISON_PARAM("LOG_FILE_NAME_CONVERT", sql_bison_extra_als_convert),
    SQL_BISON_PARAM("LOG_HOME", sql_bison_extra_als_file_dir),
    SQL_BISON_PARAM_RANGE("LOG_REPLAY_PROCESSES", sql_bison_verify_uint32_range,
        OG_DEFAULT_PARAL_RCY, OG_MAX_PARAL_RCY),
    SQL_BISON_PARAM("LSNR_ADDR", sql_bison_extra_als_ip),
    SQL_BISON_PARAM_RANGE("LSNR_PORT", sql_bison_verify_uint32_range,
        OG_MIN_PORT, OG_MAX_UINT16),
    SQL_BISON_PARAM_RANGE("MASTER_SLAVE_DIFFTIME", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("MAX_ALLOWED_PACKET", sql_bison_verify_pool_size,
        OG_MAX_PACKET_SIZE, OG_MAX_ALLOWED_PACKET_SIZE),
    SQL_BISON_PARAM_RANGE("MAX_ARCH_FILES_SIZE", sql_bison_verify_pool_size,
        0, OG_MAX_ARCH_FILES_SIZE),
    SQL_BISON_PARAM("MAX_COLUMN_COUNT", sql_bison_extra_als_max_column_count),
    SQL_BISON_PARAM_RANGE("MAX_LINK_TABLES", sql_bison_verify_uint32_range,
        0, OG_MAX_LINK_TABLES),
    SQL_BISON_PARAM_RANGE("MAX_PBL_FILE_SIZE", sql_bison_verify_pool_size,
        OG_MIN_PBL_FILE_SIZE, OG_MAX_PBL_FILE_SIZE),
    SQL_BISON_PARAM_RANGE("MAX_REMOTE_PARAMS", sql_bison_verify_uint32_range,
        0, OG_MAX_SQL_PARAM_COUNT),
    SQL_BISON_PARAM_RANGE("MAX_TEMP_TABLES", sql_bison_verify_uint32_range,
        OG_RESERVED_TEMP_TABLES, OG_MAX_TEMP_TABLES),
    SQL_BISON_PARAM_RANGE("MAX_WORKER_THREADS", sql_bison_verify_uint32_range,
        OG_MIN_OPTIMIZED_WORKER_COUNT, OG_MAX_OPTIMIZED_WORKER_COUNT),
    SQL_BISON_PARAM_RANGE("MERGE_SORT_BATCH_SIZE", sql_bison_verify_uint32_range,
        OG_MIN_MERGE_SORT_BATCH_SIZE, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("MES_CHANNEL_DEGRADE_TIME_MS", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("MES_CHANNEL_UPGRADE_TIME_MS", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("MES_CPU_INFO", sql_bison_extra_als_cpu_inf_str),
    SQL_BISON_PARAM("MES_CRC_CHECK_SWITCH", sql_bison_verify_bool),
    SQL_BISON_PARAM("MES_ELAPSED_SWITCH", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("MES_POOL_SIZE", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("MES_SSL_CRT_KEY_PATH", sql_bison_extra_als_file_dir),
    SQL_BISON_PARAM("MES_SSL_KEY_PWD", sql_bison_verify_comm),
    SQL_BISON_PARAM("MES_SSL_SWITCH", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("NBU_BACKUP_TIMEOUT", sql_bison_verify_uint32_range,
        OG_NBU_BACKUP_MIN_WAIT_TIME, OG_INVALID_ID32),
    SQL_BISON_PARAM("NODE_LOCK_STATUS", sql_bison_extra_als_node_lock_status),
    SQL_BISON_PARAM("NORMAL_USER_RESERVED_SESSIONS_FACTOR", sql_bison_extra_normal_emerge_sess_factor),
    SQL_BISON_PARAM_RANGE("OGRAC_TASK_NUM", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("OGSTORE_INST_PATH", sql_bison_extra_als_uds_file_path),
    SQL_BISON_PARAM_RANGE("OGSTORE_MAX_OPEN_FILES", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("OG_CLUSTER_STRICT_CHECK", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("OG_GDV_SQL_SESS_TMOUT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("OPEN_CURSORS", sql_bison_verify_uint32_range,
        OG_MIN_OPEN_CURSORS, OG_MAX_OPEN_CURSORS),
    SQL_BISON_PARAM_RANGE("OPTIMIZED_WORKER_THREADS", sql_bison_verify_uint32_range,
        OG_MIN_OPTIMIZED_WORKER_COUNT, OG_MAX_OPTIMIZED_WORKER_COUNT),
    SQL_BISON_PARAM("PAGE_CHECKSUM", sql_bison_extra_als_db_block_checksum),
    SQL_BISON_PARAM("PAGE_CLEAN_MODE", sql_bison_extra_als_page_clean_mode),
    SQL_BISON_PARAM("PAGE_SIZE", sql_bison_extra_als_page_size),
    SQL_BISON_PARAM_RANGE("PARALLEL_MAX_THREADS", sql_bison_verify_uint32_range,
        0, OG_PARALLEL_MAX_THREADS),
    SQL_BISON_PARAM("PARALLEL_POLICY", sql_bison_verify_onoff),
    SQL_BISON_PARAM("PLAN_DISPLAY_FORMAT", sql_bison_extra_als_plan_display_format),
    SQL_BISON_PARAM_RANGE("PMA_BUFFER_SIZE", sql_bison_verify_pool_size,
        0, PMA_MAX_SIZE),
    SQL_BISON_PARAM("QUORUM_ANY", sql_bison_extra_als_quorum_any),
    SQL_BISON_PARAM_RANGE("RAFT_ELECTION_TIMEOUT", sql_bison_verify_uint32_range,
        OG_MIN_RAFT_ELECTION_TIMEOUT, OG_MAX_RAFT_ELECTION_TIMEOUT),
    SQL_BISON_PARAM_RANGE("RAFT_FAILOVER_LIB_TIMEOUT", sql_bison_verify_uint32_range,
        OG_MIN_RAFT_FAILOVER_WAIT_TIME, OG_INVALID_ID32),
    SQL_BISON_PARAM("RAFT_KUDU_DIR", sql_bison_verify_comm),
    SQL_BISON_PARAM("RAFT_LAYOUT_INFO", sql_bison_verify_comm),
    SQL_BISON_PARAM("RAFT_LOCAL_ADDR", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("RAFT_LOG_ASYNC_BUF_NUM", sql_bison_verify_uint32_range,
        1, OG_MAX_RAFT_LOG_ASYNC_BUF),
    SQL_BISON_PARAM_RANGE("RAFT_LOG_LEVEL", sql_bison_verify_uint32_range,
        0, OG_MAX_RAFT_LOG_LEVELE),
    SQL_BISON_PARAM("RAFT_MAX_SIZE_PER_MSG", sql_bison_verify_comm),
    SQL_BISON_PARAM("RAFT_MEMORY_THRESHOLD", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("RAFT_NODE_ID", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM("RAFT_PEER_ADDRS", sql_bison_verify_comm),
    SQL_BISON_PARAM("RAFT_PEER_IDS", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("RAFT_PENDING_CMDS_BUFFER_SIZE", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("RAFT_PRIORITY_LEVEL", sql_bison_verify_uint32_range,
        0, OG_MAX_RAFT_PRIORITY_LEVEL),
    SQL_BISON_PARAM("RAFT_PRIORITY_TYPE", sql_bison_extra_als_raft_priority_type),
    SQL_BISON_PARAM("RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("RAFT_RECEIVE_BUFFER_SIZE", sql_bison_verify_uint32_range,
        1, OG_MAX_RAFT_RECEIVE_BUFFER_SIZE),
    SQL_BISON_PARAM_RANGE("RAFT_SEND_BUFFER_SIZE", sql_bison_verify_uint32_range,
        1, OG_MAX_RAFT_SEND_BUFFER_SIZE),
    SQL_BISON_PARAM_RANGE("RAFT_START_MODE", sql_bison_verify_uint32_range,
        0, OG_MAX_RAFT_START_MODE),
    SQL_BISON_PARAM("RAFT_TLS_DIR", sql_bison_extra_als_raft_tls_dir),
    SQL_BISON_PARAM("RAFT_TOKEN_VERIFY", sql_bison_extra_als_raft_token_verify),
    SQL_BISON_PARAM_RANGE("RBP_ASSEMBLE_MAX_SCAN", sql_bison_verify_uint32_range,
        RBP_ASSEMBLE_MAX_SCAN_MIN, RBP_ASSEMBLE_MAX_SCAN_MAX),
    SQL_BISON_PARAM("RBP_FOR_RECOVERY", sql_bison_verify_rbp_bool),
    SQL_BISON_PARAM("RBP_IP", sql_bison_verify_rbp_ip),
    SQL_BISON_PARAM_RANGE("RBP_PORT", sql_bison_verify_uint32_range,
        OG_MIN_PORT, OG_MAX_UINT16),
    SQL_BISON_PARAM("RBP_RT_ANALYSIS", sql_bison_verify_rbp_bool),
    SQL_BISON_PARAM_RANGE("RBP_RT_PAGE_OWNER_WORKERS", sql_bison_verify_uint32_range,
        1, DTC_RBP_RT_MAX_OWNER_WORKERS),
    SQL_BISON_PARAM_RANGE("RBP_RT_PARSE_WORKERS", sql_bison_verify_uint32_range,
        1, DTC_RBP_RT_MAX_PARSE_WORKERS),
    SQL_BISON_PARAM_RANGE("RCY_NODE_READ_BUF_SIZE", sql_bison_verify_uint32_range,
        OG_MIN_RCY_NODE_BUF_SIZE, OG_MAX_RCY_NODE_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("REACTOR_THREADS", sql_bison_verify_uint32_range,
        1, OG_MAX_REACTOR_POOL_COUNT),
    SQL_BISON_PARAM_RANGE("REACTOR_THREAD_NUM", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("RECYCLEBIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("REPLACE_PASSWORD_VERIFY", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("REPLAY_PRELOAD_PROCESSES", sql_bison_verify_uint32_range,
        0, OG_MAX_PARAL_RCY),
    SQL_BISON_PARAM("REPL_ADDR", sql_bison_extra_als_ip),
    SQL_BISON_PARAM("REPL_AUTH", sql_bison_verify_bool),
    SQL_BISON_PARAM("REPL_PORT", sql_bison_verify_repl_port),
    SQL_BISON_PARAM("REPL_SCRAM_AUTH", sql_bison_verify_bool),
    SQL_BISON_PARAM("REPL_TRUST_HOST", sql_bison_extra_als_ip),
    SQL_BISON_PARAM_RANGE("REPL_WAIT_TIMEOUT", sql_bison_verify_uint32_range,
        OG_REPL_MIN_WAIT_TIME, OG_INVALID_ID32),
    SQL_BISON_PARAM("RESOURCE_LIMIT", sql_bison_verify_bool),
    SQL_BISON_PARAM("RESOURCE_PLAN", sql_bison_verify_comm),
    SQL_BISON_PARAM("RESTORE_ARCH_COMPRESSED", sql_bison_verify_bool),
    SQL_BISON_PARAM("RESTOR_ARCH_PREFER_BAK_SET", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("RES_RECYCLE_RATIO", sql_bison_verify_uint32_range,
        OG_MIN_RES_RECYCLE_RATIO, OG_MAX_RES_RECYCLE_RATIO),
    SQL_BISON_PARAM("ROW_FORMAT", sql_bison_extra_als_row_format),
    SQL_BISON_PARAM_RANGE("SEGMENT_PAGES_HOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_SEGMENT_PAGES_HOLD),
    SQL_BISON_PARAM("SESSIONS", sql_bison_extra_als_sessions),
    SQL_BISON_PARAM("SHARED_PATH", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("SHARED_POOL_SIZE", sql_bison_verify_pool_size,
        OG_MIN_SHARED_POOL_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM("SLOWSQL_STATS_ENABLE", sql_bison_verify_bool),
    SQL_BISON_PARAM("SQL_COMPAT", sql_bison_extra_als_sql_compat),
    SQL_BISON_PARAM("SQL_STAGE_THRESHOLD", sql_bison_verify_comm),
    SQL_BISON_PARAM("SQL_STAT", sql_bison_verify_bool),
    SQL_BISON_PARAM("SSL_CA", sql_bison_extra_als_ssl_file),
    SQL_BISON_PARAM("SSL_CERT", sql_bison_extra_als_ssl_file),
    SQL_BISON_PARAM("SSL_CIPHER", sql_bison_extra_als_ssl_cipher),
    SQL_BISON_PARAM("SSL_CRL", sql_bison_extra_als_ssl_file),
    SQL_BISON_PARAM("SSL_EXPIRE_ALERT_THRESHOLD", sql_bison_extra_ssl_alt_threshold),
    SQL_BISON_PARAM("SSL_KEY", sql_bison_extra_als_ssl_file),
    SQL_BISON_PARAM("SSL_KEY_PASSWORD", sql_bison_verify_comm),
    SQL_BISON_PARAM("SSL_PERIOD_DETECTION", sql_bison_extra_ssl_period_detection),
    SQL_BISON_PARAM("SSL_VERIFY_PEER", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("STATISTICS_SAMPLE_SIZE", sql_bison_verify_pool_size,
        OG_MIN_SAMPLE_SIZE, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("STATS_COST_DELAY", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("STATS_COST_LIMIT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("STATS_ENABLE_PARALL", sql_bison_verify_bool),
    SQL_BISON_PARAM("STATS_LEVEL", sql_bison_extra_als_statistics_level),
    SQL_BISON_PARAM_RANGE("STATS_MAX_BUCKET_SIZE", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("STATS_PARALL_THREADS", sql_bison_verify_uint32_range,
        OG_MIN_STATS_PARALL_THREADS, OG_MAX_STATS_PARALL_THREADS),
    SQL_BISON_PARAM("STRING_AS_HEX_FOR_BINARY", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("SUPER_USER_RESERVED_SESSIONS", sql_bison_verify_uint32_range,
        1, OG_MAX_EMERG_SESSIONS),
    SQL_BISON_PARAM_RANGE("TABLESPACE_USAGE_ALARM_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_SPC_ALARM_THRESHOLD),
    SQL_BISON_PARAM("TCP_EXCLUDED_NODES", sql_bison_verify_comm),
    SQL_BISON_PARAM("TCP_INVITED_NODES", sql_bison_verify_comm),
    SQL_BISON_PARAM("TCP_VALID_NODE_CHECKING", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("TC_LEVEL", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("TEMP_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_MIN_TEMP_BUFFER_SIZE, OG_MAX_TEMP_BUFFER_SIZE),
    SQL_BISON_PARAM_RANGE("TEMP_POOL_NUM", sql_bison_verify_uint32_range,
        1, OG_MAX_TEMP_POOL_NUM),
    SQL_BISON_PARAM("TIMED_STATS", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("TXN_UNDO_USAGE_ALARM_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_TXN_UNDO_ALARM_THRESHOLD),
    SQL_BISON_PARAM("TYPE_MAP_FILE", NULL),
    SQL_BISON_PARAM("UDS_FILE_PATH", sql_bison_extra_als_uds_file_path),
    SQL_BISON_PARAM("UDS_FILE_PERMISSIONS", sql_bison_extra_als_uds_file_permissions),
    SQL_BISON_PARAM_RANGE("UNAUTH_SESSION_EXPIRE_TIME", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("UNDO_PREFETCH_PAGE_NUM", sql_bison_verify_uint32_range,
        OG_MIN_UNDO_PREFETCH_PAGES, OG_MAX_UNDO_PREFETCH_PAGES),
    SQL_BISON_PARAM_RANGE("UNDO_RESERVE_SIZE", sql_bison_verify_uint32_range,
        OG_UNDO_MIN_RESERVE_SIZE, OG_UNDO_MAX_RESERVE_SIZE),
    SQL_BISON_PARAM_RANGE("UNDO_RETENTION_TIME", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM("UNDO_TABLESPACE", sql_bison_verify_comm),
    SQL_BISON_PARAM_RANGE("UNDO_USAGE_ALARM_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_UNDO_ALARM_THRESHOLD),
    SQL_BISON_PARAM("UPPER_CASE_TABLE_NAMES", sql_bison_verify_bool),
    SQL_BISON_PARAM("USE_BISON_PARSER", sql_bison_verify_bool),
    SQL_BISON_PARAM("USE_LARGE_PAGES", sql_bison_verify_bool),
    SQL_BISON_PARAM("USE_NATIVE_DATATYPE", sql_bison_verify_bool),
    SQL_BISON_PARAM("USE_RBP", sql_bison_verify_rbp_bool),
    SQL_BISON_PARAM_RANGE("VARIANT_MEMORY_AREA_SIZE", sql_bison_verify_pool_size,
        OG_MIN_VMA_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("WORKER_THREADS", sql_bison_verify_uint32_range,
        OG_MIN_WORKER_THREADS, OG_MAX_WORKER_THREADS),
    SQL_BISON_PARAM_RANGE("WORKER_THREADS_SHRINK_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_SECS_AGENTS_SHRINK),
    SQL_BISON_PARAM("XA_FORMAT_ID", sql_bison_extra_als_xa_format_id),
    SQL_BISON_PARAM_RANGE("XA_SUSPEND_TIMEOUT", sql_bison_verify_uint32_range,
        1, OG_MAX_SUSPEND_TIMEOUT),
    SQL_BISON_PARAM("ZERO_DIVISOR_ACCEPTED", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_AGENT_STACK_SIZE", sql_bison_verify_pool_size,
        OG_MIN_STACK_SIZE, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_ASHRINK_WAIT_TIME", sql_bison_verify_uint32_range,
        OG_MIN_ASHRINK_WAIT_TIME, OG_MAX_ASHRINK_WAIT_TIME),
    SQL_BISON_PARAM_RANGE("_AUDIT_BACKUP_FILE_COUNT", sql_bison_verify_uint32_range,
        0, OG_MAX_LOG_FILE_COUNT),
    SQL_BISON_PARAM_RANGE("_AUDIT_MAX_FILE_SIZE", sql_bison_verify_pool_size,
        OG_MIN_LOG_FILE_SIZE, OG_MAX_LOG_FILE_SIZE),
    SQL_BISON_PARAM("_AUTO_INDEX_RECYCLE", sql_bison_extra_als_auto_index_recycle),
    SQL_BISON_PARAM_RANGE("_AUTO_UNDO_RETENTION", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_BACKUP_LOG_PARALLEL", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_BLACKBOX_STACK_DEPTH", sql_bison_verify_uint32_range,
        OG_INIT_BLACK_BOX_DEPTH, OG_MAX_BLACK_BOX_DEPTH),
    SQL_BISON_PARAM_RANGE("_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_CHECKPOINT_MERGE_IO", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_CHECKPOINT_TIMED_TASK_DELAY", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_CHECK_SYSDATA_VERSION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_CONNECT_BY_MATERIALIZE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_DEADLOCK_DETECT_INTERVAL", sql_bison_extra_als_deadlock_detect_interval),
    SQL_BISON_PARAM("_DISABLE_SOFT_PARSE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_DISTINCT_PRUNING", sql_bison_verify_onoff),
    SQL_BISON_PARAM("_DOUBLEWRITE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_ENABLE_MULTI_INDEX_SCAN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_ENABLE_QOS", sql_bison_verify_bool),
    SQL_BISON_PARAM("_ENABLE_RMO_CR", sql_bison_verify_bool),
    SQL_BISON_PARAM("_ENCRYPTION_ALG", sql_bison_extra_als_encryption_alg),
    SQL_BISON_PARAM_RANGE("_ENCRYPTION_ITERATION", sql_bison_verify_uint32_range,
        OG_KDF2MINITERATION, OG_KDF2MAXITERATION),
    SQL_BISON_PARAM("_FACTOR_KEY", sql_bison_extra_als_factor_key),
    SQL_BISON_PARAM_RANGE("_FORCE_INDEX_RECYCLE", sql_bison_verify_uint32_range,
        0, OG_MAX_INDEX_FORCE_RECYCLE),
    SQL_BISON_PARAM_RANGE("_HINT_FORCE", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_INDEX_AUTO_REBUILD", sql_bison_verify_bool),
    SQL_BISON_PARAM("_INDEX_AUTO_REBUILD_START_TIME", sql_bison_extra_als_index_auto_rebuild_start_time),
    SQL_BISON_PARAM_RANGE("_INDEX_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_MIN_INDEX_CACHE_SIZE, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM_RANGE("_INDEX_REBUILD_KEEP_STORAGE", sql_bison_verify_uint32_range,
        0, OG_MAX_INDEX_REBUILD_STORAGE),
    SQL_BISON_PARAM_RANGE("_INDEX_RECYCLE_PERCENT", sql_bison_verify_uint32_range,
        0, OG_MAX_INDEX_RECYCLE_PERCENT),
    SQL_BISON_PARAM_RANGE("_INDEX_RECYCLE_REUSE", sql_bison_verify_uint32_range,
        0, OG_MAX_INDEX_RECYCLE_REUSE),
    SQL_BISON_PARAM_RANGE("_INDEX_RECYCLE_SIZE", sql_bison_verify_pool_size,
        OG_MIN_INDEX_RECYCLE_SIZE, OG_MAX_INDEX_RECYCLE_SIZE),
    SQL_BISON_PARAM_RANGE("_INDEX_SCAN_RANGE_CACHE", sql_bison_verify_uint32_range,
        OG_MIN_OPT_THRESHOLD, OG_MAX_OPT_THRESHOLD),
    SQL_BISON_PARAM_RANGE("_INIT_CURSORS", sql_bison_verify_uint32_range,
        0, OG_MAX_INIT_CURSORS),
    SQL_BISON_PARAM_RANGE("_LNS_WAIT_TIME", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_LOB_MAX_EXEC_SIZE", sql_bison_extra_als_lob_max_exec_size),
    SQL_BISON_PARAM_RANGE("_LOG_BACKUP_FILE_COUNT", sql_bison_verify_uint32_range,
        0, OG_MAX_LOG_FILE_COUNT),
    SQL_BISON_PARAM("_LOG_FILE_PERMISSIONS", sql_bison_extra_als_log_file),
    SQL_BISON_PARAM("_LOG_LEVEL", sql_bison_verify_log_level),
    SQL_BISON_PARAM_RANGE("_LOG_MAX_FILE_SIZE", sql_bison_verify_pool_size,
        OG_MIN_LOG_FILE_SIZE, OG_MAX_LOG_FILE_SIZE),
    SQL_BISON_PARAM("_LOG_PATH_PERMISSIONS", sql_bison_extra_als_log_path),
    SQL_BISON_PARAM_RANGE("_MAX_CONNECT_BY_LEVEL", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_MAX_JSON_DYNAMIC_BUFFER_SIZE", sql_bison_verify_pool_size,
        OG_JSON_MIN_DYN_BUF_SIZE, OG_JSON_MAX_DYN_BUF_SIZE),
    SQL_BISON_PARAM("_MAX_RM_COUNT", sql_bison_extra_als_max_rm_count),
    SQL_BISON_PARAM_RANGE("_MAX_VM_FUNC_STACK_COUNT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_MRP_RES_LOGSIZE", sql_bison_verify_pool_size,
        0, OG_MAX_SGA_BUF_SIZE),
    SQL_BISON_PARAM("_OPTIMIZER_AGGR_PLACEMENT", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ADAPTIVE_FULL_OUTER_JOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ALL_TRANSFORM", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ANY_TRANSFORM", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_CONNECT_BY_PLACEMENT", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_DISTINCT_ELIMINATION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ENABLE_RIGHT_ANTIJOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ENABLE_RIGHT_LEFTJOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ENABLE_RIGHT_SEMIJOIN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_FILTER_PUSHDOWN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_FUNC_INDEX_SCAN_ONLY", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_GROUP_BY_ELIMINATION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_HASH_MATERIALIZE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_INDEX_COND_PRUNING", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_OPTIM_INDEX_SCAN_MAX_PARTS", sql_bison_verify_uint32_range,
        0, OG_MAX_MULTI_PARTS_NUM),
    SQL_BISON_PARAM("_OPTIM_IN_TRANSFORM", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_JOIN_ELIMINATION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_JOIN_PRED_PUSHDOWN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ORDER_BY_ELIMINATION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_ORDER_BY_PLACEMENT", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_OR_EXPANSION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_PRED_DELIVERY", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_PRED_MOVE_AROUND", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_PRED_PUSHDOWN", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_PRED_REORDER", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_PROJECT_LIST_PRUNING", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_SEMI2INNER", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_SIMPLIFY_EXISTS_SUBQ", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_SUBQUERY_ELIMINATION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_SUBQUERY_REWRITE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_UNNEST_SET_SUBQUERY", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_VM_VIEW_ENABLED", sql_bison_verify_bool),
    SQL_BISON_PARAM("_OPTIM_WINMAGIC_REWRITE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_OPT_CBO_STAT_SAMPLING_LEVEL", sql_bison_verify_uint32_range,
        0, CBO_MAX_DYN_SAMPLING_LEVEL),
    SQL_BISON_PARAM("_OUTER_JOIN_OPTIMIZATION", sql_bison_verify_onoff),
    SQL_BISON_PARAM_RANGE("_PREFETCH_ROWS", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_PRIVATE_KEY_LOCKS", sql_bison_verify_uint32_range,
        OG_MIN_PRIVATE_LOCKS, OG_MAX_PRIVATE_LOCKS),
    SQL_BISON_PARAM_RANGE("_PRIVATE_ROW_LOCKS", sql_bison_verify_uint32_range,
        OG_MIN_PRIVATE_LOCKS, OG_MAX_PRIVATE_LOCKS),
    SQL_BISON_PARAM("_QOS_CTRL_FACTOR", sql_bison_extra_als_qos_ctrl_fat),
    SQL_BISON_PARAM_RANGE("_QOS_RANDOM_RANGE", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_QOS_SLEEP_TIME", sql_bison_verify_uint32_range,
        1, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_QUERY_TOPN_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_TOPN_THRESHOLD),
    SQL_BISON_PARAM("_RCY_CHECK_PCN", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_RCY_SLEEP_INTERVAL", sql_bison_verify_uint32_range,
        OG_MIN_RCY_SLEEP_INTERVAL, OG_MAX_RCY_SLEEP_INTERVAL),
    SQL_BISON_PARAM_RANGE("_REMOTE_ACCESS_LIMIT", sql_bison_verify_uint32_range,
        0, OG_REMOTE_ACCESS_LIMIT),
    SQL_BISON_PARAM("_REPL_MAX_PKG_SIZE", sql_bison_extra_als_repl_max_pkg_size),
    SQL_BISON_PARAM("_RESERVED_SQL_CURSORS", sql_bison_extra_als_reserved_sql_cursors),
    SQL_BISON_PARAM("_RESTORE_CHECK_VERSION", sql_bison_verify_bool),
    SQL_BISON_PARAM("_SERIALIZED_COMMIT", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_SGA_CORE_DUMP_CONFIG", sql_bison_verify_uint32_range,
        0, OG_MAX_SGA_CORE_DUMP_CONFIG),
    SQL_BISON_PARAM("_SHOW_EXPLAIN_PREDICATE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_SHRINK_WAIT_RECYCLED_PAGES", sql_bison_verify_uint32_range,
        OG_MIN_SHRINK_WAIT_RECYCLED_PAGES, OG_MAX_SHRINK_WAIT_RECYCLED_PAGES),
    SQL_BISON_PARAM_RANGE("_SMALL_TABLE_SAMPLING_THRESHOLD", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_SPIN_COUNT", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM_RANGE("_SQL_CURSORS_EACH_SESSION", sql_bison_verify_uint32_range,
        0, OG_MAX_SQL_CURSORS_EACH_SESSION),
    SQL_BISON_PARAM("_SQL_POOL_FACTOR", sql_bison_extra_als_sql_pool_fat),
    SQL_BISON_PARAM("_STRICT_CASE_DATATYPE", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_SYSTIME_INCREASE_THREASHOLD", sql_bison_verify_uint32_range,
        0, OG_MAX_SYSTIME_INC_THRE),
    SQL_BISON_PARAM("_SYS_PASSWORD", sql_bison_extra_als_sys_password),
    SQL_BISON_PARAM("_TABLE_COMPRESS_ALGO", sql_bison_extra_als_compress_algo),
    SQL_BISON_PARAM("_TABLE_COMPRESS_BUFFER_SIZE", sql_bison_extra_als_compress_buf_size),
    SQL_BISON_PARAM("_TABLE_COMPRESS_ENABLE_BUFFER", sql_bison_verify_bool),
    SQL_BISON_PARAM("_TEMPTABLE_SUPPORT_BATCH_INSERT", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_THREAD_STACK_SIZE", sql_bison_verify_pool_size,
        OG_MIN_THREAD_STACK_SIZE, OG_MAX_THREAD_STACK_SIZE - OG_STACK_DEPTH_SLOP),
    SQL_BISON_PARAM_RANGE("_TX_ROLLBACK_PROC_NUM", sql_bison_verify_uint32_range,
        OG_MIN_ROLLBACK_PROC, OG_MAX_ROLLBACK_PROC),
    SQL_BISON_PARAM("_UNDO_ACTIVE_SEGMENTS", sql_bison_extra_als_active_undo_segments),
    SQL_BISON_PARAM("_UNDO_AUTON_BIND_OWN_SEGMENT", sql_bison_verify_bool),
    SQL_BISON_PARAM("_UNDO_AUTON_TRANS_SEGMENTS", sql_bison_extra_als_auton_trans_segments),
    SQL_BISON_PARAM("_UNDO_AUTO_SHRINK", sql_bison_verify_bool),
    SQL_BISON_PARAM("_UNDO_AUTO_SHRINK_INACTIVE", sql_bison_verify_bool),
    SQL_BISON_PARAM("_UNDO_PERF_PREALLOC", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_UNDO_PREALLOC_PAGES", sql_bison_verify_uint32_range,
        0, 65536),
    SQL_BISON_PARAM_RANGE("_UNDO_SEGMENTS", sql_bison_verify_uint32_range,
        OG_MIN_UNDO_SEGMENT, OG_MAX_UNDO_SEGMENT),
    SQL_BISON_PARAM_RANGE("_VARIANT_AREA_SIZE", sql_bison_verify_pool_size,
        OG_MIN_VARIANT_SIZE, OG_MAX_VARIANT_SIZE),
    SQL_BISON_PARAM("_VIEW_ACCESS_DC", sql_bison_extra_als_bool_only_sys_allowed),
    SQL_BISON_PARAM("_VMA_MEM_CHECK", sql_bison_verify_bool),
    SQL_BISON_PARAM_RANGE("_VMP_CACHES_EACH_SESSION", sql_bison_verify_uint32_range,
        0, OG_INVALID_ID32),
    SQL_BISON_PARAM("_WITHAS_SUBQUERY", sql_bison_extra_als_withas_subquery),
};

#undef SQL_BISON_PARAM_RANGE
#undef SQL_BISON_PARAM

static const sql_bison_sys_param_verifier_t *sql_bison_find_sys_param_verifier(const char *name)
{
    text_t search_name = {
        .str = (char *)name,
        .len = (uint32)strlen(name)
    };
    text_t verifier_name;

    for (uint32 left = 0, right = ELEMENT_COUNT(g_bison_sys_param_verifiers); left < right;) {
        uint32 mid = (left + right) >> 1;
        verifier_name.str = (char *)g_bison_sys_param_verifiers[mid].name;
        verifier_name.len = (uint32)strlen(g_bison_sys_param_verifiers[mid].name);
        int32 compare_result = cm_compare_text_ins(&search_name, &verifier_name);
        if (compare_result == 0) {
            return &g_bison_sys_param_verifiers[mid];
        } else if (compare_result < 0) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }
    return NULL;
}

status_t sql_bison_verify_sys_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def,
    bison_sys_param_value_t *value)
{
    config_item_t *item = NULL;
    knl_session_t *se = &stmt->session->knl_session;
    const sql_bison_sys_param_verifier_t *verifier;
    bison_sys_param_value_t verifier_value;
    bool32 has_outer_quote;

    if (value == NULL || value->text.str == NULL || value->text.len == 0) {
        return OG_ERROR;
    }

    if (IS_LOG_MODE(def->param)) {
        text_t name = {
            .str = "_LOG_LEVEL",
            .len = sizeof("_LOG_LEVEL") - 1
        };
        item = cm_get_config_item(GET_CONFIG, &name, OG_TRUE);
    } else {
        text_t name = {
            .str = def->param,
            .len = (uint32)strlen(def->param)
        };
        item = cm_get_config_item(GET_CONFIG, &name, OG_TRUE);
    }

    if (item == NULL) {
        OG_SRC_THROW_ERROR(value->loc, ERR_INVALID_PARAMETER_NAME, def->param);
        return OG_ERROR;
    }

    def->param_id = item->id;

    if (se->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON &&
        strcmp(def->param, "ARCH_TIME") == 0) {
        OG_THROW_ERROR(ERR_NOT_COMPATIBLE, "arch time while lrep_mode is LOG_REPLICATION_ON");
        return OG_ERROR;
    }

    has_outer_quote = value->text.len >= 2 && CM_IS_QUOTE_CHAR(value->text.str[0]) &&
        value->text.str[0] == CM_TEXT_END(&value->text);
    OG_RETURN_IFERR(sql_bison_copy_sys_param_value(value, def));
    verifier_value = *value;
    verifier_value.text.str = def->value;
    verifier_value.text.len = (uint32)strlen(def->value);
    verifier_value.decoded_string = verifier_value.text;
    verifier_value.is_string = has_outer_quote;
    verifier = sql_bison_find_sys_param_verifier(item->name);
    if (verifier != NULL && verifier->bison_verify != NULL) {
        return verifier->bison_verify((void *)se, (void *)&verifier_value, (void *)def,
            verifier->min_value, verifier->max_value);
    }

    if (verifier == NULL) {
        /* A parameter missing from the Bison registry is unsupported; never persist an unchecked value. */
        OG_SRC_THROW_ERROR_EX(value->loc, ERR_CAPABILITY_NOT_SUPPORT,
            "Bison ALTER SYSTEM verifier adapter for %s", def->param);
        return OG_ERROR;
    }

    OG_SRC_THROW_ERROR_EX(value->loc, ERR_SQL_SYNTAX_ERROR, "unexpected parameter value");
    return OG_ERROR;
}

status_t sql_bison_verify_debug_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def,
    bison_sys_param_value_t *value)
{
    debug_config_item_t *debug_params = NULL;
    debug_config_item_t *item = NULL;
    knl_session_t *se = &stmt->session->knl_session;
    const sql_bison_sys_param_verifier_t *verifier;
    uint32 count;

    if (value == NULL || value->text.str == NULL || value->text.len == 0) {
        return OG_ERROR;
    }

    srv_get_debug_config_info(&debug_params, &count);
    for (uint32 i = 0; i < count; i++) {
        if (cm_str_equal_ins(debug_params[i].name, def->param)) {
            item = &debug_params[i];
            break;
        }
    }

    if (item == NULL) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, def->param);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_bison_copy_sys_param_value(value, def));
    verifier = sql_bison_find_sys_param_verifier(item->name);
    if (verifier != NULL && verifier->bison_verify != NULL) {
        return verifier->bison_verify((void *)se, (void *)value, (void *)def,
            verifier->min_value, verifier->max_value);
    }

    OG_SRC_THROW_ERROR_EX(value->loc, ERR_CAPABILITY_NOT_SUPPORT,
        "Bison ALTER SYSTEM DEBUG verifier adapter for %s", def->param);
    return OG_ERROR;
}


#ifdef __cplusplus
}
#endif
