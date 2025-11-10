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
 * cm_defs.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEFS__
#define __CM_DEFS__
#include "cm_base.h"
#include "cm_types.h"
#include <limits.h>
#include <float.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define VERSION2 "OGRACD"
#define VERSION_PKG "ZEN_PACKAGE"

#define CMS_MSG_VERSION (1)

#ifdef _DEBUG
#define LOG_DIAG
#define DB_DEBUG_VERSION
#endif

typedef enum en_status {
    OG_EAGAIN = -2,
    OG_ERROR = -1,
    OG_SUCCESS = 0,
    OG_TIMEDOUT = 1,
} status_t;

typedef enum ddl_exec_status {
    DDL_ENABLE = 0,
    DDL_DISABLE_READ_ONLY,
    DDL_DISABLE_STANDBY,
    DDL_DISABLE_DB_NOT_OPEN,
    DDL_DISABLE_DB_IS_ROLLING_BACK,
    DDL_PART_DISABLE_CLEAN_SHADOW_IDX,
    DDL_PART_DISABLE_PURGE_GARBAGE_SEG,
    DDL_PART_DISABLE_CLEAN_GARBAGE_PART,
    DDL_PART_DISABLE_CLEAN_GARBAGE_SUBPART,
    DDL_PART_DISABLE_DEL_PENDING_TRANS,
    DDL_PART_DISABLE_SET_DC_COMPLETING,
} ddl_exec_status_t;

typedef struct ddl_exec_status_str {
    ddl_exec_status_t ddl_exec_stat;
    const char *ddl_exec_str;
} ddl_exec_status_str_t;
static ddl_exec_status_str_t ddl_exec_status_strs[] = {
    { DDL_ENABLE, "DDL_ENABLE" },
    { DDL_DISABLE_READ_ONLY, "DDL_DISABLE_READ_ONLY" },
    { DDL_DISABLE_STANDBY, "DDL_DISABLE_STANDBY" },
    { DDL_DISABLE_DB_NOT_OPEN, "DDL_DISABLE_DB_NOT_OPEN" },
    { DDL_DISABLE_DB_IS_ROLLING_BACK, "DDL_DISABLE_DB_IS_ROLLING_BACK" },
    { DDL_PART_DISABLE_CLEAN_SHADOW_IDX, "DDL_PART_DISABLE_CLEAN_SHADOW_IDX" },
    { DDL_PART_DISABLE_PURGE_GARBAGE_SEG, "DDL_PART_DISABLE_PURGE_GARBAGE_SEG" },
    { DDL_PART_DISABLE_CLEAN_GARBAGE_PART, "DDL_PART_DISABLE_CLEAN_GARBAGE_PART" },
    { DDL_PART_DISABLE_CLEAN_GARBAGE_SUBPART, "DDL_PART_DISABLE_CLEAN_GARBAGE_SUBPART" },
    { DDL_PART_DISABLE_DEL_PENDING_TRANS, "DDL_PART_DISABLE_DEL_PENDING_TRANS" },
    { DDL_PART_DISABLE_SET_DC_COMPLETING, "DDL_PART_DISABLE_SET_DC_COMPLETING" },
};
static inline const char *get_ddl_exec_stat_str(ddl_exec_status_t ddl_stat)
{
    return ddl_exec_status_strs[ddl_stat].ddl_exec_str;
}

#define OG_FALSE (uint8)0
#define OG_TRUE (uint8)1

typedef enum en_cond_result { COND_FALSE = OG_FALSE, COND_TRUE = OG_TRUE, COND_UNKNOWN, COND_END } cond_result_t;

typedef enum en_cs_shd_node_type {
    CS_RESERVED = 0,
    CS_TYPE_CN = 1,
    CS_TYPE_DN = 2,
    CS_TYPE_GTS = 3,

    CS_MAX_NODE_TYPE,
} cs_shd_node_type_t;

typedef enum en_cm_digital_type {
    CM_DIGITAL_0 = 0,
    CM_DIGITAL_1 = 1,
    CM_DIGITAL_2 = 2,
    CM_DIGITAL_3 = 3,
    CM_DIGITAL_4 = 4,
    CM_DIGITAL_5 = 5,
    CM_DIGITAL_6 = 6,
    CM_DIGITAL_7 = 7,
    CM_DIGITAL_8 = 8,
    CM_DIGITAL_9 = 9,
    CM_DIGITAL_10 = 10,
    CM_DIGITAL_11 = 11,
    CM_DIGITAL_12 = 12,
    CM_DIGITAL_13 = 13,
    CM_DIGITAL_14 = 14,
    CM_DIGITAL_15 = 15,
} cm_digital_type_t;

typedef enum en_cs_distribute_type {
    DIST_NONE = 0,
    DIST_HASH = 1,
    DIST_RANGE = 2,
    DIST_LIST = 3,
    DIST_REPLICATION = 4,
    DIST_HASH_BASIC = 5
} cs_distribute_type_t;

#define SIZE_K(n) (uint32)((n)*1024)
#define SIZE_K_U64(n) (1024 * (uint64)(n))
#define SIZE_M(n) (1024 * SIZE_K(n))
#define SIZE_G(n) (1024 * (uint64)SIZE_M(n))
#define SIZE_T(n) (1024 * (uint64)SIZE_G(n))

#define OG_DYNVIEW_NORMAL_LEN (uint32)20
#define OG_DYNVIEW_DDL_STA_LEN (uint32)40
#define OG_MAX_VARCHAR_LEN (uint32)7000
// sharding
#define OG_MAX_NODE_TYPE_LEN (uint32)128
#define OG_MAX_NODE_NAME_LEN (uint32)128
#define OG_MAX_CONN_NUM (uint32)4000
#define OG_MAX_ALSET_SOCKET (uint32)100

// 10 minutes
#define OG_MAX_GTS_SCN_STAGNANT_TIME 600000000
#define OG_INVALID_SCN(scn) ((scn) == 0 || (scn) == OG_INVALID_ID64)

/* Convert an NUMERIC Marco to string, e.g. CM_STR(2) ==> "2" */
#define OG_STR_HELPER(x) #x
#define OG_STR(x) OG_STR_HELPER(x)

// buf in thread local storage, which used for converting text to string
#define OG_T2S_BUFFER_SIZE (uint32)256
#define OG_T2S_LARGER_BUFFER_SIZE SIZE_K(16)
#define OG_MESSAGE_BUFFER_SIZE (uint32)2048 /* using for client communication with server, such as error buffer */

/* ogbox */
#define MS_PER_SEC 1000000.0
#define OG_REDO_LOG_NUM 16
#define OG_XID_NUM 10
#define CARRY_FACTOR 10
#define FILE_BLOCK_SIZE 512

/* buf */
#define OG_DB_NAME_LEN (uint32)32
#define OG_TENANT_NAME_LEN (uint32)32
#define OG_TENANT_BUFFER_SIZE (uint32) CM_ALIGN4(OG_TENANT_NAME_LEN + 1)
#define OG_MAX_NAME_LEN (uint32)64
#define OG_NAME_BUFFER_SIZE (uint32) CM_ALIGN4(OG_MAX_NAME_LEN + 1)
#define OG_MAX_ALCK_USER_NAME_LEN (uint32)(OG_MAX_NAME_LEN * 2)
#define OG_MAX_ALCK_MODE_STATUS_LEN (uint32)4
#define OG_MAX_ALCK_IX_MAP_LEN (uint32)22

// plsql lock need user.pack.name.pltype
#define OG_MAX_ALCK_NAME_LEN (uint32)(OG_MAX_NAME_LEN * 2 + 3)
#define OG_ALCK_NAME_BUFFER_SIZE (uint32) CM_ALIGN4(OG_MAX_ALCK_NAME_LEN + 1)
#define OG_VALUE_BUFFER_SIZE (uint32)128
#define OG_HOST_NAME_BUFFER_SIZE (uint32)64
#define OG_RAFT_PEERS_BUFFER_SIZE (uint32)768
#define OG_MAX_RAFT_SEND_BUFFER_SIZE (uint32)10000
#define OG_MAX_RAFT_RECEIVE_BUFFER_SIZE (uint32)10000
#define OG_MIN_RAFT_PER_MSG_SIZE SIZE_M(64)
#define OG_FILE_NAME_BUFFER_SIZE (uint32)256
#define OG_MIN_RAFT_ELECTION_TIMEOUT (uint32)3
#define OG_MAX_RAFT_ELECTION_TIMEOUT (uint32)60
#define OG_MAX_FILE_NAME_LEN (uint32)(OG_FILE_NAME_BUFFER_SIZE - 1)
#define OG_MAX_FILE_PATH_LENGH (SIZE_K(1) + 1)
#define OG_MAX_ARCH_NAME_LEN \
    (uint32)(OG_FILE_NAME_BUFFER_SIZE / 2)  // archive log name = archive dest path + archive format
#define OG_MD5_HASH_SIZE (uint32)16
#define OG_MD5_SIZE (uint32)32

#define OG_MAX_PATH_BUFFER_SIZE (uint32)(OG_FILE_NAME_BUFFER_SIZE - OG_NAME_BUFFER_SIZE)
#define OG_MAX_PATH_LEN (uint32)(OG_MAX_PATH_BUFFER_SIZE - 4)
#define OG_MAX_LOG_HOME_LEN \
    (uint32)(OG_MAX_PATH_LEN - 20)  // reserve 20 characters for the stitching path(e. g./run,/audit)
#define OG_MAX_DDM_LEN (uint32)1024
#define OG_QUATO_LEN (uint32)2
#define OG_MAX_SQLFILE_SIZE SIZE_M(4)
#define OG_STR_RESERVED_LEN (uint32)4
#define OG_PASSWORD_BUFFER_SIZE (uint32)512
#define OG_PARAM_BUFFER_SIZE (uint32)1024
#define OG_NUMBER_BUFFER_SIZE (uint32)128
#define OG_MAX_NUMBER_LEN (uint32)128
#define OG_MAX_DFLT_VALUE_LEN (uint32)1024
#define OG_MAX_UDFLT_VALUE_LEN (uint32)2048
#define OG_MAX_DCTYPE_STR_LEN (uint32)30
#define OG_MAX_LSNR_HOST_COUNT (uint32)8
#define OG_MAX_CHECK_VALUE_LEN (uint32)2048
#define OG_MAX_CMD_ARGS (uint32)3
#define OG_MAX_CMD_LEN (uint32)256
#define OG_BACKUP_PARAM_SIZE (uint32)128
#define OG_MAX_PARAM_LEN (uint32)128
#define OG_LOG_PARAM_CNT (uint32)13
#define OG_MAX_SEQUENCE_LEN (uint32)1024
#define OG_DROP_DATAFILE_FORMAT_NAME_LEN(ori_len) (uint32)((ori_len) + 7)  // drop datafile format name eg:xxx.delete
#define OG_MAX_WEIGHT_VALUE (uint32)100

// backup file name format is 'filetype_fileid_secid.bak' or 'data_spacename_fileid_secid.bak'
// filetype value as 'data' or 'ctrl' or 'arch' or 'log', max filetype len is 4
// max '_' number is 3; max fileid is 1024, max len of fileid to char is 4 bytes
// max secid is 8, max len of sedid to char is 1 byte; suffix '.bak' len is 4
// max space name len is OG_NAME_BUFFER_SIZE 68
// max backup file name len is (4+3+4+1+4+68) = 84, need extra terminator, so set max len as 88
#define OG_BACKUP_FILE_NAME_LEN (uint32)88
#define OG_MAX_BACKUP_PATH_LEN (OG_MAX_FILE_NAME_LEN - OG_BACKUP_FILE_NAME_LEN)
#define OG_MAX_SSL_CIPHER_LEN (uint32)1024

#define OG_DFLT_VALUE_BUFFER_SIZE (uint32)4096
#define OG_UDFLT_VALUE_BUFFER_SIZE (uint32)8192

#define OG_MAX_TRIGGER_COUNT (uint32)8

#define OG_LOB_LOCATOR_BUF_SIZE (uint32)4000

#define OG_MAX_INSTANCES 64
#define OG_DEFAULT_INSTANCE 16
#define EXT_PROC_MAX_INSTANCES 2

/* * The maximal precision of a native datatype. The precision means the
 * * number of significant digits in a number */
#define OG_MAX_INT64_PREC 19
#define OG_MAX_UINT64_PREC 20
#define OG_MAX_INT32_PREC 10
#define OG_MAX_UINT32_PREC 10
#define OG_MAX_REAL_PREC 15        // # of decimal digits of precision
#define OG_MAX_INDEX_REAL_PREC 16  // # of index decimal digits of precision
#define OG_MAX_CM_DOUBLE_PREC 17

#define CACHE_LINESIZE (uint32)64
#define OG_MAX_TIME_STRLEN (uint32)(48)
#define OG_MAX_DATE_STRLEN (uint32)(22)
#define OG_MAX_TIMESTAMP_STRLEN (uint32)(32)
#define OG_MAX_TZ_STRLEN (uint32)(40)
#define OG_MAX_INT64_STRLEN (uint32)(20)
#define OG_MAX_INT32_STRLEN (uint32)(11)
#define OG_MAX_INT16_STRLEN (uint32)(6)
#define OG_MAX_INT8_STRLEN (uint32)(4)
#define OG_MAX_UINT64_STRLEN (uint32)(20)
#define OG_MAX_UINT32_STRLEN (uint32)(10)
#define OG_MAX_UINT16_STRLEN (uint32)(5)
#define OG_MAX_UINT8_STRLEN (uint32)(3)
#define OG_MAX_BOOL_STRLEN (uint32)(5)
#define OG_MIN_BOOL_STRLEN (uint32)(4)
#define OG_MAX_REAL_INPUT_STRLEN (uint32)(1024)
#define OG_MAX_REAL_OUTPUT_STRLEN (uint32)(24)
#define OG_MAX_YM_INTERVAL_STRLEN (uint32)(10)
#define OG_MAX_DS_INTERVAL_STRLEN (uint32)(24)
#define OG_MAX_ROWID_STRLEN (uint32)(32)
#define OG_MAX_ROWID_BUFLEN (uint32)(64)
#define OG_TLOCKLOB_BUFFER_SIZE SIZE_K(4) /* 4K */
#define OG_XA_EXTEND_BUFFER_SIZE SIZE_K(16)
#define OG_MAX_XA_BASE16_GTRID_LEN ((uint32)128)
#define OG_MAX_XA_BASE16_BQUAL_LEN ((uint32)128)
#define OG_MAX_XA_XID_TEXT_CNT (uint32)2
#define OG_MAX_MIN_VALUE_SIZE (uint32)(64)
#define OG_COMMENT_SIZE (uint32)256
#define OG_COMMENT_BUFFER_SIZE (uint32)260
#define OG_PROC_LOAD_BUF_SIZE SIZE_K(4) /* thread and agent */
#define OG_AGENT_THREAD_STACK_SIZE SIZE_K(256)
#define OG_DFLT_THREAD_STACK_SIZE SIZE_K(256)
#define OG_DFLT_THREAD_GUARD_SIZE 4096
#define OG_MIN_THREAD_STACK_SIZE OG_DFLT_THREAD_STACK_SIZE
#define OG_MAX_THREAD_STACK_SIZE SIZE_M(8)
#define OG_STACK_DEPTH_SLOP SIZE_K(512)
#define OG_STACK_DEPTH_THRESHOLD_SIZE                                                                                 \
    (OG_T2S_BUFFER_SIZE * 3 + OG_T2S_LARGER_BUFFER_SIZE + OG_MESSAGE_BUFFER_SIZE * 2 + SIZE_K(50)) /* __thread        \
                                                                                                      error_info_t in \
                                                                                                      cm_error.c */
#define OG_LOCK_GROUP_COUNT (uint32)3

#define OG_PROTO_CODE *(uint32 *)"\xFE\xDC\xBA\x98"
#define OG_PLOG_PAGES (uint32)17
#define OG_EV_WAIT_TIMEOUT 16
#define OG_EV_WAIT_NUM 256
#define OG_INIT_PREFETCH_ROWS 100
#define OG_RESERVED_BYTES_14 14
#define OG_RESERVED_BYTES_32 32

#define OG_REAL_PRECISION (double)0.000000000000001
#define CM_DBL_IS_FINITE(x) isfinite(x)

#define CM_SINGLE_QUOTE_LEN 2

/* file */
#define OG_MAX_CONFIG_FILE_SIZE SIZE_K(64)  // 64K
#define OG_MAX_HBA_FILE_SIZE SIZE_M(1)
#define OG_MAX_CONFIG_LINE_SIZE SIZE_K(2)
#define OG_MIN_SYSTEM_DATAFILE_SIZE SIZE_M(128)
#define OG_MIN_SYSAUX_DATAFILE_SIZE SIZE_M(128)
#define OG_MIN_USER_DATAFILE_SIZE SIZE_M(1)
#define OG_DFLT_CTRL_BLOCK_SIZE SIZE_K(16)
#define OG_DFLT_LOG_BLOCK_SIZE (uint32)512
#define FILE_BLOCK_SIZE_512 (uint32)512
#define FILE_BLOCK_SIZE_4096 (uint32)4096
#define OG_MAX_ARCH_FILES_SIZE SIZE_T(32)
#define OG_MAX_PUNCH_SIZE SIZE_G(500)
#define OG_MIN_BACKUP_BUF_SIZE SIZE_M(8)
#define OG_MAX_BACKUP_BUF_SIZE SIZE_M(512)

/* sql engine */
#define OG_MAX_INVALID_CHARSTR_LEN (uint32)1024
#define OG_SQL_BUCKETS (uint32)SIZE_K(128)
#define OG_CONTEXT_MAP_SIZE (uint32)SIZE_K(512)
#define OG_STRING_BUFFER_SIZE (uint32)32768
#define OG_MAX_STRING_LEN (uint32)(OG_STRING_BUFFER_SIZE - 1)
#define OG_MAX_JOIN_TABLES (uint32)128
#define OG_MAX_SUBSELECT_EXPRS (uint32)64
#define OG_MAX_FILTER_TABLES (uint32)8
#define OG_MAX_MATERIALS (uint32)128
#define OG_RESERVED_TEMP_TABLES (uint32)(OG_MAX_MATERIALS / 2)
#define OG_MAX_DLVR_COLS_COUNT (uint32)10
/* less than 0xFFFFFFFF/sizeof(knl_temp_cache_t) 9761289 */
#define OG_MAX_TEMP_TABLES (uint32)(8192)
#define OG_MAX_LINK_TABLES (uint32)(1024)
#define OG_MAX_JOIN_JTABLES (uint32)512         /* base table + join table */

#define OG_MAX_MTRL_OPEN_PAGES (uint32)256
#define OG_RBO_MAX_HASH_COUNT (uint32)200000
#define OG_CBO_MAX_HASH_COUNT (uint32)2000000
#define OG_HASH_JOIN_COUNT (uint32)100000
#define OG_HASH_FACTOR (uint32)2
#define OG_DEFAULT_NULL_VALUE (uint32)0xFFFFFFFF
#define OG_SERIAL_CACHE_COUNT (uint32)100
#define OG_GENERATED_KEY_ROW_SIZE (uint32)16 /* row head size(8) + bigint (8) */
#define OG_MAX_HINT_ARGUMENT_LEN (uint32)64
#define OG_MAX_ROW_SIZE (uint32)64000
#define OG_MAX_PAR_EXP_VALUE (uint32)16
#define OG_MAX_CHAIN_COUNT (uint32)255
#define OG_MAX_DEBUG_BREAKPOINT_COUNT (uint32)64
#define OG_MAX_DUAL_ROW_SIZE (uint32)64
#define OG_MAX_PLAN_VERSIONS (uint32)10
#define OG_MAX_VPEEK_VER_SIZE (uint32)256

/* audit log_level */
#define DDL_AUDIT_ALL 255

/* network & protocol */
#define OG_MAX_PACKET_SIZE (uint32) SIZE_K(96)
#define OG_MAX_ALLOWED_PACKET_SIZE (uint32) SIZE_M(64)
#define OG_POLL_WAIT (uint32)50              /* mill-seconds */
#define OG_NETWORK_IO_TIMEOUT (uint32)5000   /* mill-seconds */
#define OG_NETWORK_WAIT_TIMEOUT (uint32)1000 /* mill-seconds */
#define OG_BACKUP_RETRY_COUNT (uint32)12000
#define OG_MAX_REP_RETRY_COUNT (uint32)3
#define OG_CONNECT_TIMEOUT (uint32)60000 /* mill-seconds */
#define OG_SSL_IO_TIMEOUT (uint32)30000  /* mill-seconds */
#define OG_TIME_THOUSAND_UN (uint32)1000
#define OG_TIME_THOUSAND (int32)1000
#define OG_REPL_SEND_TIMEOUT (uint32)30000   /* mill-seconds */
#define OG_BUILD_SEND_TIMEOUT (uint32)300000 /* mill-seconds */
#define OG_HANDSHAKE_TIMEOUT (uint32)600000  /* mill-seconds */

/* resource manager */
#define OG_CPU_TIME (uint32)100         // mill-seconds
#define OG_RES_IO_WAIT (uint32)10       /* mill-seconds */
#define OG_RES_IO_WAIT_US (uint32)10000 /* micro-seconds */

/* TCP options */
#define OG_TCP_DEFAULT_BUFFER_SIZE SIZE_M(64)
#define OG_TCP_KEEP_IDLE (uint32)120 /* seconds */
#define OG_TCP_KEEP_INTERVAL (uint32)5
#define OG_TCP_KEEP_COUNT (uint32)3
#define OG_TCP_PORT_MAX_LENGTH (uint32)5

/* limitations */
#define OG_MAX_WORKER_THREADS (uint32)10000
#define OG_MIN_WORKER_THREADS (uint32)0
#define OG_MAX_OPTIMIZED_WORKER_COUNT (uint32)10000
#define OG_MIN_OPTIMIZED_WORKER_COUNT (uint32)2
#define OG_MAX_REACTOR_POOL_COUNT (uint32)10000
#define PRIV_AGENT_OPTIMIZED_BASE (uint32)4
#define OG_MALICIOUS_LOGIN_COUNT (uint32)9
#define OG_MALICIOUS_LOGIN_ALARM (uint32)15
#define OG_MAX_MALICIOUS_IP_COUNT (uint32)64000
#define OG_SYS_SESSIONS (uint32)32
#define OG_MAX_AUTON_SESSIONS (uint32)256
#define OG_MAX_UNDO_SEGMENTS (uint32)1024
#define OG_MAX_SESSIONS (uint32)19380
#define OG_MAX_RM_LEN (uint32)8
#define OG_MAX_RM_COUNT (uint32)(OG_SHARED_PAGE_SIZE - OFFSET_OF(schema_lock_t, map))
#define OG_MAX_AGENTS (uint32)1024
#define OG_MAX_RMS (uint32)24480
#define OG_MAX_RM_BUCKETS (uint32)4096
#define OG_EXTEND_RMS (uint32)64
#define OG_MAX_RM_PAGES (uint32)(OG_MAX_RMS / OG_EXTEND_RMS + 1)
#define OG_MAX_STATS (uint32) OG_MAX_SESSIONS
#define OG_EXTEND_STATS (uint32)64
#define OG_MAX_STAT_PAGES (uint32)(OG_MAX_STATS / OG_EXTEND_STATS + 1)
#define OG_MAX_SUSPEND_TIMEOUT (uint32)3600  // 60min
#define OG_SPRS_COLUMNS (uint32)1024
#define OG_MAX_COLUMNS (uint32)4096
#define OG_MAX_COLUMN_SIZE (uint32)8000
#define OG_MAX_PART_COLUMN_SIZE (uint32)4000
#define OG_MAX_LOB_SIZE ((uint64)SIZE_M(1024) * 4)
#define OG_MAX_SQL_PARAM_COUNT (uint32)0x8000
#define OG_MAX_INDEX_COLUMNS (uint32)16
#define OG_MAX_PARTKEY_COLUMNS (uint32)16
#define OG_MAX_PART_COUNT (uint32)(PART_GROUP_SIZE * PART_GROUP_SIZE)
#define OG_MAX_SUBPART_COUNT (uint32)(OG_SHARED_PAGE_SIZE / sizeof(uint32))
#define OG_MAX_HASH_PART_COUNT (uint32)(OG_MAX_PART_COUNT / 2)
#define OG_MAX_HASH_SUBPART_COUNT (uint32)(OG_MAX_SUBPART_COUNT / 2)
#define OG_DFT_PARTID_STEP (uint32)10
#define OG_MAX_PART_ID_GAP (uint32)50
#define OG_KEY_BUF_SIZE (uint32)4096
#define OG_MAX_KEY_SIZE (uint32)4095
#define OG_ROWID_BUF_SIZE (uint32) SIZE_K(2)
#define OG_MAX_TABLE_INDEXES (uint32)64
#define OG_MAX_CONSTRAINTS (uint32)32
#define OG_MAX_POLICIES (uint32)32
#define OG_MAX_OBJECT_STACK_DEPTH (uint32)128  // 32
#define OG_MAX_BTREE_LEVEL (uint32)8
#define OG_INI_TRANS (uint32)2
#define OG_MAX_SYSINDEX_TRANS (uint32)128
#define OG_MAX_TRANS (uint32)255
#define OG_PCT_FREE (uint32)8
#define OG_PCT_FREE_MAX (uint32)80
#define OG_RESERVED_SYSID (uint32)64
#define OG_EX_SYSID_START (uint32)1024
#define OG_EX_SYSID_END (uint32)1536
#define OG_MAX_SAVEPOINTS (uint8)8
#define OG_MIN_ROLLBACK_PROC (uint32)1
#define OG_MAX_ROLLBACK_PROC (uint32)2
#define OG_MAX_PARAL_RCY (uint32)128
#define OG_DEFAULT_PARAL_RCY (uint32)1
#define OG_RCY_BUF_SIZE (uint32) SIZE_M(64)
#define OG_MAX_RAFT_START_MODE (uint32)3
#define OG_MAX_RAFT_LOG_LEVELE (uint32)6
#define OG_MAX_RAFT_PRIORITY_LEVEL (uint32)16
#define OG_MAX_RAFT_LOG_ASYNC_BUF (uint32)128
#define OG_MIN_RAFT_FAILOVER_WAIT_TIME (uint32)5
#define OG_MAX_EXEC_LOB_SIZE (uint32)(SIZE_K(64) - 2)  // must less than maximum(uint16) - 1
#define OG_MAX_PLAN_RANGE_COUNT (uint32)4096
#define OG_MAX_POINT_RANGE_COUNT (uint32)100
#define OG_MAX_HIBOUND_VALUE_LEN (uint32)64
#define OG_PAGE_UNIT_SIZE (uint32)4096
#define OG_MAX_EMERG_SESSIONS (uint32)32
#define OG_MAX_SGA_CORE_DUMP_CONFIG (uint32)0xFFFF
#define OG_MAX_EXTENT_SIZE (uint32)8192
#define OG_MIN_EXTENT_SIZE (uint32)8
#define OG_MAX_SECS_AGENTS_SHRINK (uint32)4000000
#define OG_MAX_CPUS (uint32)4096
#define OG_MAX_STORAGE_MAXSIZE (uint64) SIZE_T(1)
#define OG_MIN_STORAGE_MAXSIZE (uint64) SIZE_M(1)
#define OG_MAX_STORAGE_INITIAL (uint64) SIZE_T(1)
#define OG_MIN_STORAGE_INITIAL (uint64) SIZE_K(64)
#define OG_SIGN_BUF_SIZE (uint32) CM_ALIGN4(OG_MD5_SIZE + 1)
#define OG_SPM_OUTLINE_LEN OG_MAX_COLUMN_SIZE
#define OG_SPM_OUTLINE_SIZE (uint32) CM_ALIGN4(OG_SPM_OUTLINE_LEN + 1)
#define OG_SPM_PROFILE_LEN (uint32)4000
#define OG_SPM_PROFILE_SIZE (uint32) CM_ALIGN4(OG_SPM_PROFILE_LEN + 1)
#define OG_SPM_SQL_SIZE (uint32) OG_SHARED_PAGE_SIZE
#define OG_SPM_SQL_LEN (uint32)(OG_SPM_SQL_SIZE - 1)

#define OG_MAX_DECODE_ARGUMENTS (uint32)256
#define OG_MAX_FUNC_ARGUMENTS (uint32)64
#define OG_MAX_USERS (uint32)15000
#define OG_MAX_ROLES (uint32)1024
#define OG_MAX_DBLINKS (uint32)64
#define OG_MAX_PLAN_GROUPS (uint32)256
#define OG_MAX_TENANTS (uint32)256

#define OG_MAX_QOS_WAITTIME_US (uint32)200000
#define OG_MAX_CHECK_COLUMNS OG_MAX_INDEX_COLUMNS

#define OG_MAX_PL_PACKET_SIZE (uint32) SIZE_K(64)
#define OG_MAX_PUTLINE_SIZE (uint32) SIZE_K(32)

#define OG_MAX_JOB_THREADS (uint32)200
#define OG_MAX_UNDO_SEGMENT (uint32)1024
#define OG_MIN_UNDO_SEGMENT (uint32)2
#define OG_MIN_AUTON_TRANS_SEGMENT (uint32)1
#define OG_MIN_UNDO_ACTIVE_SEGMENT (uint32)2
#define OG_MAX_UNDO_ACTIVE_SEGMENT (uint32)1024
#define OG_MIN_UNDO_PREFETCH_PAGES (uint32)1
#define OG_MAX_UNDO_PREFETCH_PAGES (uint32)128
#define OG_MAX_SYSTIME_INC_THRE (uint32)3600
#define OG_MAX_SPC_USAGE_ALARM_THRE (uint32)100
#define OG_MIN_VERSION_NUM_LEN (uint32)5                    // The version number min length
#define OG_MIN_SCN_INTERVAL_THRE (uint32)60                 // seconds
#define OG_MAX_SCN_INTERVAL_THRE (uint32)311040000          // seconds of 3600 days
#define OG_MIN_ASHRINK_WAIT_TIME (uint32)1                  // seconds
#define OG_MAX_ASHRINK_WAIT_TIME (uint32)172800             // seconds
#define OG_MIN_SHRINK_WAIT_RECYCLED_PAGES (uint32)0         // pages
#define OG_MAX_SHRINK_WAIT_RECYCLED_PAGES (uint32)13107200  // pages

#define OG_MIN_PORT (uint32)1024
#define OG_MAX_TOPN_THRESHOLD (uint32)10000
#define OG_MAX_SEGMENT_PAGES_HOLD (uint32)10000
#define OG_MAX_HASH_PAGES_HOLD (uint32)10000

#define OG_MIN_OPT_THRESHOLD (uint32)0
#define OG_MAX_OPT_THRESHOLD (uint32)2000

#define OG_MAX_MULTI_PARTS_NUM (uint32)900

#define OG_MAX_PROMOTE_RECORD_COUNT 100
#define OG_MAX_PROMOTE_TYPE_LEN (uint32)16

#define OG_MAX_CASCADE_DEPTH 15

/* invalid id */
#define OG_INVALID_INT8 ((int8)(-1))
#define OG_INVALID_ID8 (uint8)0xFF
#define OG_INVALID_ID16 (uint16)0xFFFF
#define OG_INVALID_ID24 (uint32)0xFFFFFF
#define OG_INVALID_ID32 (uint32)0xFFFFFFFF
#define OG_INVALID_ID64 (uint64)0xFFFFFFFFFFFFFFFF
#define OG_INFINITE32 (uint32)0xFFFFFFFF
#define OG_NULL_VALUE_LEN (uint16)0xFFFF
#define OG_INVALID_ASN (uint32)0
#define OG_INVALID_LSN (uint64)0
#define OG_INVALID_LFN (uint64)0
#define OG_INVALID_INT32 (uint32)0x7FFFFFFF
#define OG_INVALID_INT64 (int64)0x7FFFFFFFFFFFFFFF
#define OG_INVALID_HANDLE (int32)(-1)
#define OG_INVALID_FILEID OG_INVALID_ID16
#define OG_INVALID_CHECKSUM (uint16)0
#define OG_INVALID_VALUE_CNT OG_INVALID_ID32

/* sga & pga */
#define OG_MIN_DATA_BUFFER_SIZE (int64) SIZE_M(64) /* 64M */
#define OG_MAX_BUF_POOL_NUM (uint32)128
#define OG_MIN_CR_POOL_SIZE (int64) SIZE_M(16)     /* 16M */
#define OG_MAX_CR_POOL_COUNT (uint32)256
#define OG_MAX_TEMP_POOL_NUM (uint32)128
#define OG_MIN_TEMP_BUFFER_SIZE (int64) SIZE_M(32) /* 32M */
#define OG_MAX_TEMP_BUFFER_SIZE \
    (int64) SIZE_T(4) /* 4T < (OG_VMEM_PAGE_SIZE[128K] + VM_PAGE_CTRL_SIZE[12]) * VM_MAX_CTRLS[32K*3276] */
#define OG_MIN_LOG_BUFFER_SIZE (int64) SIZE_M(1) /* 1M */
#define OG_MAX_LOG_BUFFER_SIZE (int64) SIZE_M(110)
#define OG_MAX_BATCH_SIZE (int64)(OG_MAX_LOG_BUFFER_SIZE / 2)
#define OG_SHARED_PAGE_SIZE SIZE_K(32) /* 16K */
#define OG_VMA_LW_FACTOR 0.1
#define OG_VMA_PAGE_SIZE SIZE_K(16)
#define OG_LARGE_VMA_PAGE_SIZE (int64) SIZE_K(256)
#define OG_MIN_VMA_SIZE (int64) SIZE_M(4)
#define OG_MIN_LARGE_VMA_SIZE (int64) SIZE_M(1)
#define OG_MAX_VMP_OS_MEM_SIZE (int64) SIZE_M(32)
#define OG_MIN_LOCK_PAGES (uint32)128
#define OG_MAX_LOCK_PAGES (uint32) SIZE_K(32)
#define OG_MIN_SQL_PAGES (uint32)2048
#define OG_MIN_DICT_PAGES (uint32)2048
#define OG_CKPT_GROUP_SIZE(session) ((session)->kernel->attr.ckpt_group_size)
#define OG_MAX_BUF_DIRTY_PCT (uint32)75
#define OG_MIN_LOB_ITEMS_PAGES (uint32)128
#define OG_MIN_SHARED_POOL_SIZE \
    (int64)((OG_MIN_LOCK_PAGES + OG_MIN_SQL_PAGES + OG_MIN_DICT_PAGES + OG_MIN_LOB_ITEMS_PAGES) * OG_SHARED_PAGE_SIZE)
#define OG_MIN_LARGE_POOL_SIZE (int64) SIZE_M(4)
#define OG_ARCHIVE_BUFFER_SIZE (int64) SIZE_M(2) /* 2M */
#define OG_COMPRESS_BUFFER_SIZE (int64) SIZE_M(12)
#define OG_LARGE_PAGE_SIZE SIZE_M(1)
#define OG_BACKUP_BUFFER_SIZE (uint32) SIZE_M(8)       /* 8M */
#define BACKUP_BUFFER_SIZE(bak) ((bak)->backup_buf_size)
#define OG_ARC_COMPRESS_BUFFER_SIZE (uint32) SIZE_M(4) /* 4M */
#define COMPRESS_BUFFER_SIZE(bak) (BACKUP_BUFFER_SIZE(bak) * 3 / 2)
#define OG_MIN_INDEX_CACHE_SIZE (int64)16384
#define OG_MIN_AUTOEXTEND_SIZE (int64)1
#define OG_MAX_ALIGN_SIZE_4K (uint64) SIZE_K(4)
#define OG_MAX_SGA_BUF_SIZE SIZE_T(32)

#define OG_MIN_KERNEL_RESERVE_SIZE (uint32) SIZE_K(256)
#define OG_MIN_STACK_SIZE (uint32) SIZE_K(512)

#define OG_MIN_VARIANT_SIZE (uint32) SIZE_K(256)
#define OG_MAX_VARIANT_SIZE (int64) SIZE_M(64)

#define OG_XPURPOSE_BUFFER_SIZE SIZE_M(2)
#define OG_MAX_VMEM_MAP_PAGES SIZE_K(32) /* 32K, MAXIMUM vmem size is 1T */
#define OG_VMEM_PAGE_SIZE SIZE_K(128)
#define OG_MAX_LOG_BUFFERS (uint32)16
#define OG_MIN_LOG_BUFFERS (uint32)1
#define OG_MAX_SSL_EXPIRE_THRESHOLD (uint32)180
#define OG_MIN_SSL_EXPIRE_THRESHOLD (uint32)7
#define OG_MAX_SSL_PERIOD_DETECTION (uint32)180
#define OG_MIN_SSL_PERIOD_DETECTION (uint32)1

#define OG_MAX_TIMEOUT_VALUE (uint32)1000000
#define OG_MAX_INDEX_RECYCLE_PERCENT (uint32)100
#define OG_MIN_INDEX_RECYCLE_SIZE (uint64) SIZE_M(4)
#define OG_MAX_INDEX_RECYCLE_SIZE (uint64) SIZE_T(1)
#define OG_MAX_INDEX_FORCE_RECYCLE (uint32)172800    /* MAXIMUM 48 hours */
#define OG_MAX_INDEX_RECYCLE_REUSE (uint32)172800000 /* MAXIMUM 48 hours */
#define OG_MAX_INDEX_REBUILD_STORAGE (uint32)172800  /* MAXIMUM 48 hours */

/* time */
#define OG_MONTH_PER_YEAR 12
#define OG_SEC_PER_DAY 86400
#define OG_SEC_PER_HOUR 3600
#define OG_SEC_PER_MIN 60
#define OG_DAY_PER_MONTH 31

/* database */
#define OG_MAX_CTRL_FILES (uint32)8
#define OG_MIN_LOG_FILES (uint32)3
#define OG_MAX_LOG_FILES (uint32)256
#define OG_MAX_SPACES (uint32)1024
#define OG_SPACES_BITMAP_SIZE (uint32)(OG_MAX_SPACES / UINT8_BITS)
#define OG_MAX_DATA_FILES (uint32)1023           /* 2^10 - 1 */
#define OG_MAX_DATAFILE_PAGES (uint32)1073741824 /* 2^30, max pages per data file */
#define OG_MAX_UNDOFILE_PAGES (uint32)4194304    /* 2^22, max pages per data file */
#define OG_MAX_SPACE_FILES (uint32)1000
#define OG_EXTENT_SIZE (uint32)8
#define OG_SWAP_EXTENT_SIZE (uint32)17
#define OG_UNDO_MAX_RESERVE_SIZE (uint32)1024
#define OG_UNDO_MIN_RESERVE_SIZE (uint32)64
#define OG_MAX_DDL_LOCK_TIMEOUT (uint32)1000000
#define OG_MIN_DDL_LOCK_TIMEOUT (uint32)0
#define OG_PRIVATE_TABLE_LOCKS (uint32)8
#define OG_MIN_PRIVATE_LOCKS (uint32)8
#define OG_MAX_PRIVATE_LOCKS (uint32)128
#define OG_MAX_DBWR_PROCESS (uint32)36
#define OG_MAX_MES_ROOMS_BASE (uint32)(OG_MAX_SESSIONS)
#define OG_MAX_MES_ROOMS (uint32)(OG_MAX_SESSIONS + OG_MAX_DBWR_PROCESS)
#define OG_MAX_ARCH_DEST (uint32)10
#define OG_WAIT_FLUSH_TIME (uint32)100
#define OG_LTT_ID_OFFSET (uint32)268435456 /* 2^28 */
#define OG_DBLINK_ENTRY_START_ID (OG_LTT_ID_OFFSET + OG_MAX_TEMP_TABLES)
#define OG_MAX_BACKUP_PROCESS (uint32)20
#define OG_MAX_PHYSICAL_STANDBY (uint32)9
#define OG_FIRST_ASN (uint32)1
#define OG_LOB_PCTVISON (uint32)10
#define OG_REPL_MIN_WAIT_TIME (uint32)3
#define OG_BUILD_MIN_WAIT_TIME (uint32)3
#define OG_NBU_BACKUP_MIN_WAIT_TIME (uint32)1
#define OG_MAX_ARCH_NUM (uint32)10240
#define OG_MIN_ARCH_TIME (uint64)100000
#define OG_MAX_ARCH_TIME (uint64)300000000
#define OG_MAX_RESETLOG_DISTANCE (uint32)1
#define OG_MAX_FILE_CONVERT_NUM (uint32)30
#define OG_FIX_CHECK_SQL_FORMAT "SELECT * FROM `%s`.`%s` WHERE NOT (%s);"
#define OG_FIX_CHECK_SQL_LEN (uint32)(strlen(OG_FIX_CHECK_SQL_FORMAT) + 1)
#define OG_RCY_MAX_PAGE_COUNT (OG_MAX_BATCH_SIZE / 16)
#define OG_RCY_MAX_PAGE_BITMAP_LEN ((OG_RCY_MAX_PAGE_COUNT / 16) + 1)
#define OG_MIN_MERGE_SORT_BATCH_SIZE (uint32)100000
#define OG_MAX_QOS_CTRL_FACTOR (double)5
#define OG_MIN_QOS_CTRL_FACTOR (double)0
#define OG_MAX_SQL_POOL_FACTOR (double)0.999
#define OG_MIN_SQL_POOL_FACTOR (double)0.001
#define OG_MAX_SQL_MAP_BUCKETS (uint32)1000000
#define OG_MAX_SQL_CURSORS_EACH_SESSION (uint32)300
#define OG_MAX_RESERVED_SQL_CURSORS (uint32)1000
#define OG_MAX_INIT_CURSORS (uint32)256
#define OG_EXIST_COL_TYPE_SQL_FORMAT "SELECT ID FROM `%s`.`%s` WHERE DATATYPE = %u LIMIT 1;"
#define OG_EXIST_COL_TYPE_SQL_LEN ((uint32)((sizeof(OG_EXIST_COL_TYPE_SQL_FORMAT) - 1) + 6))
#define OG_MAX_ROLE_VALID_LEN (uint32)13
#define OG_MAX_NET_MODE_LEN (uint32)6
#define OG_MAX_SPC_ALARM_THRESHOLD (uint32)100
#define OG_MAX_UNDO_ALARM_THRESHOLD (uint32)100
#define OG_MAX_TXN_UNDO_ALARM_THRESHOLD (uint32)100
#define OG_MIN_OPEN_CURSORS (uint32)1
#define OG_MAX_OPEN_CURSORS (uint32)(16 * 1024)
#define OG_MAX_PEER_BUILDING_LEN (uint32)(OG_MAX_BOOL_STRLEN + 1)
#define OG_MIN_REPL_PKG_SIZE (int64) SIZE_K(512)
#define OG_MAX_REPL_PKG_SIZE (int64) SIZE_M(8)
#define OG_MAX_SHRINK_PERCENT (uint32)100
#define OG_MIN_SHRINK_PERCENT (uint32)1
#define OG_MIN_RCY_SLEEP_INTERVAL (uint32)1
#define OG_MAX_RCY_SLEEP_INTERVAL (uint32)1024
#define OG_MIN_SWITCHOVER_TIMEOUT (uint32)30
#define OG_MAX_SWITCHOVER_TIMEOUT (uint32)1800
#define OG_MAX_ARCH_CLEAN_PERCENT (uint32)100
#define OG_MIN_ARCH_CLEAN_UL_PERCENT (uint32)1
#define OG_MIN_ARCH_CLEAN_LL_PERCENT (uint32)0
#define OG_DTC_RCY_NODE_READ_BUF_TIMEOUT (uint32)(90 * 1000)
#define OG_DTC_RCY_NODE_READ_BUF_SLEEP_TIME (uint32)1
#define OG_DTC_RCY_NODE_READ_TRY_TO_READ_LAST_FAILED_NODE_TIMES (uint32)100

/* JSON */
#define OG_JSON_MIN_DYN_BUF_SIZE (uint64) SIZE_M(1)
#define OG_JSON_MAX_DYN_BUF_SIZE (uint64) SIZE_T(32)

/* PARALLEL */
#define OG_MAX_PARAL_QUERY (uint32)256
#define OG_MAX_QUERY_PARALLELISM (uint32)16
#define OG_MAX_INDEX_PARALLELISM (uint32)48
#define OG_MAX_REBUILD_INDEX_PARALLELISM (uint32)64
#define OG_MAX_PAR_COMSUMER_SESSIONS (uint32)8
#define OG_MIN_PAR_SHARED_VM_PAGES (uint32)128
#define OG_MAX_PAR_SHARED_VM_PAGES (uint32)256
#define OG_PARALLEL_MAX_THREADS (uint32)4096

/* UPGRADE */
#define OG_MAX_VERSION_LEN 256
#define OG_MAX_ACTION_LEN 128

#ifdef OG_RAC_ING

#define OG_DISTRIBUTE_BUFFER_SIZE (uint32)1024
#define OG_DISTRIBUTE_COLUMN_COUNT (uint32)10
#define OG_DEF_HASH_SLICE_COUNT (uint32)1024
#define OG_SLICE_PREFIX "S"

#define OG_PRIV_CONNECTION_MIN (uint32)(1)
#define OG_PRIV_CONNECTION_MAX (uint32)(8)

#define OG_PRIV_SESSION_MIN (uint32)(32)
#define OG_PRIV_SESSION_MAX (uint32)(256)

#define OG_PRIV_AGENT_MIN (uint32)(32)
#define OG_PRIV_AGENT_MAX (uint32)(256)

#define OG_NO_VAILD_NUM (uint32)0
#define OG_MIN_VALID_NUM (uint32)1
#endif

/**
 * @addtogroup DATETIME
 * @brief The settings for Nebula's datetime/timestamp types
 * @{ */
/* * The default precision for datetime/timestamp   */
#define OG_MIN_DATETIME_PRECISION 0
#define OG_DATETIME_PRECISION_5 5
#define OG_MAX_DATETIME_PRECISION 6
#define OG_DEFAULT_DATETIME_PRECISION OG_MAX_DATETIME_PRECISION  // end group DATETIME

/*
 * @addtogroup NUMERIC
 * @brief The settings for Nebula's number and decimal types
 * The minimal and maximal precision when parsing number datatype  */
#define OG_MIN_NUM_SCALE (int32)(-84)
#define OG_MAX_NUM_SCALE (int32)127

#define OG_MIN_NUM_PRECISION (int32)1
#define OG_MAX_NUM_PRECISION (int32)38

#define OG_MAX_NUM_SAVING_PREC (int32)40 /* the maximal precision that stored into DB */

#define OG_MAX_WAIT_TIME (uint32)2000

/* The default settings for DECIMAL/NUMBER/NUMERIC/NUMBER2, when the precision and
 * scale of the them are not given. When encountering these two settings,
 * it indicating the precision and scale of a decimal is not limited */
#define OG_UNSPECIFIED_NUM_PREC 0
#define OG_UNSPECIFIED_NUM_SCALE (-100)  // should use OG_UNSPECIFIED_NUM_SCALE and OG_UNSPECIFIED_NUM_PREC at same time

/* The default settings for DOUBLE/FLOAT, when the precision and
 * scale of the them are not given. When encountering these two settings,
 * it indicating the precision and scale of a decimal is not limited */
#define OG_UNSPECIFIED_REAL_PREC OG_UNSPECIFIED_NUM_PREC
#define OG_UNSPECIFIED_REAL_SCALE OG_UNSPECIFIED_NUM_SCALE

#define OG_MIN_REAL_SCALE OG_MIN_NUM_SCALE
#define OG_MAX_REAL_SCALE OG_MAX_NUM_SCALE

#define OG_MIN_REAL_PRECISION OG_MIN_NUM_PRECISION
#define OG_MAX_REAL_PRECISION OG_MAX_NUM_PRECISION

/* The maximal precision for outputting a decimal */
#define OG_MAX_DEC_OUTPUT_PREC OG_MAX_NUM_SAVING_PREC
#define OG_MAX_DEC_OUTPUT_ALL_PREC (int32)72

#define OG_CONVERT_BUFFER_SIZE \
    ((stmt->pl_exec == NULL) ? ((uint32)(OG_MAX_COLUMN_SIZE * 2 + 4)) : (OG_MAX_STRING_LEN))  // 0x as prefix for binary
#define OG_CHAR_TO_BYTES_RATIO (uint32)6

#define OG_MIN_SAMPLE_SIZE (uint32) SIZE_M(32)   /* 32M */

#define OG_MIN_LOB_REUSE_SIZE (uint32) SIZE_M(4) /* 4M */
#define OG_MAX_LOB_REUSE_SIZE (uint64) SIZE_G(4) /* 4G */

#define OG_MIN_STATS_PARALL_THREADS 2
#define OG_MAX_STATS_PARALL_THREADS 8

#define OG_MIN_TAB_COMPRESS_BUF_SIZE (uint32) SIZE_M(16) /* 16M */
#define OG_MAX_TAB_COMPRESS_BUF_SIZE (uint64) SIZE_G(1)  /* 1G */
/* OGRAC */
#define OG_MES_MIN_CHANNEL_NUM (uint32)(1)
#define OG_MES_MAX_CHANNEL_NUM (uint32)(32)
#define OG_MES_MAX_REACTOR_THREAD_NUM (uint32)(32)
#define OG_MES_MAX_CPU_STR (uint32)(128)
#define OG_DTC_MIN_TASK_NUM (16)
#define OG_DTC_MAX_TASK_NUM (1000)
#define OG_MES_MIN_POOL_SIZE (uint32)(256)
#define OG_MES_MAX_POOL_SIZE (uint32)(65536)
#define OG_MES_MIN_THREAD_NUM (1)
#define OG_MES_MAX_THREAD_NUM (32)
#define OG_MES_DEFALT_THREAD_NUM (16)
#define OG_MES_MAX_INSTANCE_ID (uint32)(63)
#define OG_MES_SEND_RCV_TIMEOUT (uint32)3000  // define the timeout when gdv send request to remote instance
#define OG_CTSTORE_ALIGN_SIZE 512
#define OG_REMOTE_ACCESS_LIMIT (uint32)(255)

#define OG_MES_MIN_TASK_RATIO (double)0.001
#define OG_MES_MAX_TASK_RATIO (double)0.999

#define OG_SIMPLE_PART_NUM (uint32)1024
#define OG_SEGMENT_DLS_RATIO (double)0.9

#ifndef DATA_TYPES
#define DATA_TYPES

/*
 * @addtogroup DATA_TYPE
 * @brief The settings for Nebula's supporting data types
 * CAUTION!!!: don't change the value of datatype
 * in column default value / check constraint, the id is stored in system table COLUMN$
 * CAUTION!!!: if add new type or modify old type's order,
 * please modify ogsql_func.c/g_col_type_tab synchronously
 */
typedef enum en_og_type {
    OG_TYPE_UNKNOWN = -1,
    OG_TYPE_BASE = 20000,
    OG_TYPE_INTEGER = OG_TYPE_BASE + 1,    /* native 32 bits integer */
    OG_TYPE_BIGINT = OG_TYPE_BASE + 2,     /* native 64 bits integer */
    OG_TYPE_REAL = OG_TYPE_BASE + 3,       /* 8-byte native double */
    OG_TYPE_NUMBER = OG_TYPE_BASE + 4,     /* number */
    OG_TYPE_DECIMAL = OG_TYPE_BASE + 5,    /* decimal, internal used */
    OG_TYPE_DATE = OG_TYPE_BASE + 6,       /* datetime */
    OG_TYPE_TIMESTAMP = OG_TYPE_BASE + 7,  /* timestamp */
    OG_TYPE_CHAR = OG_TYPE_BASE + 8,       /* char(n) */
    OG_TYPE_VARCHAR = OG_TYPE_BASE + 9,    /* varchar, varchar2 */
    OG_TYPE_STRING = OG_TYPE_BASE + 10,    /* native char * */
    OG_TYPE_BINARY = OG_TYPE_BASE + 11,    /* binary */
    OG_TYPE_VARBINARY = OG_TYPE_BASE + 12, /* varbinary */
    OG_TYPE_CLOB = OG_TYPE_BASE + 13,      /* clob */
    OG_TYPE_BLOB = OG_TYPE_BASE + 14,      /* blob */
    OG_TYPE_CURSOR = OG_TYPE_BASE + 15,    /* resultset, for stored procedure */
    OG_TYPE_COLUMN = OG_TYPE_BASE + 16,    /* column type, internal used */
    OG_TYPE_BOOLEAN = OG_TYPE_BASE + 17,

    /* timestamp with time zone ,this type is fake, it is abandoned now,
     * you can treat it as OG_TYPE_TIMESTAMP just for compatibility */
    OG_TYPE_TIMESTAMP_TZ_FAKE = OG_TYPE_BASE + 18,
    OG_TYPE_TIMESTAMP_LTZ = OG_TYPE_BASE + 19, /* timestamp with local time zone */
    OG_TYPE_INTERVAL = OG_TYPE_BASE + 20,      /* interval of Postgre style, no use */
    OG_TYPE_INTERVAL_YM = OG_TYPE_BASE + 21,   /* interval YEAR TO MONTH */
    OG_TYPE_INTERVAL_DS = OG_TYPE_BASE + 22,   /* interval DAY TO SECOND */
    OG_TYPE_RAW = OG_TYPE_BASE + 23,           /* raw */
    OG_TYPE_IMAGE = OG_TYPE_BASE + 24,         /* image, equals to longblob */
    OG_TYPE_UINT32 = OG_TYPE_BASE + 25,        /* unsigned integer */
    OG_TYPE_UINT64 = OG_TYPE_BASE + 26,        /* unsigned bigint */
    OG_TYPE_SMALLINT = OG_TYPE_BASE + 27,      /* 16-bit integer */
    OG_TYPE_USMALLINT = OG_TYPE_BASE + 28,     /* unsigned 16-bit integer */
    OG_TYPE_TINYINT = OG_TYPE_BASE + 29,       /* 8-bit integer */
    OG_TYPE_UTINYINT = OG_TYPE_BASE + 30,      /* unsigned 8-bit integer */
    OG_TYPE_FLOAT = OG_TYPE_BASE + 31,         /* 4-byte float */
    // !!!add new member must ensure not exceed the limitation of g_type_maps in ogsql_oper_func.c
    /* the real tz type , OG_TYPE_TIMESTAMP_TZ_FAKE will be not used , it will be the same as OG_TYPE_TIMESTAMP */
    OG_TYPE_TIMESTAMP_TZ = OG_TYPE_BASE + 32, /* timestamp with time zone */
    OG_TYPE_ARRAY = OG_TYPE_BASE + 33,        /* array */
    OG_TYPE_NUMBER2 = OG_TYPE_BASE + 34,      /* number2, more effective encode format */
    OG_TYPE_NUMBER3 = OG_TYPE_BASE + 38,

    /* com */
    /* caution: SCALAR type must defined above */
    OG_TYPE_OPERAND_CEIL = OG_TYPE_BASE + 40,  // ceil of operand type

    /* The datatype can't used in datatype caculation system. only used for
     * decl in/out param in pl/sql */
    OG_TYPE_RECORD = OG_TYPE_BASE + 41,
    OG_TYPE_COLLECTION = OG_TYPE_BASE + 42,
    OG_TYPE_OBJECT = OG_TYPE_BASE + 43,
    /* The datatype below the OG_TYPE__DO_NOT_USE can be used as database DATATYPE.
     * In some extend, OG_TYPE__DO_NOT_USE represents the maximal number
     * of DATATYPE that oGRAC are supported. The newly adding datatype
     * must before OG_TYPE__DO_NOT_USE, and the type_id must be consecutive*/
    OG_TYPE__DO_NOT_USE = OG_TYPE_BASE + 44,

    /* The following datatypes are functional datatypes, which can help
     * to implement some features when needed. Note that they can not be
     * used as database DATATYPE */
    /* to present a datatype node, for example cast(para1, typenode),
     * the second argument is an expr_node storing the information of
     * a datatype, such as length, precision, scale, etc.. */
    OG_TYPE_FUNC_BASE = OG_TYPE_BASE + 200,
    OG_TYPE_TYPMODE = OG_TYPE_FUNC_BASE + 1,

    /* This datatype only be used in winsort aggr */
    OG_TYPE_VM_ROWID = OG_TYPE_FUNC_BASE + 2,
    OG_TYPE_ITVL_UNIT = OG_TYPE_FUNC_BASE + 3,
    OG_TYPE_UNINITIALIZED = OG_TYPE_FUNC_BASE + 4,

    /* The following datatypes be used for native date or timestamp type value to bind */
    OG_TYPE_NATIVE_DATE = OG_TYPE_FUNC_BASE + 5,       // native datetime, internal used
    OG_TYPE_NATIVE_TIMESTAMP = OG_TYPE_FUNC_BASE + 6,  // native timestamp, internal used
    OG_TYPE_LOGIC_TRUE = OG_TYPE_FUNC_BASE + 7,        // native true, internal used
} og_type_t;
/* @see rules for the arithmetic operators between different datatypes */
/* @see rules for obtaining (C-string) datatype names,
 * and more operations of datatypes */
#define OG_MAX_DATATYPE_NUM (OG_TYPE__DO_NOT_USE - OG_TYPE_BASE)

/* The following two Marcos is used to distinguish a og_type_t is a database
 * datatype or a functional datatype */
#define CM_IS_DATABASE_DATATYPE(type) ((type) > OG_TYPE_BASE && (type) < OG_TYPE__DO_NOT_USE)

#define CM_IS_SCALAR_DATATYPE(type) ((type) > OG_TYPE_BASE && (type) < OG_TYPE_OPERAND_CEIL)

#define CM_IS_COMPOUND_DATATYPE(type) ((type) > OG_TYPE_OPERAND_CEIL && (type) < OG_TYPE__DO_NOT_USE)

#define CM_IS_PLV_UDT_DATATYPE(type) ((type) == PLV_COLLECTION || (type) == PLV_RECORD || (type) == PLV_OBJECT)

/* The datatype and size of a NULL node or variant */
#define OG_DATATYPE_OF_NULL OG_TYPE_VARCHAR
#define OG_SIZE_OF_NULL 0

#define OG_IS_CHAR_DATATYPE(type)                                                                                   \
    ((type) == OG_TYPE_CHAR || (type) == OG_TYPE_VARCHAR || (type) == OG_TYPE_STRING || (type) == OG_TYPE_BINARY || \
     (type) == OG_TYPE_VARBINARY || (type) == OG_TYPE_RAW)

/* The limitation for native data type */
#define OG_MAX_UINT8 UINT8_MAX
#define OG_MIN_UINT8 0
#define OG_MIN_INT16 INT16_MIN
#define OG_MAX_INT16 INT16_MAX
#define OG_MAX_UINT16 UINT16_MAX
#define OG_MIN_UINT16 0
#define OG_MAX_INT32 (int32) INT_MAX
#define OG_MIN_INT32 (int32) INT_MIN
#define OG_MAX_UINT32 (uint32) UINT_MAX
#define OG_MIN_UINT32 (uint32)0
#define OG_MAX_INT64 LLONG_MAX
#define OG_MIN_INT64 LLONG_MIN
#define OG_MIN_UINT64 (uint64)0
#define OG_MAX_UINT64 ULLONG_MAX
#define OG_MAX_REAL (double)DBL_MAX
#define OG_MIN_REAL (double)DBL_MIN

#define OG_INTEGER_SIZE 4
#define OG_BIGINT_SIZE 8
#define OG_REAL_SIZE 8
#define OG_TIMESTAMP_SIZE 8
#define OG_DATE_SIZE 8
#define OG_TIMESTAMP_TZ_SIZE 12
#define OG_VARCHAR_SIZE 4
#define OG_BOOLEAN_SIZE 4

#define OG_MAX_REAL_EXPN DBL_MAX_10_EXP  // max decimal exponent
#define OG_MIN_REAL_EXPN (-308)          // DBL_MIN_10_EXP    // min decimal exponent

/* The format effector when a data type is printed */
#define PRINT_FMT_INTEGER "%d"
#define PRINT_FMT_UINT32 "%u"
#ifdef WIN32
#define PRINT_FMT_BIGINT "%I64d"
#else
#define PRINT_FMT_BIGINT "%lld"
#endif
#define PRINT_FMT_INT64 PRINT_FMT_BIGINT
#define PRINT_FMT_UINT64 "%llu"
/* The format effector for OG_TYPE_REAL, %g can removing tailing zeros */
#define PRINT_FMT_REAL "%." OG_STR(OG_MAX_REAL_PREC) "g"  // * == OG_MAX_REAL_PREC

// end group DATA_TYPE
#endif

typedef enum en_sql_style {
    SQL_STYLE_UNKNOWN = -1,
    SQL_STYLE_CT = 0,  // oGRAC style (oracle like)
} sql_style_t;

/*
CAUTION!!! don't change the value of enumeration
in column default value / check constraint, the operator id is stored in system table COLUMN$
*/
typedef enum en_operator_type {
    OPER_TYPE_ROOT = 0,  // UNARY OPERATOR
    OPER_TYPE_PRIOR = 1,
    OPER_TYPE_MUL = 2,
    OPER_TYPE_DIV = 3,
    OPER_TYPE_MOD = 4,
    OPER_TYPE_ADD = 5,
    OPER_TYPE_SUB = 6,
    OPER_TYPE_LSHIFT = 7,
    OPER_TYPE_RSHIFT = 8,
    OPER_TYPE_BITAND = 9,
    OPER_TYPE_BITXOR = 10,
    OPER_TYPE_BITOR = 11,
    OPER_TYPE_CAT = 12,
    OPER_TYPE_VARIANT_CEIL = 13,
    OPER_TYPE_SET_UNION = 14,
    OPER_TYPE_SET_UNION_ALL = 15,
    OPER_TYPE_SET_INTERSECT = 16,
    OPER_TYPE_SET_INTERSECT_ALL = 17,
    OPER_TYPE_SET_EXCEPT = 18,
    OPER_TYPE_SET_EXCEPT_ALL = 19,
    // !!!add new member must ensure not exceed the limitation 'OPER_TYPE_CEIL'
    OPER_TYPE_CEIL = 20
} operator_type_t;

/* is letter */
#define CM_IS_LETER(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
/* is naming leter */
#define CM_IS_NAMING_LETER(c)                                                                                \
    (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') || ((c) >= '0' && (c) <= '9') || (c) == '_' || \
     (c) == '$' || (c) == '#')

/* size alignment */
#define CM_ALIGN2(size) ((((size)&0x01) == 0) ? (size) : ((size) + 0x01))
#define CM_ALIGN4(size) ((((size)&0x03) == 0) ? (size) : ((size) + 0x04 - ((size)&0x03)))
#define CM_ALIGN8(size) ((((size)&0x07) == 0) ? (size) : ((size) + 0x08 - ((size)&0x07)))
#define CM_ALIGN16(size) ((((size)&0x0F) == 0) ? (size) : ((size) + 0x10 - ((size)&0x0F)))
// align to power of 2
#define CM_CALC_ALIGN(size, align) (((size) + (align)-1) & (~((align)-1)))
#define CM_CALC_ALIGN_FLOOR(size, align) (((size)-1) & (~((align)-1)))
/* align to any positive integer */
#define CM_ALIGN_ANY(size, align) (((size) + (align)-1) / (align) * (align))

#define CM_ALIGN_CEIL(size, align) (((size) + (align)-1) / (align))

#define CM_IS_ALIGN2(size) (((size)&0x01) == 0)
#define CM_IS_ALIGN4(size) (((size)&0x03) == 0)
#define CM_IS_ALIGN8(size) (((size)&0x07) == 0)

#define CM_ALIGN4_FLOOR(size) ((((size)&0x03) == 0) ? (size) : ((size) - ((size)&0x03)))
#define CM_ALIGN_8K(size) (((size) + 0x00001FFF) & 0xFFFFE000)
#define CM_ALIGN_512(size) (((size) + 0x000001FF) & 0xFFFFFE00)

#define CM_CYCLED_MOVE_NEXT(len, id)             \
    {                                            \
        (id) = ((id) == (len)-1) ? 0 : (id) + 1; \
    }

#define IS_BIG_ENDIAN (*(uint32 *)"\x01\x02\x03\x04" == (uint32)0x01020304)

#define OFFSET_OF offsetof

/* simple mathematical calculation */
#define MIN(A, B) ((B) < (A) ? (B) : (A))
#define MAX(A, B) ((B) > (A) ? (B) : (A))
#define SWAP(type, A, B) \
    do {                 \
        type t_ = (A);   \
        (A) = (B);       \
        (B) = t_;        \
    } while (0)
#define CM_DELTA(A, B) (((A) > (B)) ? ((A) - (B)) : ((B) - (A)))

#ifndef ELEMENT_COUNT
#define ELEMENT_COUNT(x) ((uint32)(sizeof(x) / sizeof((x)[0])))
#endif
/* compiler adapter */
#ifdef WIN32
#define inline __inline
#define cm_sleep(ms) Sleep(ms)
#else
static inline void cm_sleep(uint32 ms)
{
    struct timespec tq;
    struct timespec tr;
    tq.tv_sec = ms / 1000;
    tq.tv_nsec = (ms % 1000) * 1000000;

    (void)nanosleep(&tq, &tr);
}
#endif

#ifdef WIN32
#define cm_abs64(big_val) _abs64(big_val)
#else
#define cm_abs64(big_val) llabs(big_val)
#endif

#define __TO_STR(x) #x
#define __AS_STR(x) __TO_STR(x)
#define __STR_LINE__ __AS_STR(__LINE__)

#ifdef WIN32
#define __TODO__ __pragma(message(__FILE__ "(" __STR_LINE__ "): warning c0000: " __FUNCTION__ " need to be done"))
#define __CN__ __pragma(message(__FILE__ "(" __STR_LINE__ "): warning c0000: the code only for CN"))
#define CM_STATIC_ASSERT(cond) typedef char __static_assert_t[!!(cond)]
#else
#define DO_PRAGMA(x) _Pragma(#x)
#define __TODO__ DO_PRAGMA(message(__FILE__ "(" __STR_LINE__ ") need to be done"))
#define __CN__ DO_PRAGMA(message(__FILE__ "(" __STR_LINE__ ") the code only for CN"))
#define CM_STATIC_ASSERT(cond) typedef char __static_assert_t[1 - 2 * (!!!(cond))]
#endif

typedef struct st_handle_mutiple_ptrs {
    void *ptr1; /* ptr1 */
    void *ptr2; /* ptr2 */
    void *ptr3; /* ptr3 */
    void *ptr4; /* add more ptrs if needed */
    void *ptr5; /* add more ptrs if needed */
    void *ptr6; /* add more ptrs if needed */
} handle_mutiple_ptrs_t;

#define OG_PASSWD_MIN_LEN 8
#define OG_PASSWD_MAX_LEN 64
#define OG_PBL_PASSWD_MAX_LEN 256
#define OG_PWD_BUFFER_SIZE (uint32) CM_ALIGN4(OG_PBL_PASSWD_MAX_LEN + 1)

/* For password authentication between primary and standby, length should be at least 16 */
#define OG_REPL_PASSWD_MIN_LEN 16

/*
"A. at least one lowercase letter\n"
"B. at least one uppercase letter\n"
"C. at least one digit\n"
"D. at least one special character: #$_
*/
#define CM_PASSWD_MIN_TYPE 3

#define PUBLIC_USER "PUBLIC"
#define DBA_ROLE "DBA"

#define PUBLIC_USER_ID (uint32)1

#define OG_MAX_BLACK_BOX_DEPTH (uint32)40
#define OG_DEFAUT_BLACK_BOX_DEPTH (uint32)30
#define OG_INIT_BLACK_BOX_DEPTH (uint32)2
#define OG_INIT_ASSERT_DEPTH (uint32)1

#define CAST_FUNCTION_NAME "cast"
#define OG_PRIV_FILENAME "privilege"
#define OG_FKEY_FILENAME1 "ograc_key1"
#define OG_FKEY_FILENAME2 "ograc_key2"
#define OG_LKEY_FILENAME "workerstore"
#define OG_FKEY_FILENAME "factorstore"
#define OG_PRIVILEGE_FILENAME   "priv.bin"

#define OG_FKEY_REPL "repl_factor"
#define OG_WKEY_REPL "repl_worker"
#define OG_CIPHER_REPL "repl_cipher"

#define OG_DEFAULT_GROUP_NAME "DEFAULT_GROUPS"

#define OG_TYPE_I(type) ((type)-OG_TYPE_BASE)
#define OG_TYPE_MASK(type) ((uint64)1 << (uint64)(OG_TYPE_I(type)))

#define OG_GET_MASK(bit) ((uint64)0x1 << (bit))
#define OG_BIT_TEST(bits, mask) ((bits) & (mask))
#define OG_BIT_SET(bits, mask) ((bits) |= (mask))
#define OG_BIT_RESET(bits, mask) ((bits) &= ~(mask))

#define CM_SET_FLAG(v, flag) OG_BIT_SET(v, flag)
#define CM_CLEAN_FLAG(v, flag) OG_BIT_RESET(v, flag)

#define OG_BUFLEN_128 128
#define OG_BUFLEN_256 256
#define OG_BUFLEN_512 512
#define OG_BUFLEN_1K 1024
#define OG_BUFLEN_4K 4096
#define OG_MIN_BATCH_FLUSH_CAPACITY 1
#define OG_MAX_BATCH_FLUSH_CAPACITY 4096
#define OG_MIN_CKPT_GROUP_SIZE 1
#define OG_MAX_CKPT_GROUP_SIZE 32768

#define OG_DEFAULT_LOCAL_CHARSET CHARSET_UTF8

// check if overflow for converting to uint8
// note: when convert int8 to uint8, type should be set to int16 or int32 or int64
#define TO_UINT8_OVERFLOW_CHECK(u8, type)                                         \
    do {                                                                          \
        if ((type)(u8) < (type)OG_MIN_UINT8 || (type)(u8) > (type)OG_MAX_UINT8) { \
            OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED CHAR");                   \
            return OG_ERROR;                                                      \
        }                                                                         \
    } while (0)
// check if overflow for converting int64/double to int32
#define INT32_OVERFLOW_CHECK(i32)                           \
    do {                                                    \
        if ((i32) > OG_MAX_INT32 || (i32) < OG_MIN_INT32) { \
            OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");   \
            return OG_ERROR;                                \
        }                                                   \
    } while (0)

// check if overflow for converting int32/int64/uint64/double to uint32
// note: when convert int32 to uint32, type should be set to int64
#define TO_UINT32_OVERFLOW_CHECK(u32, type)                                                             \
    do {                                                                                                \
        if (SECUREC_UNLIKELY((type)(u32) < (type)OG_MIN_UINT32 || (type)(u32) > (type)OG_MAX_UINT32)) { \
            OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");                                      \
            return OG_ERROR;                                                                            \
        }                                                                                               \
    } while (0)

#define TO_UINT64_OVERFLOW_CHECK(u64, type)                                                             \
    do {                                                                                                \
        if (SECUREC_UNLIKELY((type)(u64) < (type)OG_MIN_UINT64 || (type)(u64) > (type)OG_MAX_UINT64)) { \
            OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");                                      \
            return OG_ERROR;                                                                            \
        }                                                                                               \
    } while (0)

#define REAL2UINT64_IS_OVERFLOW(ui64, real)                                                  \
    ((fabs((double)(ui64) - (real))) >= OG_REAL_PRECISION || ((real) < OG_REAL_PRECISION) || \
     ((real) > 1.84467440737095550e+19))

#define REAL2INT64_IS_OVERFLOW(i64, real)                                                         \
    ((fabs((double)(i64) - (real))) >= OG_REAL_PRECISION || ((real) < -9.2233720368547747e+18) || \
     ((real) > 9.2233720368547750e+18))

// return OG_SUCCESS if cond is true
#define OG_RETSUC_IFTRUE(cond) \
    if (cond) {                \
        return OG_SUCCESS;     \
    }

// return OG_ERROR if error occurs
#define OG_RETURN_IFERR(ret)                            \
    do {                                                \
        status_t _status_ = (ret);                      \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) { \
            cm_set_error_pos(__FILE__, __LINE__);       \
            return _status_;                            \
        }                                               \
    } while (0)

// print ERROR if error occurs
#define OG_PRINT_IFERR(ret, param, limit)                                                      \
    do {                                                                                       \
        status_t _status_ = (ret);                                                             \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {                                        \
            printf("Error,the parameter [%s] is too large,the limit is %d. \n", param, limit); \
            return _status_;                                                                   \
        }                                                                                      \
    } while (0)

#define OG_PRINT_IFERR2(ret, param, limit)                                                     \
    do {                                                                                       \
        status_t _status_ = (ret);                                                             \
        if (SECUREC_UNLIKELY(_status_ == -1)) {                                                \
            printf("Error,the parameter [%s] is too large,the limit is %d. \n", param, limit); \
            return _status_;                                                                   \
        }                                                                                      \
    } while (0)

// return OG_SUCCESS if success occurs
#define OG_RETURN_IFSUC(ret)                          \
    do {                                              \
        status_t _status_ = (ret);                    \
        if (SECUREC_LIKELY(_status_ == OG_SUCCESS)) { \
            return _status_;                          \
        }                                             \
    } while (0)

// return OG_ERROR with sql location where error occurs
#define LOC_RETURN_IFERR(ret, loc)                      \
    do {                                                \
        int _status_ = (ret);                           \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) { \
            cm_set_error_loc(loc);                      \
            return _status_;                            \
        }                                               \
    } while (0)

// return specific value if cond is true
#define OG_RETVALUE_IFTRUE(cond, value) \
    if (cond) {                         \
        return (value);                 \
    }

// return out the current function if error occurs
#define OG_RETVOID_IFERR(ret)  \
    if ((ret) != OG_SUCCESS) { \
        return;                \
    }

// return out the current function if cond is true
#define OG_RETVOID_IFTRUE(cond) \
    if (cond) {                 \
        return;                 \
    }

// break the loop if ret is not OG_SUCCESS
#define OG_BREAK_IF_ERROR(ret) \
    if ((ret) != OG_SUCCESS) { \
        break;                 \
    }

// continue the loop if cond is true
#define OG_BREAK_IF_TRUE(cond) \
    if (cond) {                \
        break;                 \
    }

// continue the loop if cond is true
#define OG_CONTINUE_IFTRUE(cond) \
    if (cond) {                  \
        continue;                \
    }

// free memory and set the pointer to NULL
#define CM_FREE_PTR(pointer)     \
    do {                         \
        if ((pointer) != NULL) { \
            free(pointer);       \
            (pointer) = NULL;    \
        }                        \
    } while (0)

// securec memory function check
#define MEMS_RETURN_IFERR(func)                        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return OG_ERROR;                           \
        }                                              \
    } while (0)

// securec memory function check
#define MEMS_RETVOID_IFERR(func)                       \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)

// for snprintf_s/sprintf_s..., return OG_ERROR if error
#define PRTS_RETURN_IFERR(func)                        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return OG_ERROR;                           \
        }                                              \
    } while (0)

// for snprintf_s/sprintf_s..., return if error
#define PRTS_RETVOID_IFERR(func)                       \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)

/* To decide whether a pointer is null */
#define CM_IS_NULL(ptr) ((ptr) == NULL)

#define CM_SET_VALUE_IF_NOTNULL(ptr, v) \
    do {                                \
        if ((ptr) != NULL) {            \
            *(ptr) = (v);               \
        }                               \
    } while (0)

#ifdef WIN32
#define OG_CHECK_FMT(a, b)
#else
#define OG_CHECK_FMT(a, b) __attribute__((format(printf, a, b)))
#endif  // WIN32

#pragma pack(4)
typedef struct st_source_location {
    uint16 line;
    uint16 column;
} source_location_t;
#pragma pack()

typedef source_location_t src_loc_t;

// XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:xxx.xxx.xxx.xxx%local-link: 5*6+4*4+16+1=63
// 64 bytes is enough expect local-link > 16 bytes,
// it's not necessary to enlarge to NI_MAXHOST(1025 bytes).
#define CM_MAX_IP_LEN 64
#define CM_INST_MAX_IP_NUM 2  // indicate maximum number of links between nodes
#define OG_MAX_INST_IP_LEN (CM_INST_MAX_IP_NUM * (CM_MAX_IP_LEN + 1))

#define OG_ENV_HOME (char *)"OGDB_HOME"
#define CM_UNIX_DOMAIN_PATH_LEN 108UL
#define CM_SYSDBA_USER_NAME "SYSDBA"
#define CM_CLSMGR_USER_NAME "CLSMGR"
#define SYS_USER_NAME "SYS"
#define SYS_USER_NAME_LEN 3
#define SYS_COLUMN_TABLE_NAME "SYS_COLUMNS"

#define KEY_LF 10L
#define KEY_CR 13L
#define KEY_BS 8L
#define KEY_BS_LNX 127L

typedef enum en_og_param_direction_t {
    OG_INTERNAL_PARAM = 0,
    OG_INPUT_PARAM = 1,
    OG_OUTPUT_PARAM = 2,
    OG_INOUT_PARAM = 3
} og_param_direction_t;

#ifdef WIN32
#define SLASH '\\'
#else
#define SLASH '/'
#endif

static inline void cm_try_delete_end_slash(char *str)
{
    if (strlen(str) > 0) {
        str[strlen(str) - 1] = (str[strlen(str) - 1] == SLASH) ? '\0' : str[strlen(str) - 1];
    }
}

#define LOOPBACK_ADDRESS "127.0.0.1"
#define ARRAY_NUM(a) (sizeof(a) / sizeof((a)[0]))
#define OG_MAC_ADDRESS_LEN (uint16)6

#define OGDB_UDS_EMERG_CLIENT "uds_emerg.client"
#define OGDB_UDS_EMERG_SERVER "uds_emerg.server"

#define UDS_EXT_INST_0 "uds_inst_0"
#define UDS_EXT_INST_1 "uds_inst_1"

#define OG_MAX_UDS_FILE_PERMISSIONS (uint16)777
#define OG_DEF_UDS_FILE_PERMISSIONS (uint16)600
#define OG_UNIX_PATH_MAX (uint32)108

#define OG_MIN_LRU_SEARCH_THRESHOLD (uint32_t)1
#define OG_MAX_LRU_SEARCH_THRESHOLD (uint32_t)100

#define OG_MIN_PAGE_CLEAN_RATIO (double)0.0001
#define OG_MAX_PAGE_CLEAN_RATIO (double)1

#define OLD_PREFIX_SYS_PART_NAME "SYS_P"
#define OLD_PREFIX_SYS_PART_NAME_LEN 5
#define NEW_PREFIX_SYS_PART_NAME "_SYS_P"
#define NEW_PREFIX_SYS_PART_NAME_LEN 6
#define PREFIX_SYS_SUBPART_NAME "_SYS_SUBP"
#define PREFIX_SYS_SUBPART_NAME_LEN 9

/* _log_level */
#define LOG_RUN_ERR_LEVEL 0x00000001
#define LOG_RUN_WAR_LEVEL 0x00000002
#define LOG_RUN_INF_LEVEL 0x00000004
#define LOG_DEBUG_ERR_LEVEL 0x00000010
#define LOG_DEBUG_WAR_LEVEL 0x00000020
#define LOG_DEBUG_INF_LEVEL 0x00000040
#define LOG_LONGSQL_LEVEL 0x00000100
#define LOG_OPER_LEVEL 0x00000200
#define LOG_FATAL_LEVEL 0xFFFFFFFF
#define LOG_ODBC_ERR_LEVEL 0x00001000
#define LOG_ODBC_WAR_LEVEL 0x00002000
#define LOG_ODBC_INF_LEVEL 0x00004000

/* log print interval */
#define LOG_PRINT_INTERVAL_SECOND_10 10
#define LOG_PRINT_INTERVAL_SECOND_20 20
#define LOG_PRINT_INTERVAL_SECOND_60 60

// 0x00010000 ~ 0x00800000 reserved for DTC
#define DTC_DCS_LOG_INF_LEVEL 0x00010000  // 65536
#define DTC_DCS_LOG_ERR_LEVEL 0x00020000  // 131072
#define DTC_DLS_LOG_INF_LEVEL 0x00040000  // 262144
#define DTC_DLS_LOG_ERR_LEVEL 0x00080000  // 524288
#define DTC_MES_LOG_INF_LEVEL 0x00100000  // 1048576
#define DTC_MES_LOG_ERR_LEVEL 0x00200000  // 2097152
#define DTC_DRC_LOG_INF_LEVEL 0x00400000  // 4194304
#define DTC_DRC_LOG_ERR_LEVEL 0x00800000  // 8388608

#define MAX_LOG_LEVEL                                                                                                  \
    ((LOG_RUN_ERR_LEVEL) | (LOG_RUN_WAR_LEVEL) | (LOG_RUN_INF_LEVEL) | (LOG_DEBUG_ERR_LEVEL) | (LOG_DEBUG_WAR_LEVEL) | \
     (LOG_DEBUG_INF_LEVEL) | (LOG_LONGSQL_LEVEL) | (LOG_OPER_LEVEL) | (DTC_DCS_LOG_INF_LEVEL) |                        \
     (DTC_DCS_LOG_ERR_LEVEL) | (DTC_DLS_LOG_INF_LEVEL) | (DTC_DLS_LOG_ERR_LEVEL) | (DTC_MES_LOG_INF_LEVEL) |           \
     (DTC_MES_LOG_ERR_LEVEL) | (DTC_DRC_LOG_INF_LEVEL) | (DTC_DRC_LOG_ERR_LEVEL))
#define MAX_LOG_ODBC_LEVEL ((LOG_ODBC_ERR_LEVEL) | (LOG_ODBC_WAR_LEVEL) | (LOG_ODBC_INF_LEVEL))

#define ARCHIVE_DEST_N_LEN 20
#define OG_PERCENT (uint32)100
#define OG_MAX_RAND_RANGE 1048576  // (1024 * 1024)

#define SET_NULL_FLAG(flag, is_null) ((flag) = (flag)&0xFE, (flag) |= (is_null))
#define SET_DIR_FLAG(flag, dir) ((flag) = (flag)&0xF9, (flag) |= (dir) << 1)
#define GET_NULL_FLAG(flag) ((flag)&0x1)
#define GET_DIR_FLAG(flag) ((flag)&0x6) >> 1

#define GET_DATA_TYPE(type) (og_type_t)(type == OG_TYPE_UNKNOWN ? OG_TYPE_UNKNOWN : (type) + OG_TYPE_BASE)
#define SET_DATA_TYPE(type, datatype) \
    ((type) = (int8)((datatype) == OG_TYPE_UNKNOWN ? OG_TYPE_UNKNOWN : ((datatype)-OG_TYPE_BASE)))

#define IS_COMPLEX_TYPE(type) (type) == OG_TYPE_COLLECTION || (type) == OG_TYPE_RECORD || (type) == OG_TYPE_OBJECT

static inline uint64 cm_get_next_2power(uint64 size)
{
    uint64 val = 1;

    while (val < size) {
        val <<= 1;
    }
    return val;
}

static inline uint64 cm_get_prev_2power(uint64 size)
{
    uint64 val = 1;

    while (val <= size) {
        val <<= 1;
    }
    return val / 2;
}

#define BUDDY_MEM_POOL_MAX_SIZE SIZE_G((uint64)10)
#define BUDDY_MEM_POOL_MIN_SIZE SIZE_M(32)
#define BUDDY_MIN_BLOCK_SIZE (uint64)64
#define BUDDY_MAX_BLOCK_SIZE SIZE_G(2)

#define BUDDY_INIT_BLOCK_SIZE SIZE_M(32)
#define BUDDY_MEM_POOL_INIT_SIZE SIZE_G(2)

#define BUDDY_MAX_ARCH_FILE_SIZE SIZE_G((uint64)10)
#define BUDDY_MIN_ARCH_FILE_SIZE SIZE_M((uint64)512)

static inline bool32 cm_is_even(int32 val)
{
    return (val & 1) == 0;
}

static inline bool32 cm_is_odd(int32 val)
{
    return (val & 1) == 1;
}

#define CM_ABS(val) ((val) < 0 ? -(val) : (val))

// gen scn with given seq
#define OG_TIMESEQ_TO_SCN(time_val, init_time, seq) \
    ((uint64)((time_val)->tv_sec - (init_time)) << 32 | (uint64)(time_val)->tv_usec << 12 | (seq))

#define OG_SCN_TO_TIMESEQ(scn, time_val, seq, init_time)                                  \
    do {                                                                                  \
        (time_val)->tv_sec = (long)(((scn) >> 32 & 0x00000000ffffffffULL) + (init_time)); \
        (time_val)->tv_usec = (long)((scn) >> 12 & 0x00000000000fffffULL);                \
        seq = (uint64)((scn)&0x0000000000000fffULL);                                      \
    } while (0)

// gen scn with 0x000 seq
#define OG_TIME_TO_SCN(time_val, init_time) \
    ((uint64)((time_val)->tv_sec - (init_time)) << 32 | (uint64)(time_val)->tv_usec << 12)

#define OG_SCN_TO_TIME(scn, time_val, init_time)                                                    \
    do {                                                                                            \
        (time_val)->tv_sec = (long)((((uint64)(scn)) >> 32 & 0x00000000ffffffffULL) + (init_time)); \
        (time_val)->tv_usec = (long)(((uint64)(scn)) >> 12 & 0x00000000000fffffULL);                \
    } while (0)
#define OG_MQ_MAX_THD_NUM (uint32)1024
#define OG_MQ_MIN_THD_NUM (uint32)1

#define OG_MQ_MAX_QUEUE_NUM (uint32)64
#define OG_MQ_MIN_QUEUE_NUM (uint32)1

#define OG_MAX_RES_RECYCLE_RATIO (uint32)95
#define OG_MIN_RES_RECYCLE_RATIO (uint32)50

#define OG_MAX_CREATE_INDEX_PARALLELISM (uint32)10
#define OG_MIN_CREATE_INDEX_PARALLELISM (uint32)0

#define OG_MQ_MAX_COOL_TIME (uint32)0xffffffff
#define OG_MQ_MIN_COOL_TIME (uint32)0

#define OG_MAX_RCY_NODE_BUF_SIZE (uint32)10
#define OG_MIN_RCY_NODE_BUF_SIZE (uint32)2

#define OG_MAX_DTC_RCY_PARAL_BUF_LIST_SIZE (uint32)256
#define OG_MIN_DTC_RCY_PARAL_BUF_LIST_SIZE (uint32)2

#ifndef EXTER_ATTACK
#define EXTER_ATTACK
#endif

#ifndef SENSI_INFO
#define SENSI_INFO
#endif

#ifdef __cplusplus
}
#endif

#endif
