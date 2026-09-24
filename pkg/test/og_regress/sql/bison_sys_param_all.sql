-- Bison ALTER SYSTEM g_parameters coverage: 419/419.
-- Every parameter is exercised with its declared default and a verifier-specific follow-up value.
-- Read-only and environment-dependent defaults retain inline --error markers.
alter system set use_bison_parser = true scope = memory;

-- Declared-default cases.
alter system set LSNR_ADDR = '127.0.0.1' scope = pfile;
alter system set LSNR_PORT = '1611' scope = pfile;
alter system set WORKER_THREADS = '100' scope = pfile;
alter system set OPTIMIZED_WORKER_THREADS = '100' scope = both;
alter system set MAX_WORKER_THREADS = '100' scope = pfile;
alter system set REACTOR_THREADS = '2' scope = pfile;
alter system set SQL_COMPAT = OGDB scope = pfile;
alter system set DATA_BUFFER_SIZE = '128M' scope = pfile;
alter system set VARIANT_MEMORY_AREA_SIZE = '32M' scope = pfile;
alter system set LARGE_VARIANT_MEMORY_AREA_SIZE = '32M' scope = pfile;
alter system set _VMP_CACHES_EACH_SESSION = '8' scope = pfile;
alter system set _VMA_MEM_CHECK = FALSE scope = pfile;
alter system set PMA_BUFFER_SIZE = '128M' scope = pfile;
alter system set HASH_AREA_SIZE = '4M' scope = pfile;
alter system set SHARED_POOL_SIZE = '192M' scope = pfile;
alter system set _SQL_POOL_FACTOR = '0.3' scope = pfile;
alter system set LARGE_POOL_SIZE = '32M' scope = pfile;
alter system set LOG_BUFFER_SIZE = '4M' scope = pfile;
alter system set LOG_BUFFER_COUNT = '4' scope = pfile;
alter system set TEMP_BUFFER_SIZE = '32M' scope = pfile;
alter system set USE_LARGE_PAGES = TRUE scope = pfile;
alter system set USE_NATIVE_DATATYPE = TRUE scope = pfile;
alter system set JOB_THREADS = '100' scope = pfile;
alter system set CR_POOL_SIZE = '32M' scope = pfile;
alter system set CR_POOL_COUNT = '1' scope = pfile;
alter system set DEFAULT_TABLESPACE_TYPE = NORMAL scope = pfile;
alter system set BUFFER_PAGE_CLEAN_PERIOD = '0' scope = pfile;
alter system set BUFFER_LRU_SEARCH_THRE = '60' scope = pfile;
alter system set BUFFER_PAGE_CLEAN_RATIO = '0.4' scope = pfile;
alter system set _BUFFER_PAGE_CLEAN_WAIT_TIMEOUT = '0' scope = pfile;
alter system set _CHECKPOINT_TIMED_TASK_DELAY = '100' scope = pfile;
alter system set _SPIN_COUNT = '1000' scope = pfile;
alter system set _ENABLE_QOS = FALSE scope = pfile;
alter system set _QOS_CTRL_FACTOR = '0.75' scope = pfile;
alter system set _QOS_SLEEP_TIME = '20' scope = pfile;
alter system set _QOS_RANDOM_RANGE = '64' scope = pfile;
alter system set _INDEX_BUFFER_SIZE = '8M' scope = pfile;
alter system set _INDEX_AUTO_REBUILD = FALSE scope = pfile;
alter system set _INDEX_AUTO_REBUILD_START_TIME = '' scope = pfile;
alter system set _AUTO_INDEX_RECYCLE = ON scope = pfile;
alter system set _INDEX_RECYCLE_PERCENT = '20' scope = pfile;
alter system set _INDEX_RECYCLE_SIZE = '2G' scope = pfile;
alter system set _FORCE_INDEX_RECYCLE = '14400' scope = pfile;
alter system set _INDEX_RECYCLE_REUSE = '512' scope = pfile;
alter system set _INDEX_REBUILD_KEEP_STORAGE = '43200' scope = pfile;
alter system set _DOUBLEWRITE = TRUE scope = pfile;
alter system set _THREAD_STACK_SIZE = '512K' scope = pfile;
alter system set _BLACKBOX_STACK_DEPTH = '30' scope = pfile;
alter system set _HINT_FORCE = '0' scope = pfile;
alter system set _RCY_CHECK_PCN = TRUE scope = pfile;
alter system set _SGA_CORE_DUMP_CONFIG = '0' scope = pfile;
alter system set _MAX_RM_COUNT = '0' scope = pfile;
alter system set _SMALL_TABLE_SAMPLING_THRESHOLD = '10000' scope = pfile;
alter system set _ASHRINK_WAIT_TIME = '21600' scope = pfile;
alter system set _SHRINK_WAIT_RECYCLED_PAGES = '1024' scope = pfile;
alter system set _TEMPTABLE_SUPPORT_BATCH_INSERT = FALSE scope = pfile;
alter system set _AGENT_STACK_SIZE = '2M' scope = pfile;
alter system set _LOB_MAX_EXEC_SIZE = '65534' scope = pfile;
alter system set _VARIANT_AREA_SIZE = '256K' scope = pfile;
alter system set _INIT_CURSORS = '32' scope = pfile;
alter system set _DISABLE_SOFT_PARSE = FALSE scope = pfile;
alter system set SESSIONS = '200' scope = pfile;
alter system set KNL_AUTONOMOUS_SESSIONS = '8' scope = pfile;
alter system set AUTONOMOUS_SESSIONS = '8' scope = pfile;
alter system set SUPER_USER_RESERVED_SESSIONS = '10' scope = pfile;
alter system set NORMAL_USER_RESERVED_SESSIONS_FACTOR = '1' scope = pfile;
alter system set OPEN_CURSORS = '2000' scope = pfile;
alter system set _PREFETCH_ROWS = '100' scope = pfile;
alter system set PAGE_SIZE = 8K scope = pfile;
alter system set COMMIT_MODE = IMMEDIATE scope = pfile;
alter system set COMMIT_WAIT_LOGGING = WAIT scope = pfile;
alter system set CONTROL_FILES = '' scope = pfile;
alter system set KMC_KEY_FILES = '' scope = pfile;
alter system set PAGE_CHECKSUM = TYPICAL scope = pfile;
alter system set DB_ISOLEVEL = RC scope = pfile;
alter system set _SERIALIZED_COMMIT = FALSE scope = pfile;
alter system set ARCHIVE_CONFIG = 'SEND,RECEIVE,NODG_CONFIG' scope = pfile;
alter system set ARCHIVE_CONFIG = 'SEND   ,         RECEIVE  ,  NODG_CONFIG   ' scope = pfile;
alter system set ARCHIVE_CONFIG = 'send,Receive,NoDg_Config' scope = pfile;
alter system set ARCHIVE_DEST_1 = '' scope = pfile;
alter system set ARCHIVE_DEST_2 = '' scope = pfile;
alter system set ARCHIVE_DEST_3 = '' scope = pfile;
alter system set ARCHIVE_DEST_4 = '' scope = pfile;
alter system set ARCHIVE_DEST_5 = '' scope = pfile;
alter system set ARCHIVE_DEST_6 = '' scope = pfile;
alter system set ARCHIVE_DEST_7 = '' scope = pfile;
alter system set ARCHIVE_DEST_8 = '' scope = pfile;
alter system set ARCHIVE_DEST_9 = '' scope = pfile;
alter system set ARCHIVE_DEST_10 = '' scope = pfile;
alter system set ARCHIVE_DEST_STATE_1 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_2 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_3 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_4 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_5 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_6 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_7 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_8 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_9 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_DEST_STATE_10 = 'ENABLE' scope = pfile;
alter system set ARCHIVE_FORMAT = 'arch_%t_%r_%s.arc' scope = pfile;
alter system set ARCHIVE_FORMAT_WITH_LSN = 'arch_%t_%r_%s_%d_%e.arc' scope = pfile;
alter system set ARCHIVE_MAX_THREADS = '1' scope = pfile;
alter system set ARCHIVE_MIN_SUCCEED_DEST = '1' scope = pfile;
alter system set ARCHIVE_TRACE = '0' scope = pfile;
alter system set ENABLE_ARCH_COMPRESS = FALSE scope = pfile;
alter system set QUORUM_ANY = '0' scope = pfile;
alter system set CHECKPOINT_PERIOD = '300' scope = pfile;
alter system set CHECKPOINT_PAGES = '100000' scope = pfile;
alter system set CHECKPOINT_IO_CAPACITY = '1024' scope = pfile;
alter system set _CHECKPOINT_MERGE_IO = TRUE scope = pfile;
alter system set CHECKPOINT_GROUP_SIZE = '4096' scope = pfile;
alter system set LOG_REPLAY_PROCESSES = '1' scope = pfile;
alter system set REPLAY_PRELOAD_PROCESSES = '0' scope = pfile;
alter system set _RCY_SLEEP_INTERVAL = '32' scope = pfile;
alter system set TIMED_STATS = TRUE scope = pfile;
alter system set STATS_LEVEL = TYPICAL scope = pfile;
alter system set DBWR_PROCESSES = '8' scope = pfile;
alter system set SQL_STAT = TRUE scope = pfile;
alter system set INSTANCE_NAME = 'oGRAC' scope = pfile;
alter system set ALARM_LOG_DIR = '' scope = pfile; --error
alter system set REPL_ADDR = '' scope = pfile;
alter system set REPL_PORT = '0' scope = pfile;
alter system set REPL_TRUST_HOST = '' scope = pfile;
alter system set REPL_AUTH = FALSE scope = pfile;
alter system set REPL_SCRAM_AUTH = FALSE scope = pfile;
alter system set _REPL_MAX_PKG_SIZE = '0' scope = pfile;
alter system set FILE_OPTIONS = NONE scope = pfile;
alter system set BUILD_DATAFILE_PARALLEL = FALSE scope = pfile;
alter system set ENABLE_TEMP_SPACE_BITMAP = TRUE scope = pfile;
alter system set BUILD_DATAFILE_PREALLOCATE = FALSE scope = pfile;
alter system set _ENCRYPTION_ALG = SCRAM_SHA256 scope = pfile;
alter system set _SYS_PASSWORD = '' scope = pfile; --error
alter system set TC_LEVEL = '1' scope = pfile;
alter system set AUDIT_LEVEL = '3' scope = pfile;
alter system set AUDIT_TRAIL_MODE = FILE scope = pfile;
alter system set AUDIT_SYSLOG_LEVEL = 'LOCAL0.DEBUG' scope = pfile;
alter system set LOG_HOME = '' scope = pfile; --error
alter system set _LOG_BACKUP_FILE_COUNT = '10' scope = pfile;
alter system set _AUDIT_BACKUP_FILE_COUNT = '10' scope = pfile;
alter system set _LOG_MAX_FILE_SIZE = '10M' scope = pfile;
alter system set _AUDIT_MAX_FILE_SIZE = '10M' scope = pfile;
alter system set _LOG_LEVEL = 7 scope = pfile;
alter system set _LOG_FILE_PERMISSIONS = '640' scope = pfile;
alter system set _LOG_PATH_PERMISSIONS = '750' scope = pfile;
alter system set UNDO_RESERVE_SIZE = '1024' scope = pfile;
alter system set UNDO_RETENTION_TIME = '100' scope = pfile;
alter system set INDEX_DEFER_RECYCLE_TIME = '0' scope = pfile;
alter system set _UNDO_SEGMENTS = '32' scope = pfile;
alter system set _UNDO_ACTIVE_SEGMENTS = '32' scope = pfile;
alter system set _UNDO_AUTON_TRANS_SEGMENTS = '1' scope = pfile;
alter system set _UNDO_AUTON_BIND_OWN_SEGMENT = FALSE scope = pfile;
alter system set _UNDO_AUTO_SHRINK = TRUE scope = pfile;
alter system set _UNDO_AUTO_SHRINK_INACTIVE = FALSE scope = pfile;
alter system set UNDO_PREFETCH_PAGE_NUM = '1' scope = pfile;
alter system set _TX_ROLLBACK_PROC_NUM = '2' scope = pfile;
alter system set REPL_WAIT_TIMEOUT = '10' scope = pfile;
alter system set COMMIT_ON_DISCONNECT = FALSE scope = pfile;
alter system set _MAX_CONNECT_BY_LEVEL = '256' scope = pfile;
alter system set BACKUP_BUFFER_SIZE = '128M' scope = pfile;
alter system set RESTORE_ARCH_COMPRESSED = FALSE scope = pfile;
alter system set _INDEX_SCAN_RANGE_CACHE = '100' scope = pfile;
alter system set _RESTORE_CHECK_VERSION = TRUE scope = pfile;
alter system set RESTOR_ARCH_PREFER_BAK_SET = FALSE scope = pfile;
alter system set NBU_BACKUP_TIMEOUT = '90' scope = pfile;
alter system set _CHECK_SYSDATA_VERSION = TRUE scope = pfile;
alter system set MAX_ARCH_FILES_SIZE = '60G' scope = pfile;
alter system set ARCH_LOG_CHECK = TRUE scope = pfile;
alter system set ARCH_FILE_SIZE = '10G' scope = pfile;
alter system set ARCH_SIZE = '512M' scope = pfile;
alter system set ARCH_TIME = '60000000' scope = pfile;
alter system set ARCH_CLEAN_UPPER_LIMIT = '85' scope = pfile;
alter system set ARCH_CLEAN_LOWER_LIMIT = '30' scope = pfile;
alter system set ARCH_CLEAN_IGNORE_BACKUP = TRUE scope = pfile;
alter system set ARCH_CLEAN_IGNORE_STANDBY = FALSE scope = pfile;
alter system set XA_SUSPEND_TIMEOUT = '60' scope = pfile;
alter system set BUILD_KEEP_ALIVE_TIMEOUT = '30' scope = pfile;
alter system set _BACKUP_LOG_PARALLEL = FALSE scope = pfile;
alter system set TCP_VALID_NODE_CHECKING = FALSE scope = pfile;
alter system set TCP_INVITED_NODES = '' scope = pfile;
alter system set TCP_EXCLUDED_NODES = '' scope = pfile;
alter system set LOCK_WAIT_TIMEOUT = '0' scope = pfile;
alter system set ENABLE_RAFT = FALSE scope = pfile;
alter system set RAFT_START_MODE = '0' scope = pfile;
alter system set RAFT_NODE_ID = '' scope = pfile; --error
alter system set RAFT_PEER_IDS = '' scope = pfile;
alter system set RAFT_LOCAL_ADDR = '' scope = pfile;
alter system set RAFT_PEER_ADDRS = '' scope = pfile;
alter system set RAFT_LOG_LEVEL = '2' scope = pfile;
alter system set RAFT_KUDU_DIR = '' scope = pfile;
alter system set RAFT_PRIORITY_TYPE = 'External' scope = pfile;
alter system set RAFT_PRIORITY_LEVEL = '0' scope = pfile;
alter system set RAFT_LAYOUT_INFO = '' scope = pfile;
alter system set RAFT_PENDING_CMDS_BUFFER_SIZE = '1000' scope = pfile;
alter system set RAFT_SEND_BUFFER_SIZE = '100' scope = pfile;
alter system set RAFT_RECEIVE_BUFFER_SIZE = '100' scope = pfile;
alter system set RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE = '2G' scope = pfile;
alter system set RAFT_MAX_SIZE_PER_MSG = '128M' scope = pfile;
alter system set RAFT_ELECTION_TIMEOUT = '5' scope = pfile;
alter system set RAFT_MEMORY_THRESHOLD = '5G' scope = pfile;
alter system set RAFT_LOG_ASYNC_BUF_NUM = '16' scope = pfile;
alter system set RAFT_FAILOVER_LIB_TIMEOUT = '600' scope = pfile;
alter system set RAFT_TLS_DIR = '' scope = pfile; --error
alter system set RAFT_TOKEN_VERIFY = 'FALSE' scope = pfile;
alter system set LOCAL_KEY = '' scope = both; --error
alter system set BUF_POOL_NUM = '1' scope = pfile;
alter system set DEFAULT_EXTENTS = '8' scope = pfile;
alter system set _MAX_VM_FUNC_STACK_COUNT = '0' scope = pfile;
alter system set TEMP_POOL_NUM = '1' scope = pfile;
alter system set MERGE_SORT_BATCH_SIZE = '100000' scope = pfile;
alter system set ENABLE_NESTLOOP_JOIN = TRUE scope = pfile;
alter system set ENABLE_HASH_JOIN = FALSE scope = pfile;
alter system set ENABLE_MERGE_JOIN = TRUE scope = pfile;
alter system set MAX_ALLOWED_PACKET = '64M' scope = pfile;
alter system set DB_FILE_NAME_CONVERT = '' scope = pfile;
alter system set LOG_FILE_NAME_CONVERT = '' scope = pfile;
alter system set INTERACTIVE_TIMEOUT = '1800' scope = pfile;
alter system set SQL_STAGE_THRESHOLD = '10' scope = pfile;
alter system set SSL_CA = '' scope = pfile;
alter system set SSL_CERT = '' scope = pfile;
alter system set SSL_KEY = '' scope = pfile;
alter system set SSL_CRL = '' scope = pfile;
alter system set SSL_VERIFY_PEER = FALSE scope = pfile;
alter system set SSL_KEY_PASSWORD = '' scope = pfile;
alter system set SSL_CIPHER = '' scope = pfile;
alter system set SSL_EXPIRE_ALERT_THRESHOLD = '90' scope = pfile;
alter system set SSL_PERIOD_DETECTION = '7' scope = pfile;
alter system set LOCAL_TEMPORARY_TABLE_ENABLED = FALSE scope = pfile;
alter system set UPPER_CASE_TABLE_NAMES = TRUE scope = pfile;
alter system set UNAUTH_SESSION_EXPIRE_TIME = '60' scope = pfile;
alter system set ENABLE_SYSDBA_LOGIN = TRUE scope = pfile;
alter system set ENABLE_SYS_REMOTE_LOGIN = FALSE scope = pfile;
alter system set ENABLE_SYSDBA_REMOTE_LOGIN = FALSE scope = pfile;
alter system set RESOURCE_LIMIT = FALSE scope = pfile;
alter system set _FACTOR_KEY = '' scope = both; --error
alter system set ENABLE_ERR_SUPERPOSED = FALSE scope = pfile;
alter system set EMPTY_STRING_AS_NULL = TRUE scope = pfile;
alter system set ZERO_DIVISOR_ACCEPTED = FALSE scope = pfile;
alter system set STRING_AS_HEX_FOR_BINARY = FALSE scope = pfile;
alter system set DROP_NOLOGGING = FALSE scope = pfile;
alter system set RECYCLEBIN = TRUE scope = pfile;
alter system set HAVE_SSL = 'FALSE' scope = pfile; --error
alter system set _ENCRYPTION_ITERATION = '10000' scope = pfile;
alter system set MAX_TEMP_TABLES = '256' scope = pfile;
alter system set ENABLE_IDX_CONFS_NAME_DUPL = 'FALSE' scope = pfile; --error
alter system set ENABLE_IDX_KEY_LEN_CHECK = TRUE scope = pfile;
alter system set CBO = ON scope = pfile;
alter system set MAX_COLUMN_COUNT = 1024 scope = pfile; --error
alter system set STATISTICS_SAMPLE_SIZE = '128M' scope = pfile;
alter system set _SQL_CURSORS_EACH_SESSION = '8' scope = pfile;
alter system set _RESERVED_SQL_CURSORS = '80' scope = pfile;
alter system set COVERAGE_ENABLE = FALSE scope = pfile;
alter system set TYPE_MAP_FILE = '' scope = pfile; --error
alter system set INI_TRANS = '2' scope = pfile;
alter system set INT_SYSINDEX_TRANS = '2' scope = pfile;
alter system set CR_MODE = PAGE scope = pfile;
alter system set ROW_FORMAT = ASF scope = pfile;
alter system set _LNS_WAIT_TIME = '3' scope = pfile;
alter system set _PRIVATE_KEY_LOCKS = '8' scope = pfile;
alter system set _PRIVATE_ROW_LOCKS = '8' scope = pfile;
alter system set DDL_LOCK_TIMEOUT = '30' scope = pfile;
alter system set MAX_REMOTE_PARAMS = '300' scope = pfile;
alter system set DB_TIMEZONE = '+00:00' scope = pfile;
alter system set TABLESPACE_USAGE_ALARM_THRESHOLD = '80' scope = pfile;
alter system set UNDO_USAGE_ALARM_THRESHOLD = '0' scope = pfile;
alter system set TXN_UNDO_USAGE_ALARM_THRESHOLD = '0' scope = pfile;
alter system set _SYSTIME_INCREASE_THREASHOLD = '365' scope = pfile;
alter system set BLOCK_REPAIR_ENABLE = FALSE scope = pfile;
alter system set BLOCK_REPAIR_TIMEOUT = '60' scope = pfile;
alter system set UDS_FILE_PATH = '' scope = pfile;
alter system set UDS_FILE_PERMISSIONS = '600' scope = pfile;
alter system set STATS_COST_LIMIT = '0' scope = pfile;
alter system set STATS_COST_DELAY = '0' scope = pfile;
alter system set ENABLE_SAMPLE_LIMIT = FALSE scope = pfile;
alter system set MASTER_SLAVE_DIFFTIME = '10' scope = pfile;
alter system set WORKER_THREADS_SHRINK_THRESHOLD = '1800' scope = pfile;
alter system set XA_FORMAT_ID = '247' scope = pfile; --error
alter system set DEGRADE_SEARCH_MAP = TRUE scope = pfile;
alter system set CPU_NODE_BIND = '' scope = pfile; --error
alter system set RESOURCE_PLAN = '' scope = pfile;
alter system set STATS_MAX_BUCKET_SIZE = '254' scope = pfile;
alter system set PARALLEL_POLICY = ON scope = pfile;
alter system set DELAY_CLEANOUT = TRUE scope = pfile;
alter system set ENABLE_ACCESS_DC = TRUE scope = pfile;
alter system set _VIEW_ACCESS_DC = FALSE scope = pfile;
alter system set ENABLE_PERMISSIVE_UNICODE = FALSE scope = pfile;
alter system set NODE_LOCK_STATUS = NOLOCK scope = pfile;
alter system set UNDO_TABLESPACE = '' scope = pfile;
alter system set LOB_REUSE_THRESHOLD = '80M' scope = pfile;
alter system set ENABLE_LOCAL_INFILE = FALSE scope = pfile;
alter system set ARRAY_STORAGE_OPTIMIZATION = FALSE scope = pfile;
alter system set _MAX_JSON_DYNAMIC_BUFFER_SIZE = '1G' scope = pfile;
alter system set SLOWSQL_STATS_ENABLE = FALSE scope = pfile;
alter system set STATS_PARALL_THREADS = '2' scope = pfile;
alter system set STATS_ENABLE_PARALL = FALSE scope = pfile;
alter system set _OUTER_JOIN_OPTIMIZATION = OFF scope = pfile;
alter system set CBO_INDEX_CACHING = '0' scope = pfile;
alter system set CBO_INDEX_COST_ADJ = '100' scope = pfile;
alter system set CBO_PATH_CACHING = '3' scope = pfile;
alter system set _WITHAS_SUBQUERY = OPTIMIZER scope = pfile;
alter system set MAX_PBL_FILE_SIZE = '10M' scope = pfile;
alter system set _DISTINCT_PRUNING = ON scope = pfile;
alter system set _QUERY_TOPN_THRESHOLD = '1000' scope = pfile;
alter system set _CONNECT_BY_MATERIALIZE = TRUE scope = pfile;
alter system set INIT_LOCK_POOL_PAGES = '1024' scope = pfile;
alter system set _OPTIMIZER_AGGR_PLACEMENT = TRUE scope = pfile;
alter system set _OPTIM_OR_EXPANSION = TRUE scope = pfile;
alter system set _OPTIM_DISTINCT_ELIMINATION = TRUE scope = pfile;
alter system set _OPTIM_PROJECT_LIST_PRUNING = TRUE scope = pfile;
alter system set _OPTIM_PRED_MOVE_AROUND = TRUE scope = pfile;
alter system set _OPTIM_PRED_DELIVERY = TRUE scope = pfile;
alter system set _OPTIM_HASH_MATERIALIZE = TRUE scope = pfile;
alter system set _OPTIM_WINMAGIC_REWRITE = TRUE scope = pfile;
alter system set _OPTIM_PRED_REORDER = TRUE scope = pfile;
alter system set _OPTIM_ORDER_BY_PLACEMENT = TRUE scope = pfile;
alter system set _OPTIM_SUBQUERY_ELIMINATION = TRUE scope = pfile;
alter system set _OPTIM_JOIN_ELIMINATION = TRUE scope = pfile;
alter system set _OPTIM_CONNECT_BY_PLACEMENT = TRUE scope = pfile;
alter system set _OPTIM_GROUP_BY_ELIMINATION = TRUE scope = pfile;
alter system set _OPTIM_ANY_TRANSFORM = TRUE scope = pfile;
alter system set _OPTIM_ALL_TRANSFORM = TRUE scope = pfile;
alter system set _ENABLE_MULTI_INDEX_SCAN = TRUE scope = pfile;
alter system set _OPTIM_JOIN_PRED_PUSHDOWN = TRUE scope = pfile;
alter system set _OPTIM_FILTER_PUSHDOWN = TRUE scope = pfile;
alter system set _OPTIM_INDEX_SCAN_MAX_PARTS = '200' scope = pfile;
alter system set _OPTIM_ORDER_BY_ELIMINATION = TRUE scope = pfile;
alter system set _OPTIM_UNNEST_SET_SUBQUERY = TRUE scope = pfile;
alter system set _OPTIM_ENABLE_RIGHT_SEMIJOIN = TRUE scope = pfile;
alter system set _OPTIM_ENABLE_RIGHT_ANTIJOIN = TRUE scope = pfile;
alter system set _OPTIM_ENABLE_RIGHT_LEFTJOIN = TRUE scope = pfile;
alter system set SEGMENT_PAGES_HOLD = '0' scope = pfile;
alter system set HASH_TABLE_PAGES_HOLD = '128' scope = pfile;
alter system set _OPTIM_SIMPLIFY_EXISTS_SUBQ = TRUE scope = pfile;
alter system set _OPTIM_SUBQUERY_REWRITE = FALSE scope = pfile;
alter system set _OPTIM_SEMI2INNER = TRUE scope = pfile;
alter system set _OPTIM_PRED_PUSHDOWN = TRUE scope = pfile;
alter system set _OPTIM_IN_TRANSFORM = TRUE scope = pfile;
alter system set CTRLLOG_BACKUP_LEVEL = NONE scope = pfile;
alter system set _OPTIM_FUNC_INDEX_SCAN_ONLY = TRUE scope = pfile;
alter system set _OPTIM_INDEX_COND_PRUNING = TRUE scope = pfile;
alter system set _OPTIM_VM_VIEW_ENABLED = TRUE scope = pfile;
alter system set _OPTIM_ADAPTIVE_FULL_OUTER_JOIN = TRUE scope = pfile;
alter system set _TABLE_COMPRESS_ALGO = NONE scope = pfile;
alter system set _TABLE_COMPRESS_BUFFER_SIZE = '16M' scope = pfile;
alter system set _TABLE_COMPRESS_ENABLE_BUFFER = FALSE scope = pfile;
alter system set ENABLE_PASSWORD_CIPHER = TRUE scope = pfile;
alter system set CBO_HINT_ENABLED = TRUE scope = pfile;
alter system set PARALLEL_MAX_THREADS = '16' scope = pfile;
alter system set _OPT_CBO_STAT_SAMPLING_LEVEL = '0' scope = pfile;
alter system set _STRICT_CASE_DATATYPE = FALSE scope = pfile;
alter system set MAX_LINK_TABLES = '32' scope = pfile;
alter system set AUTO_INHERIT_USER = OFF scope = pfile;
alter system set REPLACE_PASSWORD_VERIFY = FALSE scope = pfile;
alter system set CLUSTER_DATABASE = FALSE scope = pfile;
alter system set INTERCONNECT_ADDR = '127.0.0.1' scope = pfile;
alter system set INTERCONNECT_PORT = '1611' scope = pfile;
alter system set INTERCONNECT_TYPE = 'TCP' scope = pfile; --error
alter system set INTERCONNECT_CHANNEL_NUM = '1' scope = pfile;
alter system set REACTOR_THREAD_NUM = '2' scope = pfile;
alter system set MES_CPU_INFO = '' scope = pfile; --error
alter system set ENABLE_TX_FREE_PAGE_LIST = TRUE scope = pfile;
alter system set OGRAC_TASK_NUM = '16' scope = pfile;
alter system set INSTANCE_ID = '0' scope = pfile;
alter system set MES_POOL_SIZE = '256' scope = pfile;
alter system set OGSTORE_INST_PATH = 'UDS:/tmp/.ogstore_unix_d_socket' scope = pfile; --error
alter system set INTERCONNECT_BY_PROFILE = FALSE scope = pfile;
alter system set MES_ELAPSED_SWITCH = TRUE scope = pfile;
alter system set MES_CRC_CHECK_SWITCH = TRUE scope = pfile;
alter system set OGSTORE_MAX_OPEN_FILES = '1024' scope = pfile;
alter system set DSS_LOG_LEVEL = '7' scope = pfile;
alter system set _ENABLE_RMO_CR = TRUE scope = pfile;
alter system set _REMOTE_ACCESS_LIMIT = '4' scope = pfile;
alter system set OG_GDV_SQL_SESS_TMOUT = '10' scope = pfile;
alter system set DTC_CKPT_NOTIFY_TASK_RATIO = '0.125' scope = pfile;
alter system set DTC_CLEAN_EDP_TASK_RATIO = '0.125' scope = pfile;
alter system set DTC_TXN_INFO_TASK_RATIO = '0.25' scope = pfile;
alter system set RCY_NODE_READ_BUF_SIZE = '4' scope = pfile;
alter system set DTC_RCY_PARAL_BUF_LIST_SIZE = '256' scope = pfile;
alter system set CPU_GROUP_INFO = '0' scope = pfile; --error
alter system set _DEADLOCK_DETECT_INTERVAL = '1000' scope = pfile;
alter system set _AUTO_UNDO_RETENTION = '3' scope = pfile;
alter system set SHARED_PATH = '' scope = pfile;
alter system set ENABLE_DBSTOR = FALSE scope = pfile;
alter system set DBSTOR_DEPLOY_MODE = 0 scope = pfile;
select count(*) dbstor_default_match from dv_parameters
 where name = 'DBSTOR_DEPLOY_MODE' and value = '0' and runtime_value = '0';
alter system set DBSTOR_NAMESPACE = '' scope = pfile;
alter system set ENABLE_OGRAC_STATS = OFF scope = pfile;
alter system set PAGE_CLEAN_MODE = SINGLE scope = pfile;
alter system set ENABLE_DBSTOR_BATCH_FLUSH = FALSE scope = pfile;
alter system set CLUSTER_ID = '0' scope = pfile;
alter system set BACKUP_RETRY = TRUE scope = pfile;
alter system set BATCH_FLUSH_CAPACITY = '160' scope = pfile;
alter system set ENABLE_HWN_CHANGE = FALSE scope = pfile;
alter system set MES_CHANNEL_UPGRADE_TIME_MS = '0' scope = pfile;
alter system set MES_CHANNEL_DEGRADE_TIME_MS = '0' scope = pfile;
alter system set ENABLE_FDSA = FALSE scope = pfile;
alter system set ENABLE_BROADCAST_ON_COMMIT = TRUE scope = pfile;
alter system set MES_SSL_SWITCH = FALSE scope = pfile;
alter system set MES_SSL_CRT_KEY_PATH = '' scope = pfile; --error
alter system set MES_SSL_KEY_PWD = '' scope = pfile;
alter system set ENABLE_CHECK_SECURITY_LOG = FALSE scope = pfile;
alter system set ENABLE_SYS_CRC_CHECK = FALSE scope = pfile;
alter system set CLUSTER_NO_CMS = FALSE scope = pfile;
alter system set OG_CLUSTER_STRICT_CHECK = TRUE scope = pfile;
alter system set DRC_IN_REFORMER_MODE = FALSE scope = pfile;
alter system set RES_RECYCLE_RATIO = '50' scope = pfile;
alter system set CREATE_INDEX_PARALLELISM = '0' scope = pfile;
alter system set ENABLE_DSS = FALSE scope = pfile;
alter system set USE_BISON_PARSER = FALSE scope = pfile;
alter system set RBP_IP = '127.0.0.1' scope = pfile;
alter system set RBP_PORT = '2611' scope = pfile;
alter system set LOCAL_RBP_HOST = '127.0.0.1' scope = pfile;
alter system set USE_RBP = 'FALSE' scope = pfile;
alter system set RBP_FOR_RECOVERY = 'TRUE' scope = pfile;
alter system set RBP_RT_ANALYSIS = 'FALSE' scope = pfile;
alter system set RBP_RT_PARSE_WORKERS = '2' scope = pfile;
alter system set RBP_RT_PAGE_OWNER_WORKERS = '4' scope = pfile;
alter system set RBP_ASSEMBLE_MAX_SCAN = '300' scope = pfile;
alter system set PLAN_DISPLAY_FORMAT = 'TYPICAL' scope = pfile;
alter system set _SHOW_EXPLAIN_PREDICATE = TRUE scope = pfile;
alter system set ENABLE_QUICK_CKPT = FALSE scope = pfile;

-- Rejecting cases.
alter system set LSNR_ADDR = '127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1' scope = pfile; --error
alter system set LSNR_PORT = '1' scope = pfile; --error
alter system set WORKER_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set OPTIMIZED_WORKER_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_WORKER_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set REACTOR_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set SQL_COMPAT = 'BISON_INVALID' scope = pfile; --error
alter system set DATA_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set VARIANT_MEMORY_AREA_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set LARGE_VARIANT_MEMORY_AREA_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _VMP_CACHES_EACH_SESSION = 'BISON_INVALID' scope = pfile; --error
alter system set _VMA_MEM_CHECK = 'BISON_INVALID' scope = pfile; --error
alter system set PMA_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set HASH_AREA_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set SHARED_POOL_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _SQL_POOL_FACTOR = 'BISON_INVALID' scope = pfile; --error
alter system set LARGE_POOL_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set LOG_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set LOG_BUFFER_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set TEMP_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set USE_LARGE_PAGES = 'BISON_INVALID' scope = pfile; --error
alter system set USE_NATIVE_DATATYPE = 'BISON_INVALID' scope = pfile; --error
alter system set JOB_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set CR_POOL_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set CR_POOL_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set DEFAULT_TABLESPACE_TYPE = 'BISON_INVALID' scope = pfile; --error
alter system set BUFFER_PAGE_CLEAN_PERIOD = 'BISON_INVALID' scope = pfile; --error
alter system set BUFFER_LRU_SEARCH_THRE = 'BISON_INVALID' scope = pfile; --error
alter system set BUFFER_PAGE_CLEAN_RATIO = 'BISON_INVALID' scope = pfile; --error
alter system set _BUFFER_PAGE_CLEAN_WAIT_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set _CHECKPOINT_TIMED_TASK_DELAY = 'BISON_INVALID' scope = pfile; --error
alter system set _SPIN_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set _ENABLE_QOS = 'BISON_INVALID' scope = pfile; --error
alter system set _QOS_CTRL_FACTOR = 'BISON_INVALID' scope = pfile; --error
alter system set _QOS_SLEEP_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set _QOS_RANDOM_RANGE = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_AUTO_REBUILD = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_AUTO_REBUILD_START_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set _AUTO_INDEX_RECYCLE = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_RECYCLE_PERCENT = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_RECYCLE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _FORCE_INDEX_RECYCLE = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_RECYCLE_REUSE = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_REBUILD_KEEP_STORAGE = 'BISON_INVALID' scope = pfile; --error
alter system set _DOUBLEWRITE = 'BISON_INVALID' scope = pfile; --error
alter system set _THREAD_STACK_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _BLACKBOX_STACK_DEPTH = 'BISON_INVALID' scope = pfile; --error
alter system set _HINT_FORCE = 'BISON_INVALID' scope = pfile; --error
alter system set _RCY_CHECK_PCN = 'BISON_INVALID' scope = pfile; --error
alter system set _SGA_CORE_DUMP_CONFIG = 'BISON_INVALID' scope = pfile; --error
alter system set _MAX_RM_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set _SMALL_TABLE_SAMPLING_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set _ASHRINK_WAIT_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set _SHRINK_WAIT_RECYCLED_PAGES = 'BISON_INVALID' scope = pfile; --error
alter system set _TEMPTABLE_SUPPORT_BATCH_INSERT = 'BISON_INVALID' scope = pfile; --error
alter system set _AGENT_STACK_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _LOB_MAX_EXEC_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _VARIANT_AREA_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _INIT_CURSORS = 'BISON_INVALID' scope = pfile; --error
alter system set _DISABLE_SOFT_PARSE = 'BISON_INVALID' scope = pfile; --error
alter system set SESSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set KNL_AUTONOMOUS_SESSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set AUTONOMOUS_SESSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set SUPER_USER_RESERVED_SESSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set NORMAL_USER_RESERVED_SESSIONS_FACTOR = 'BISON_INVALID' scope = pfile; --error
alter system set OPEN_CURSORS = 'BISON_INVALID' scope = pfile; --error
alter system set _PREFETCH_ROWS = 'BISON_INVALID' scope = pfile; --error
alter system set PAGE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set COMMIT_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set COMMIT_WAIT_LOGGING = 'BISON_INVALID' scope = pfile; --error
alter system set CONTROL_FILES = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set KMC_KEY_FILES = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set PAGE_CHECKSUM = 'BISON_INVALID' scope = pfile; --error
alter system set DB_ISOLEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set _SERIALIZED_COMMIT = 'BISON_INVALID' scope = pfile; --error
alter system set ARCHIVE_CONFIG = 'BISON_INVALID' scope = pfile; --error
alter system set ARCHIVE_DEST_1 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_2 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_3 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_4 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_5 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_6 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_7 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_8 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_9 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_10 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_1 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_2 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_3 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_4 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_5 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_6 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_7 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_8 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_9 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_DEST_STATE_10 = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_FORMAT = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_FORMAT_WITH_LSN = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ARCHIVE_MAX_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set ARCHIVE_MIN_SUCCEED_DEST = 'BISON_INVALID' scope = pfile; --error
alter system set ARCHIVE_TRACE = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_ARCH_COMPRESS = 'BISON_INVALID' scope = pfile; --error
alter system set QUORUM_ANY = 'BISON_INVALID' scope = pfile; --error
alter system set CHECKPOINT_PERIOD = 'BISON_INVALID' scope = pfile; --error
alter system set CHECKPOINT_PAGES = 'BISON_INVALID' scope = pfile; --error
alter system set CHECKPOINT_IO_CAPACITY = 'BISON_INVALID' scope = pfile; --error
alter system set _CHECKPOINT_MERGE_IO = 'BISON_INVALID' scope = pfile; --error
alter system set CHECKPOINT_GROUP_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set LOG_REPLAY_PROCESSES = 'BISON_INVALID' scope = pfile; --error
alter system set REPLAY_PRELOAD_PROCESSES = 'BISON_INVALID' scope = pfile; --error
alter system set _RCY_SLEEP_INTERVAL = 'BISON_INVALID' scope = pfile; --error
alter system set TIMED_STATS = 'BISON_INVALID' scope = pfile; --error
alter system set STATS_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set DBWR_PROCESSES = 'BISON_INVALID' scope = pfile; --error
alter system set SQL_STAT = 'BISON_INVALID' scope = pfile; --error
alter system set INSTANCE_NAME = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ALARM_LOG_DIR = '/bison/nonexistent' scope = pfile; --error
alter system set REPL_ADDR = '127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1' scope = pfile; --error
alter system set REPL_PORT = '1' scope = pfile; --error
alter system set REPL_TRUST_HOST = '127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1' scope = pfile; --error
alter system set REPL_AUTH = 'BISON_INVALID' scope = pfile; --error
alter system set REPL_SCRAM_AUTH = 'BISON_INVALID' scope = pfile; --error
alter system set _REPL_MAX_PKG_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set FILE_OPTIONS = 'BISON_INVALID' scope = pfile; --error
alter system set BUILD_DATAFILE_PARALLEL = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_TEMP_SPACE_BITMAP = 'BISON_INVALID' scope = pfile; --error
alter system set BUILD_DATAFILE_PREALLOCATE = 'BISON_INVALID' scope = pfile; --error
alter system set _ENCRYPTION_ALG = 'BISON_INVALID' scope = pfile; --error
alter system set _SYS_PASSWORD = 'x' scope = pfile; --error
alter system set TC_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set AUDIT_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set AUDIT_TRAIL_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set AUDIT_SYSLOG_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set LOG_HOME = '/bison/nonexistent' scope = pfile; --error
alter system set _LOG_BACKUP_FILE_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set _AUDIT_BACKUP_FILE_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set _LOG_MAX_FILE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _AUDIT_MAX_FILE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _LOG_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set _LOG_FILE_PERMISSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set _LOG_PATH_PERMISSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set UNDO_RESERVE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set UNDO_RETENTION_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set INDEX_DEFER_RECYCLE_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_SEGMENTS = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_ACTIVE_SEGMENTS = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_AUTON_TRANS_SEGMENTS = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_AUTON_BIND_OWN_SEGMENT = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_AUTO_SHRINK = 'BISON_INVALID' scope = pfile; --error
alter system set _UNDO_AUTO_SHRINK_INACTIVE = 'BISON_INVALID' scope = pfile; --error
alter system set UNDO_PREFETCH_PAGE_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set _TX_ROLLBACK_PROC_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set REPL_WAIT_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set COMMIT_ON_DISCONNECT = 'BISON_INVALID' scope = pfile; --error
alter system set _MAX_CONNECT_BY_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set BACKUP_BUFFER_SIZE = '-1' scope = pfile; --error
alter system set RESTORE_ARCH_COMPRESSED = 'BISON_INVALID' scope = pfile; --error
alter system set _INDEX_SCAN_RANGE_CACHE = 'BISON_INVALID' scope = pfile; --error
alter system set _RESTORE_CHECK_VERSION = 'BISON_INVALID' scope = pfile; --error
alter system set RESTOR_ARCH_PREFER_BAK_SET = 'BISON_INVALID' scope = pfile; --error
alter system set NBU_BACKUP_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set _CHECK_SYSDATA_VERSION = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_ARCH_FILES_SIZE = '-1' scope = pfile; --error
alter system set ARCH_LOG_CHECK = 'BISON_INVALID' scope = pfile; --error
alter system set ARCH_FILE_SIZE = '-1' scope = pfile; --error
alter system set ARCH_SIZE = '-1' scope = pfile; --error
alter system set ARCH_TIME = '-1' scope = pfile; --error
alter system set ARCH_CLEAN_UPPER_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set ARCH_CLEAN_LOWER_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set ARCH_CLEAN_IGNORE_BACKUP = 'BISON_INVALID' scope = pfile; --error
alter system set ARCH_CLEAN_IGNORE_STANDBY = 'BISON_INVALID' scope = pfile; --error
alter system set XA_SUSPEND_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set BUILD_KEEP_ALIVE_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set _BACKUP_LOG_PARALLEL = 'BISON_INVALID' scope = pfile; --error
alter system set TCP_VALID_NODE_CHECKING = 'BISON_INVALID' scope = pfile; --error
alter system set TCP_INVITED_NODES = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set TCP_EXCLUDED_NODES = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set LOCK_WAIT_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_RAFT = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_START_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_NODE_ID = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_PEER_IDS = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_LOCAL_ADDR = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_PEER_ADDRS = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_LOG_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_KUDU_DIR = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_PRIORITY_TYPE = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_PRIORITY_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_LAYOUT_INFO = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_PENDING_CMDS_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_SEND_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_RECEIVE_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_MAX_SIZE_PER_MSG = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_ELECTION_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_MEMORY_THRESHOLD = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set RAFT_LOG_ASYNC_BUF_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_FAILOVER_LIB_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set RAFT_TLS_DIR = '../BISON_INVALID' scope = pfile; --error
alter system set RAFT_TOKEN_VERIFY = 'BISON_INVALID' scope = pfile; --error
alter system set LOCAL_KEY = 'BISON_INVALID' scope = both; --error
alter system set BUF_POOL_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set DEFAULT_EXTENTS = 'BISON_INVALID' scope = pfile; --error
alter system set _MAX_VM_FUNC_STACK_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set TEMP_POOL_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set MERGE_SORT_BATCH_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_NESTLOOP_JOIN = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_HASH_JOIN = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_MERGE_JOIN = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_ALLOWED_PACKET = 'BISON_INVALID' scope = pfile; --error
alter system set DB_FILE_NAME_CONVERT = '|' scope = pfile; --error
alter system set LOG_FILE_NAME_CONVERT = '|' scope = pfile; --error
alter system set INTERACTIVE_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set SQL_STAGE_THRESHOLD = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set SSL_CA = '/bison/nonexistent' scope = pfile; --error
alter system set SSL_CERT = '/bison/nonexistent' scope = pfile; --error
alter system set SSL_KEY = '/bison/nonexistent' scope = pfile; --error
alter system set SSL_CRL = '/bison/nonexistent' scope = pfile; --error
alter system set SSL_VERIFY_PEER = 'BISON_INVALID' scope = pfile; --error
alter system set SSL_KEY_PASSWORD = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set SSL_KEY_PASSWORD = '' scope = pfile;
alter system set SSL_CIPHER = 'BISON_INVALID' scope = pfile; --error
alter system set SSL_EXPIRE_ALERT_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set SSL_PERIOD_DETECTION = 'BISON_INVALID' scope = pfile; --error
alter system set LOCAL_TEMPORARY_TABLE_ENABLED = 'BISON_INVALID' scope = pfile; --error
alter system set UPPER_CASE_TABLE_NAMES = 'BISON_INVALID' scope = pfile; --error
alter system set UNAUTH_SESSION_EXPIRE_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_SYSDBA_LOGIN = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_SYS_REMOTE_LOGIN = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_SYSDBA_REMOTE_LOGIN = 'BISON_INVALID' scope = pfile; --error
alter system set RESOURCE_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set _FACTOR_KEY = 'BISON_INVALID' scope = both; --error
alter system set ENABLE_ERR_SUPERPOSED = 'BISON_INVALID' scope = pfile; --error
alter system set EMPTY_STRING_AS_NULL = 'BISON_INVALID' scope = pfile; --error
alter system set ZERO_DIVISOR_ACCEPTED = 'BISON_INVALID' scope = pfile; --error
alter system set STRING_AS_HEX_FOR_BINARY = 'BISON_INVALID' scope = pfile; --error
alter system set DROP_NOLOGGING = 'BISON_INVALID' scope = pfile; --error
alter system set RECYCLEBIN = 'BISON_INVALID' scope = pfile; --error
alter system set HAVE_SSL = 'FALSE' scope = pfile; --error
alter system set _ENCRYPTION_ITERATION = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_TEMP_TABLES = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_IDX_CONFS_NAME_DUPL = 'FALSE' scope = pfile; --error
alter system set ENABLE_IDX_KEY_LEN_CHECK = 'BISON_INVALID' scope = pfile; --error
alter system set CBO = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_COLUMN_COUNT = 'BISON_INVALID' scope = pfile; --error
alter system set STATISTICS_SAMPLE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _SQL_CURSORS_EACH_SESSION = 'BISON_INVALID' scope = pfile; --error
alter system set _RESERVED_SQL_CURSORS = 'BISON_INVALID' scope = pfile; --error
alter system set COVERAGE_ENABLE = 'BISON_INVALID' scope = pfile; --error
alter system set TYPE_MAP_FILE = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set INI_TRANS = 'BISON_INVALID' scope = pfile; --error
alter system set INT_SYSINDEX_TRANS = 'BISON_INVALID' scope = pfile; --error
alter system set CR_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set ROW_FORMAT = 'BISON_INVALID' scope = pfile; --error
alter system set _LNS_WAIT_TIME = 'BISON_INVALID' scope = pfile; --error
alter system set _PRIVATE_KEY_LOCKS = 'BISON_INVALID' scope = pfile; --error
alter system set _PRIVATE_ROW_LOCKS = 'BISON_INVALID' scope = pfile; --error
alter system set DDL_LOCK_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_REMOTE_PARAMS = 'BISON_INVALID' scope = pfile; --error
alter system set DB_TIMEZONE = 'BISON_INVALID' scope = pfile; --error
alter system set TABLESPACE_USAGE_ALARM_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set UNDO_USAGE_ALARM_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set TXN_UNDO_USAGE_ALARM_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set _SYSTIME_INCREASE_THREASHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set BLOCK_REPAIR_ENABLE = 'BISON_INVALID' scope = pfile; --error
alter system set BLOCK_REPAIR_TIMEOUT = 'BISON_INVALID' scope = pfile; --error
alter system set UDS_FILE_PATH = '/' scope = pfile; --error
alter system set UDS_FILE_PERMISSIONS = 'BISON_INVALID' scope = pfile; --error
alter system set STATS_COST_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set STATS_COST_DELAY = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_SAMPLE_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set MASTER_SLAVE_DIFFTIME = 'BISON_INVALID' scope = pfile; --error
alter system set WORKER_THREADS_SHRINK_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set XA_FORMAT_ID = '247' scope = pfile; --error
alter system set DEGRADE_SEARCH_MAP = 'BISON_INVALID' scope = pfile; --error
alter system set CPU_NODE_BIND = '0' scope = pfile; --error
alter system set RESOURCE_PLAN = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set STATS_MAX_BUCKET_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set PARALLEL_POLICY = 'BISON_INVALID' scope = pfile; --error
alter system set DELAY_CLEANOUT = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_ACCESS_DC = 'BISON_INVALID' scope = pfile; --error
alter system set _VIEW_ACCESS_DC = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_PERMISSIVE_UNICODE = 'BISON_INVALID' scope = pfile; --error
alter system set NODE_LOCK_STATUS = 'BISON_INVALID' scope = pfile; --error
alter system set UNDO_TABLESPACE = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set LOB_REUSE_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_LOCAL_INFILE = 'BISON_INVALID' scope = pfile; --error
alter system set ARRAY_STORAGE_OPTIMIZATION = 'BISON_INVALID' scope = pfile; --error
alter system set _MAX_JSON_DYNAMIC_BUFFER_SIZE = '-1' scope = pfile; --error
alter system set SLOWSQL_STATS_ENABLE = 'BISON_INVALID' scope = pfile; --error
alter system set STATS_PARALL_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set STATS_ENABLE_PARALL = 'BISON_INVALID' scope = pfile; --error
alter system set _OUTER_JOIN_OPTIMIZATION = 'BISON_INVALID' scope = pfile; --error
alter system set CBO_INDEX_CACHING = 'BISON_INVALID' scope = pfile; --error
alter system set CBO_INDEX_COST_ADJ = 'BISON_INVALID' scope = pfile; --error
alter system set CBO_PATH_CACHING = 'BISON_INVALID' scope = pfile; --error
alter system set _WITHAS_SUBQUERY = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_PBL_FILE_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _DISTINCT_PRUNING = 'BISON_INVALID' scope = pfile; --error
alter system set _QUERY_TOPN_THRESHOLD = 'BISON_INVALID' scope = pfile; --error
alter system set _CONNECT_BY_MATERIALIZE = 'BISON_INVALID' scope = pfile; --error
alter system set INIT_LOCK_POOL_PAGES = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIMIZER_AGGR_PLACEMENT = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_OR_EXPANSION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_DISTINCT_ELIMINATION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_PROJECT_LIST_PRUNING = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_PRED_MOVE_AROUND = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_PRED_DELIVERY = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_HASH_MATERIALIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_WINMAGIC_REWRITE = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_PRED_REORDER = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ORDER_BY_PLACEMENT = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_SUBQUERY_ELIMINATION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_JOIN_ELIMINATION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_CONNECT_BY_PLACEMENT = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_GROUP_BY_ELIMINATION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ANY_TRANSFORM = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ALL_TRANSFORM = 'BISON_INVALID' scope = pfile; --error
alter system set _ENABLE_MULTI_INDEX_SCAN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_JOIN_PRED_PUSHDOWN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_FILTER_PUSHDOWN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_INDEX_SCAN_MAX_PARTS = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ORDER_BY_ELIMINATION = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_UNNEST_SET_SUBQUERY = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ENABLE_RIGHT_SEMIJOIN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ENABLE_RIGHT_ANTIJOIN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ENABLE_RIGHT_LEFTJOIN = 'BISON_INVALID' scope = pfile; --error
alter system set SEGMENT_PAGES_HOLD = 'BISON_INVALID' scope = pfile; --error
alter system set HASH_TABLE_PAGES_HOLD = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_SIMPLIFY_EXISTS_SUBQ = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_SUBQUERY_REWRITE = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_SEMI2INNER = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_PRED_PUSHDOWN = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_IN_TRANSFORM = 'BISON_INVALID' scope = pfile; --error
alter system set CTRLLOG_BACKUP_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_FUNC_INDEX_SCAN_ONLY = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_INDEX_COND_PRUNING = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_VM_VIEW_ENABLED = 'BISON_INVALID' scope = pfile; --error
alter system set _OPTIM_ADAPTIVE_FULL_OUTER_JOIN = 'BISON_INVALID' scope = pfile; --error
alter system set _TABLE_COMPRESS_ALGO = 'BISON_INVALID' scope = pfile; --error
alter system set _TABLE_COMPRESS_BUFFER_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set _TABLE_COMPRESS_ENABLE_BUFFER = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_PASSWORD_CIPHER = 'BISON_INVALID' scope = pfile; --error
alter system set CBO_HINT_ENABLED = 'BISON_INVALID' scope = pfile; --error
alter system set PARALLEL_MAX_THREADS = 'BISON_INVALID' scope = pfile; --error
alter system set _OPT_CBO_STAT_SAMPLING_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set _STRICT_CASE_DATATYPE = 'BISON_INVALID' scope = pfile; --error
alter system set MAX_LINK_TABLES = 'BISON_INVALID' scope = pfile; --error
alter system set AUTO_INHERIT_USER = 'BISON_INVALID' scope = pfile; --error
alter system set REPLACE_PASSWORD_VERIFY = 'BISON_INVALID' scope = pfile; --error
alter system set CLUSTER_DATABASE = 'BISON_INVALID' scope = pfile; --error
alter system set INTERCONNECT_ADDR = '127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1' scope = pfile; --error
alter system set INTERCONNECT_PORT = '1' scope = pfile; --error
alter system set INTERCONNECT_TYPE = 'TCP' scope = pfile; --error
alter system set INTERCONNECT_CHANNEL_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set REACTOR_THREAD_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set MES_CPU_INFO = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ENABLE_TX_FREE_PAGE_LIST = 'BISON_INVALID' scope = pfile; --error
alter system set OGRAC_TASK_NUM = 'BISON_INVALID' scope = pfile; --error
alter system set INSTANCE_ID = 'BISON_INVALID' scope = pfile; --error
alter system set MES_POOL_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set OGSTORE_INST_PATH = '/' scope = pfile; --error
alter system set INTERCONNECT_BY_PROFILE = 'BISON_INVALID' scope = pfile; --error
alter system set MES_ELAPSED_SWITCH = 'BISON_INVALID' scope = pfile; --error
alter system set MES_CRC_CHECK_SWITCH = 'BISON_INVALID' scope = pfile; --error
alter system set OGSTORE_MAX_OPEN_FILES = 'BISON_INVALID' scope = pfile; --error
alter system set DSS_LOG_LEVEL = 'BISON_INVALID' scope = pfile; --error
alter system set _ENABLE_RMO_CR = 'BISON_INVALID' scope = pfile; --error
alter system set _REMOTE_ACCESS_LIMIT = 'BISON_INVALID' scope = pfile; --error
alter system set OG_GDV_SQL_SESS_TMOUT = 'BISON_INVALID' scope = pfile; --error
alter system set DTC_CKPT_NOTIFY_TASK_RATIO = 'BISON_INVALID' scope = pfile; --error
alter system set DTC_CLEAN_EDP_TASK_RATIO = 'BISON_INVALID' scope = pfile; --error
alter system set DTC_TXN_INFO_TASK_RATIO = 'BISON_INVALID' scope = pfile; --error
alter system set RCY_NODE_READ_BUF_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set DTC_RCY_PARAL_BUF_LIST_SIZE = 'BISON_INVALID' scope = pfile; --error
alter system set CPU_GROUP_INFO = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set _DEADLOCK_DETECT_INTERVAL = 'BISON_INVALID' scope = pfile; --error
alter system set _AUTO_UNDO_RETENTION = 'BISON_INVALID' scope = pfile; --error
alter system set SHARED_PATH = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ENABLE_DBSTOR = 'BISON_INVALID' scope = pfile; --error
alter system set DBSTOR_DEPLOY_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set DBSTOR_NAMESPACE = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ENABLE_OGRAC_STATS = 'BISON_INVALID' scope = pfile; --error
alter system set PAGE_CLEAN_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_DBSTOR_BATCH_FLUSH = 'BISON_INVALID' scope = pfile; --error
alter system set CLUSTER_ID = 'BISON_INVALID' scope = pfile; --error
alter system set BACKUP_RETRY = 'BISON_INVALID' scope = pfile; --error
alter system set BATCH_FLUSH_CAPACITY = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_HWN_CHANGE = 'BISON_INVALID' scope = pfile; --error
alter system set MES_CHANNEL_UPGRADE_TIME_MS = 'BISON_INVALID' scope = pfile; --error
alter system set MES_CHANNEL_DEGRADE_TIME_MS = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_FDSA = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_BROADCAST_ON_COMMIT = 'BISON_INVALID' scope = pfile; --error
alter system set MES_SSL_SWITCH = 'BISON_INVALID' scope = pfile; --error
alter system set MES_SSL_CRT_KEY_PATH = '/bison/nonexistent' scope = pfile; --error
alter system set MES_SSL_KEY_PWD = 'BISON_VALID' BISON_UNEXPECTED scope = pfile; --error
alter system set ENABLE_CHECK_SECURITY_LOG = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_SYS_CRC_CHECK = 'BISON_INVALID' scope = pfile; --error
alter system set CLUSTER_NO_CMS = 'BISON_INVALID' scope = pfile; --error
alter system set OG_CLUSTER_STRICT_CHECK = 'BISON_INVALID' scope = pfile; --error
alter system set DRC_IN_REFORMER_MODE = 'BISON_INVALID' scope = pfile; --error
alter system set RES_RECYCLE_RATIO = 'BISON_INVALID' scope = pfile; --error
alter system set CREATE_INDEX_PARALLELISM = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_DSS = 'BISON_INVALID' scope = pfile; --error
alter system set USE_BISON_PARSER = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_IP = '999.999.999.999' scope = pfile; --error
alter system set RBP_PORT = '1' scope = pfile; --error
alter system set LOCAL_RBP_HOST = '999.999.999.999' scope = pfile; --error
alter system set USE_RBP = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_FOR_RECOVERY = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_RT_ANALYSIS = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_RT_PARSE_WORKERS = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_RT_PAGE_OWNER_WORKERS = 'BISON_INVALID' scope = pfile; --error
alter system set RBP_ASSEMBLE_MAX_SCAN = 'BISON_INVALID' scope = pfile; --error
alter system set PLAN_DISPLAY_FORMAT = 'BISON_INVALID' scope = pfile; --error
alter system set _SHOW_EXPLAIN_PREDICATE = 'BISON_INVALID' scope = pfile; --error
alter system set ENABLE_QUICK_CKPT = 'BISON_INVALID' scope = pfile; --error

-- Focused Bison ALTER SYSTEM parity and edge cases.
alter system set use_bison_parser = on scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'USE_BISON_PARSER' and value = 'TRUE' and runtime_value = 'TRUE';
alter system set use_bison_parser = 1 scope = memory;
alter system set recyclebin = off scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'RECYCLEBIN' and value = 'FALSE' and runtime_value = 'FALSE';
alter system set recyclebin = 0 scope = memory;
alter system set enable_access_dc = on scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'ENABLE_ACCESS_DC' and value = 'TRUE' and runtime_value = 'TRUE';
alter system set enable_access_dc = 1 scope = memory;
alter system set rbp_for_recovery = off scope = both;
select count(*) boolean_alias_match from dv_parameters
 where name = 'RBP_FOR_RECOVERY' and value = 'FALSE' and runtime_value = 'TRUE';
alter system set rbp_for_recovery = 0 scope = both;
declare
    boolean_value_count integer;
    unexpected_boolean_value exception;
begin
    select count(*) into boolean_value_count
      from dv_parameters
     where (name = 'USE_BISON_PARSER' and value = 'TRUE' and runtime_value = 'TRUE')
        or (name = 'RECYCLEBIN' and value = 'FALSE' and runtime_value = 'FALSE')
        or (name = 'ENABLE_ACCESS_DC' and value = 'TRUE' and runtime_value = 'TRUE')
        or (name = 'RBP_FOR_RECOVERY' and value = 'FALSE' and runtime_value = 'TRUE');
    if boolean_value_count <> 4 then
        raise unexpected_boolean_value;
    end if;
end;
/
alter system set enable_access_dc = off scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'ENABLE_ACCESS_DC' and value = 'FALSE' and runtime_value = 'FALSE';
alter system set enable_access_dc = false scope = memory;
alter system set enable_access_dc = true scope = memory;
alter system set enable_access_dc = 0 scope = memory;
alter system set recyclebin = on scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'RECYCLEBIN' and value = 'TRUE' and runtime_value = 'TRUE';
alter system set recyclebin = 1 scope = memory;
alter system set recyclebin = false scope = memory;
alter system set recyclebin = true;
alter system set recyclebin = 2 scope = memory; --error
alter system set recyclebin = yes scope = memory; --error
alter system set recyclebin = no scope = memory; --error
alter system set rbp_for_recovery = on scope = both;
select count(*) boolean_alias_match from dv_parameters
 where name = 'RBP_FOR_RECOVERY' and value = 'TRUE' and runtime_value = 'TRUE';
alter system set rbp_for_recovery = 1 scope = both;
alter system set rbp_for_recovery = false scope = both;
alter system set rbp_for_recovery = true scope = both;
alter system set rbp_for_recovery = 2 scope = both; --error
alter system set use_bison_parser = off scope = memory;
select count(*) boolean_alias_match from dv_parameters
 where name = 'USE_BISON_PARSER' and value = 'FALSE' and runtime_value = 'FALSE';
alter system set use_bison_parser = true scope = memory;
alter system set use_bison_parser = 0 scope = memory;
declare
    boolean_value_count integer;
    unexpected_boolean_value exception;
begin
    select count(*) into boolean_value_count
      from dv_parameters
     where (name = 'USE_BISON_PARSER' and value = 'FALSE' and runtime_value = 'FALSE')
        or (name = 'RECYCLEBIN' and value = 'TRUE' and runtime_value = 'TRUE')
        or (name = 'ENABLE_ACCESS_DC' and value = 'FALSE' and runtime_value = 'FALSE')
        or (name = 'RBP_FOR_RECOVERY' and value = 'TRUE' and runtime_value = 'TRUE');
    if boolean_value_count <> 4 then
        raise unexpected_boolean_value;
    end if;
end;
/
alter system set use_bison_parser = true scope = memory;
alter system set recyclebin = 'OFF' scope = memory;
select count(*) boolean_quote_match from dv_parameters
 where name = 'RECYCLEBIN' and value = 'FALSE' and runtime_value = 'FALSE';
alter system set recyclebin = true scope = memory;
alter system set enable_access_dc = 'OFF' scope = memory;
select count(*) boolean_quote_match from dv_parameters
 where name = 'ENABLE_ACCESS_DC' and value = 'FALSE' and runtime_value = 'FALSE';
alter system set enable_access_dc = true scope = memory;
alter system set rbp_for_recovery = 'OFF' scope = both;
select count(*) boolean_quote_match from dv_parameters
 where name = 'RBP_FOR_RECOVERY' and value = 'FALSE' and runtime_value = 'TRUE';
alter system set rbp_for_recovery = true scope = both;
alter system set recyclebin = "OFF" scope = memory;
alter system set recyclebin = `1` scope = memory;
alter system set enable_access_dc = "OFF" scope = memory;
alter system set enable_access_dc = `1` scope = memory;
alter system set use_rbp = "FALSE" scope = pfile;
alter system set rbp_for_recovery = "ON" scope = pfile;
alter system set rbp_for_recovery = `TRUE` scope = pfile;
alter system set rbp_rt_analysis = "OFF" scope = pfile;
alter system set rbp_rt_analysis = `0` scope = pfile;
declare
    rbp_quote_count integer;
    unexpected_rbp_quote exception;
begin
    select count(*) into rbp_quote_count
      from dv_parameters
     where (name = 'USE_RBP' and value = 'FALSE')
        or (name = 'RBP_FOR_RECOVERY' and value = 'TRUE')
        or (name = 'RBP_RT_ANALYSIS' and value = 'FALSE');
    if rbp_quote_count <> 3 then
        raise unexpected_rbp_quote;
    end if;
end;
/
alter system set dbstor_deploy_mode = 0 scope = pfile;
select count(*) dbstor_value_match from dv_parameters
 where name = 'DBSTOR_DEPLOY_MODE' and value = '0' and runtime_value = '0';
alter system set dbstor_deploy_mode = 1 scope = both;
select count(*) dbstor_value_match from dv_parameters
 where name = 'DBSTOR_DEPLOY_MODE' and value = '1' and runtime_value = '0';
alter system set dbstor_deploy_mode = 0 scope = both;
alter system set dbstor_deploy_mode = on scope = pfile; --error
alter system set dbstor_deploy_mode = off scope = pfile; --error
alter system set dbstor_deploy_mode = true scope = pfile; --error
alter system set dbstor_deploy_mode = '0' scope = pfile;
alter system set dbstor_deploy_mode = "0" scope = pfile;
alter system set dbstor_deploy_mode = `0` scope = pfile;
alter system set dbstor_deploy_mode = 2 scope = pfile; --error
select count(*) dbstor_value_match from dv_parameters
 where name = 'DBSTOR_DEPLOY_MODE' and value = '0' and runtime_value = '0';
alter system set dbstor_namespace = "foo/*bar*/" scope = both;
select count(*) dbstor_namespace_quote_match from dv_parameters
 where name = 'DBSTOR_NAMESPACE' and value = 'foo/*bar*/';
alter system set dbstor_namespace = '$tenant' scope = both;
select count(*) dbstor_namespace_quote_match from dv_parameters
 where name = 'DBSTOR_NAMESPACE' and value = '$tenant';
ALTER SYSTEM SET DBSTOR_NAMESPACE='a' 'b'; --error
ALTER SYSTEM SET DBSTOR_NAMESPACE='a'' ''b';
select cast(value as varchar(5)) dbstor_namespace_escape_value from dv_parameters
 where name = 'DBSTOR_NAMESPACE' and value = 'a'' ''b';
alter system set backup_buffer_size = 256M scope = memory;
declare
    runtime_value_count integer;
    unexpected_runtime_value exception;
begin
    select count(*) into runtime_value_count
      from dv_parameters
     where name = 'BACKUP_BUFFER_SIZE'
       and runtime_value = '256M';
    if runtime_value_count <> 1 then
        raise unexpected_runtime_value;
    end if;
end;
/
alter system set backup_buffer_size = ' 128M ' scope = memory;
alter system set backup_buffer_size = '12''8M' scope = memory; --error
alter system set backup_buffer_size = E'128M' scope = memory; --error
alter system set backup_buffer_size = $buffer$128M$buffer$ scope = memory; --error
alter system set backup_buffer_size = `128M` scope = memory;
alter system set backup_buffer_size = '128M' scope = memory;
alter system set cpu_node_bind = 0 /* block comment */ 0 scope = memory; --error
alter system set cpu_node_bind = 0 -- line comment
0 scope = memory;
alter system set cpu_node_bind = '0 /* quoted comment */ 0' scope = memory; --error
alter system set cpu_node_bind = 0 scope = memory; --error
alter system set cpu_node_bind = 0 0 scope = memory;
alter system set cpu_node_bind = 0          0 scope = memory;
alter system set cpu_node_bind = '0          0' scope = memory;
alter system set cpu_node_bind = '0
0' scope = memory;
declare
    binary_value_count integer;
    unexpected_binary_value exception;
begin
    select count(*) into binary_value_count
      from dv_parameters
     where (name = 'CBO' and value = 'ON')
        or (name = 'DB_ISOLEVEL' and value = 'RC')
        or (name = 'SQL_COMPAT' and value = 'OGDB')
        or (name = 'CPU_NODE_BIND' and value = '0 0');
    if binary_value_count <> 4 then
        raise unexpected_binary_value;
    end if;
end;
/
alter system set _LOB_MAX_EXEC_SIZE = ' 65534 ' scope = both;
alter system set _REPL_MAX_PKG_SIZE = ' 8M ' scope = both;
declare
    normalized_size_count integer;
    unexpected_size_value exception;
begin
    select count(*) into normalized_size_count
      from dv_parameters
     where (name = '_LOB_MAX_EXEC_SIZE' and value = '65534')
        or (name = '_REPL_MAX_PKG_SIZE' and value = '8M');
    if normalized_size_count <> 2 then
        raise unexpected_size_value;
    end if;
end;
/
alter system set _REPL_MAX_PKG_SIZE = '0' scope = both;
alter system set _REPL_MAX_PKG_SIZE = '0.5M' scope = pfile; --error
alter system set _LOB_MAX_EXEC_SIZE = '8E' scope = pfile; --error
alter system set RAFT_TOKEN_VERIFY = "TRUE" scope = pfile;
alter system set RAFT_TOKEN_VERIFY = `TRUE` scope = pfile;
alter system set RAFT_TOKEN_VERIFY = TRUE scope = pfile;
alter system set RAFT_TOKEN_VERIFY = 'TRUE' scope = pfile;
alter system set COMMIT_MODE = 'IMMEDIATE' scope = pfile;
alter system set COMMIT_MODE = IMMEDIATE scope = pfile;
alter system set AUDIT_TRAIL_MODE = "FILE" scope = pfile;
alter system set AUDIT_TRAIL_MODE = `FILE` scope = pfile;
alter system set AUDIT_TRAIL_MODE = 'FILE' scope = pfile;
alter system set DB_TIMEZONE = "+00:00" scope = pfile;
alter system set DB_TIMEZONE = '+00:00' scope = pfile;
alter system set LSNR_ADDR = ' 127.0.0.1 ' scope = pfile;
alter system set REPL_ADDR = ' 127.0.0.1 ' scope = pfile;
alter system set REPL_TRUST_HOST = ' 127.0.0.1 ' scope = pfile;
alter system set INTERCONNECT_ADDR = ' 127.0.0.1 ' scope = pfile;
alter system set lsnr_port = 1 scope = pfile; --error
alter system set lsnr_port = 1611 scope = pfile;
alter system set slowsql_log_mode = on scope = memory;
alter system set sql_stage_threshold = 5 scope = memory;
alter system set sql_stage_threshold = 10 scope = memory;
alter system set _log_level = 16712568 scope = memory; --error
alter system set _log_level = 7 scope = memory;
alter system set worker_threads = 100 scope = pfile;
alter system set rbp_ip = '0.0.0.0' scope = pfile; --error
alter system set local_rbp_host = '127.0.0.1,127.0.0.2' scope = pfile; --error
alter system set use_rbp = 'invalid' scope = pfile; --error

-- ALTER SESSION SET and ALTER SYSTEM DEBUG share the raw Bison value token.
alter system debug mode _MRP_RES_LOGSIZE = 1G;
select count(*) debug_value_match from dv_debug_parameters
 where name = '_MRP_RES_LOGSIZE' and current_value = '1G';
alter system debug mode _MRP_RES_LOGSIZE = ' 2G ';
select count(*) debug_value_match from dv_debug_parameters
 where name = '_MRP_RES_LOGSIZE' and current_value = '2G';
alter system debug mode _MRP_RES_LOGSIZE = 01G; --error
alter system debug mode _MRP_RES_LOGSIZE = '01G'; --error
alter system debug mode _MRP_RES_LOGSIZE = +1; --error
alter system debug mode _MRP_RES_LOGSIZE = '+1';
select count(*) debug_value_match from dv_debug_parameters
 where name = '_MRP_RES_LOGSIZE' and current_value = '+1';
alter system debug mode _MRP_RES_LOGSIZE = '+1G'; --error
alter system debug mode _MRP_RES_LOGSIZE = 0.5M; --error
alter system debug mode _MRP_RES_LOGSIZE = 64T; --error
alter system debug mode _MRP_RES_LOGSIZE = 0;
select count(*) debug_value_match from dv_debug_parameters
 where name = '_MRP_RES_LOGSIZE' and current_value = '0';

-- ALTER SESSION Bison adapters use the native parameter table and preserve native results.
alter session set commit_wait = "WAIT";
alter session set commit_wait = `NOWAIT`;
alter session set commit_logging = 'IMMEDIATE';
alter session set commit_logging = "IMMEDIATE"; --error
alter session set commit_logging = `IMMEDIATE`; --error
alter session set lock_wait_timeout = 10 /* comment */;
alter session set lock_wait_timeout = '10'; --error
alter session set lock_wait_timeout = 10 extra; --error
alter session set time_zone = '+08:00';
alter session set time_zone = "+08:00"; --error
alter session set _show_explain_predicate = true;
alter session set _show_explain_predicate = 'true'; --error
alter session set shd_socket_timeout = '10'; --error
alter session set _outer_join_optimization = ON;
alter session set _outer_join_optimization = 'ON'; --error
alter session set cbo_index_caching = 10;
alter session set cbo_index_cost_adj = 100;
alter session set _withas_subquery = OPTIMIZER;
alter session set _withas_subquery = 'OPTIMIZER'; --error
alter session set _cursor_sharing = OFF;
alter session set _cursor_sharing = 'OFF'; --error
alter session set plan_display_format = basic, predicate;
alter session set plan_display_format = 'basic, predicate';
alter session set current_schema = SYS;
alter session set current_schema = SYS-SYS; --error
alter session set current_schema = SYS.SYS; --error
alter session set tenant = ROOT-ROOT; --error
alter session set tenant = ROOT.ROOT; --error
alter session set tenant = ''; --error
alter session set nls_date_format = ' YYYY-MM-DD ';
alter session set nls_date_format = "YYYY-MM-DD"; --error

alter system set use_bison_parser = false;
