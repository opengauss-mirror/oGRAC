%{
#include "gramparse.h"
#include "table_parser.h"
#include "expr_parser.h"
#include "ogsql_hint_parser.h"
#include "ogsql_select_parser.h"
#include "ogsql_insert_parser.h"
#include "ogsql_update_parser.h"
#include "ogsql_merge_parser.h"
#include "ogsql_replace_parser.h"
#include "cond_parser.h"
#include "ogsql_json_table.h"
#include "pl_meta_common.h"
#include "ddl_table_attr_parser.h"
#include "ddl_table_parser.h"
#include "ddl_database_parser.h"
#include "ddl_user_parser.h"
#include "cm_interval.h"
#include "ddl_space_parser.h"
#include "ddl_view_parser.h"
#include "ddl_sequence_parser.h"
#include "ddl_column_parser.h"
#include "ddl_constraint_parser.h"
#include "ddl_table_attr_parser.h"
#include "ddl_privilege_parser.h"
#include "ogsql_privilege.h"
#include "pl_ddl_parser.h"
#include "cm_error.h"

/* Location tracking support --- simpler than bison's default */

#define YYLLOC_DEFAULT(Current, Rhs, N) \
    do { \
        if (N) \
            (Current) = (Rhs)[1]; \
        else \
            (Current) = (Rhs)[0]; \
    } while (0)

/*
 * Bison doesn't allocate anything that needs to live across parser calls,
 * so we can easily have it use palloc instead of malloc.  This prevents
 * memory leaks if we error out during parsing.  Note this only works with
 * bison >= 2.0.  However, in bison 1.875 the default is to use alloca()
 * if possible, so there's not really much problem anyhow, at least if
 * you're building with gcc.
 */
#define YYMALLOC(size) core_yyalloc(size, yyscanner)
#define YYFREE(ptr)   core_yyfree(ptr, yyscanner)
#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, &yylloc, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, &yylloc, yyscanner)
#endif

#define parser_yyerror(msg)             \
do {                                    \
    scanner_yyerror(msg, yyscanner);    \
    YYABORT;                            \
} while (0)

#define parser_abort_or_yyerror(msg)    \
do {                                    \
    if (cm_get_error_code() != 0) {     \
        YYABORT;                        \
    }                                   \
    parser_yyerror(msg);                \
} while (0)

#define BISON_MEM_STRDUP(dest, src)                                             \
do {                                                                            \
    size_t len = strlen(src) + 1;                                               \
    if (SECUREC_UNLIKELY(og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_context == NULL)) {    \
        if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,   \
            len, (void **)&dest) != OG_SUCCESS) {                                   \
            parser_yyerror("alloc mem failed ");                                    \
        }                                                                           \
    } else if (pl_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_context,            \
        len, (void **)&dest) != OG_SUCCESS) {                                   \
        parser_yyerror("alloc mem failed ");                                    \
    }                                                                           \
    errno_t ret = memcpy_s(dest, len, src, len - 1);                            \
    knl_securec_check(ret);                                                     \
    dest[len - 1] = '\0';                                                       \
} while (0)

#define parser_errposition(pos)  scanner_errposition(pos, yyscanner)

static digitext_t g_pos_bigint_ceil = { "9223372036854775807",  19 };

typedef enum en_interval_unit_order {
    IUO_YEAR = 0,
    IUO_MONTH,
    IUO_DAY,
    IUO_HOUR,
    IUO_MINUTE,
    IUO_SECOND,
    /* add new value before this */
    IUO_MAX
} interval_unit_order_t;

static void base_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner,
                         const char *msg);
static status_t column_list_to_column_pairs(sql_stmt_t *stmt, galist_t *colname_list, galist_t **pairs);
static status_t make_type_word(core_yyscan_t yyscanner, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc);
static status_t make_type_modifiers(core_yyscan_t yyscanner, galist_t **list, int val, source_location_t loc);
static bool check_in_rows_match(galist_t *rows, uint32 cols, expr_tree_t **expr);
static void fix_type_for_select_node(expr_tree_t *expr, select_type_t type);
static status_t convert_expr_tree_to_galist(sql_stmt_t *stmt, expr_tree_t *expr, galist_t **list);
static status_t attach_pending_subselects_to_query(sql_query_t *query, sql_array_t *pending);
static status_t sql_parse_table_cast_type(sql_stmt_t *stmt, expr_tree_t **expr, char *name, source_location_t loc);
static status_t strGetInt64(const char *str, int64 *value);
static char* ds_unit_to_str(interval_unit_order_t order);
static interval_unit_t get_interval_unit(interval_unit_order_t order);
static interval_unit_t generate_interval_unit(interval_unit_order_t from, interval_unit_order_t to);
static status_t process_alter_index_action(sql_stmt_t *stmt, alter_index_action_t *alter_idx_act, knl_alindex_def_t *def);
static text_t *pl_prepend_body_start(core_yyscan_t yyscanner, text_t *body, int start_offset, source_location_t loc);
static status_t pl_compile_stored_body_source(core_yyscan_t yyscanner, text_t *body, int start_offset,
    source_location_t loc, bool32 has_program_body);

/* Please note that the following line will be replaced with the contents of given file name even if with starting with a comment */
/*$$include "gram-dialect-prologue.y.h"*/
%}

%define api.pure
%expect 0
%name-prefix "base_yy"
%locations

%parse-param {core_yyscan_t yyscanner}
%lex-param   {core_yyscan_t yyscanner}

%union
{
    core_YYSTYPE        core_yystype;
    /* these fields must match core_YYSTYPE: */
    int                 ival;
    char                *str;
    bool                boolean;
    int64               ival64;
    const char          *keyword;
    void                *res;
    galist_t            *list;
    expr_tree_t         *expr;
    sql_table_t         *table;
    case_pair_t         *case_pair;
    column_parse_info   *column;
    sort_item_t         *sortby;
    winsort_args_t      *winsort_args;
    windowing_args_t    *windowing_args;
    query_column_t      *query_column;
    windowing_border_t  *windowing_border;
    insert_all_t        *insert_all;
    sql_update_t        *update_ctx;
    column_value_pair_t *pair;
    del_object_t        *del_obj;
    cond_node_t         *cond_node;
    cond_tree_t         *cond_tree;
    type_word_t         *type_word;
    timezone_type_t     timezone_type;
    trim_list_t         *trim_list;
    extract_list_t      *extract_list;
    sql_join_node_t     *join_node;
    sql_join_type_t     join_type;
    rs_column_t         *rs_column;
    json_func_att_id_t  json_func_att_id;
    json_func_attr_t    json_func_attr;
    interval_info_t     interval_info;
    json_array_returning_attr returning_attr;
    limit_item_t        *limit_item;
    sql_withas_factor_t *withas_factor;
    expr_with_alias     *expr_alias;
    pivot_items_t       *pivot_item;
    expr_with_as_expr   *expr_alias_as;
    swcb_clause         *swcb;
    for_update_clause   *for_update;
    rowmark_type_t      rowmark_type;
    merge_when_clause   *merge_when;
    name_with_owner     *name_owner;
    createdb_opt        *db_opt;
    createdb_user_token *db_user_token;
    createts_opt        *ts_opt;
    knl_device_def_t    *dev_def;
    createdb_instance_node *inode;
    user_option_t       *user_opt;
    alter_index_action_t   *alter_idx_act;
    knl_index_col_def_t *index_col;
    createidx_opt       *idx_opt;
    index_partition_parse_info *part_parse_info;
    index_partition_opt *idx_part;
    knl_storage_def_t   *storage_def;
    storage_opt_t       *storage_opt;
    knl_part_def_t      *part_def;
    createseq_opt       *seq_opt;
    ctrlfile_opt        *ctrlfile_opt;
    backup_opt          *backup_opt;
    profile_limit_item_t *profile_limit_item;
    profile_limit_value_t *profile_limit_value;
    table_attr_t        *table_attr;
    column_attr_t       *column_attr;
    constraint_state    *cons_state;
    parse_constraint_t  *parse_cons;
    parse_column_t      *parse_col;
    parse_table_element_t *table_element;
    text_t              *text;
    alterts_opt         *alts_opt;
}

%type <res>    stmtblock stmtmulti InsertStmt SelectStmt simple_select DeleteStmt select_with_parens select_no_parens
               UpdateStmt select_clause MergeStmt DropStmt merge_insert merge_when_insert_clause ReplaceStmt TruncateStmt
               FlashStmt CommentStmt AnalyzeStmt CreatedbStmt CreateUserStmt CreateRoleStmt CreateTenantStmt AlterUserStmt AlterTenantStmt AlterIndexStmt CreateTablespaceStmt
               CreateIndexStmt CreateIndexClusterStmt CreateSequenceStmt CreateViewStmt CreateSynonymStmt CreateProfileStmt CreateDirectoryStmt
               CreateLibraryStmt CreateCtrlfileStmt CreateTableStmt opt_as_select CreateProcedureStmt CreateFunctionStmt
               CreatePackageStmt CreateTypeStmt CreateTriggerStmt compileFunctionSource compileProcedureSource compileStoredBodySource
               GrantStmt RevokeStmt PurgeStmt AlterTableStmt AlterDatabaseStmt AlterSequenceStmt AlterTablespaceStmt
               AlterProfileStmt AlterTriggerStmt AlterFunctionStmt ddl_passthrough_tail index_cluster_item TransactionStmt
               RecoverStmt OgracStmt ShutdownStmt BuildStmt RepairStmt CheckPointStmt ValidateStmt SyncPointStmt
               LockTableStmt AlterSystemStmt AlterSessionStmt XID LTID InternalReparseStmt
%type <list>   ctext_expr_list ctext_row indirection opt_indirection values_clause insert_column_list when_expr_clause_list
               when_cond_clause_list func_name within_group_clause sort_clause opt_sort_clause sortby_list opt_partition_clause
               expr_list target_list opt_target_list opt_type_modifiers opt_float opt_array_bounds createseq_opts opt_createseq_opts alterseq_opts opt_alterseq_opts
               profile_limit_list ctrlfile_opts opt_ctrlfile_opts ctrlfile_file_list ctrlfile_files OptTableElementList column_attrs
               opt_column_attrs table_attrs opt_table_attrs column_name_list opt_backup_opts backup_opts
               all_insert_into_list set_clause_list set_clause multiple_set_clause return_clause delete_target_list
               expr_list_with_select_rows json_column_list siblings_clause with_clause cte_list pivot_in_list pivot_clause_list
               select_pivot_clause unpivot_in_list expr_or_implicit_row_list cube_clause rollup_clause
               group_sets_item group_sets_list grouping_sets_clause group_by_cartesian_item group_by_list group_clause any_name_list
               locked_rels_list columnref_list opt_siblings_clause replace_set_clause_list index_cluster_list attrs
%type <expr>   ctext_expr a_expr c_expr AexprConst indirection_el columnref case_default case_expr func_application func_expr
               func_arg_expr func_arg_list expr_elem_list func_expr_common_subexpr substr_list multi_expr_list
               expr_or_implicit_row json_array_args json_array_arg_item json_object_args json_object_arg_item
%type <table>  insert_target qualified_name relation_expr table_func json_table
%type <case_pair> when_expr_clause when_cond_clause
%type <column> insert_column_item
%type <table_attr> table_attr
%type <column_attr> column_attr_cons column_attr
%type <parse_col> columnDef
%type <parse_cons> TableConstraint ConstraintElem
%type <table_element> TableElement
%type <boolean> opt_ignore opt_varying opt_charbyte sub_type format_json json_on_error_or_null jsonb_table opt_found_rows
                opt_distinct unpivot_include_or_exclude_nulls opt_nocycle opt_all opt_all_distinct opt_if_exists opt_drop_behavior
                opt_cascade opt_purge opt_temporary opt_public opt_force partition_or_subpartition opt_archivelog
                opt_reuse opt_all_in_memory opt_encrypted ignore_nulls opt_orajoin on_or_off opt_undo opt_or_replace opt_signed
                opt_revoke_cascade opt_with_read_only alter_trigger_enable opt_package_body opt_type_body opt_type_force
%type <winsort_args> over_clause window_specification
%type <windowing_args> opt_frame_clause frame_extent
%type <query_column> target_el
%type <windowing_border> frame_bound
%type <insert_all> all_insert_into
%type <update_ctx> upsert_clause merge_when_update_clause merge_update
%type <pair> single_set_clause set_target_list
%type <del_obj> delete_target
%type <cond_node> cond_node
%type <cond_tree> where_clause cond_tree_expr having_clause opt_merge_where_condition
%type <type_word> GenericType Typename SimpleTypename Numeric NoSignedInteger Character CharacterWithLength CharacterWithoutLength
                  ConstDatetime ConstInterval JsonType SignedInteger func_type
%type <type_word> opt_column_type
%type <timezone_type> opt_timezone
%type <trim_list> trim_list
%type <extract_list> extract_list
%type <expr> expr_with_select expr_list_with_select expr_list_with_select_row implicit_row opt_escape expr_list_with_paren
             func_expr_windowless opt_column_on_update
%type <join_node> using_clause from_list table_ref joined_table from_clause
%type <join_type> join_type
%type <rs_column> json_column
%type <json_func_att_id> format_json_attr json_on_null json_array_wrapper json_on_error json_on_empty json_on_empty_null_or_error
%type <json_func_attr> json_attr_all
%type <returning_attr> json_returning
%type <withas_factor> common_table_expr
%type <expr_alias> pivot_in_item_list pivot_in_item pivot_in_list_element
%type <pivot_item> pivot_clause
%type <expr_alias_as> unpivot_in_list_element
%type <swcb> start_with_clause
%type <for_update> for_locking_clause
%type <rowmark_type> opt_nowait_or_skip
%type <merge_when> merge_when_list
%type <name_owner> any_name on_list
%type <db_user_token> createdb_user_name
%type <db_opt> createdb_user_opt createdb_controlfile_opt createdb_charset_opt instance_node_opt createdb_instance_opt
               createdb_nologging_opt createdb_system_opt createdb_sysaux_opt createdb_default_opt createdb_maxinstance_opt
               createdb_opt createdb_archivelog_opt createdb_compatibility_opt
%type <backup_opt> backup_opt
%type <ctrlfile_opt> ctrlfile_opt
%type <list> files logfiles instance_node_opts instance_nodes createdb_opts opt_createdb_opts datafiles opt_user_options user_option_list alter_user_options
             tablespace_name_list createts_opts opt_createts_opts index_column_list createidx_opts opt_partition_index_def
             partition_index_list opt_part_options part_options subpartition_index_list opt_subpartition_index_def opt_createidx_opts
             opt_view_column_list view_column_list table_column_list opt_constraint_states constraint_states
             opt_lob_store_params lob_store_params range_partition_list range_partition_boundary_list range_subpartition_list
             list_subpartition_list hash_subpartition_list list_partition_list listValueList hash_partition_list
             opt_partition_store_in_clause tablespaceList opt_interval_tablespaceList func_args_with_defaults_list
             func_args_with_defaults proc_args grantee_list sys_priv_list obj_priv_list revokee_list
%type <ival64> num_size opt_blocksize next_size max_size extents_clause BigintOnly SignedIconst opt_punch_size opt_segments
%type <dev_def> logfile datafile ctrlfile_file
%type <inode> instance_node
%type <interval_info> interval_type
%type <str> profile_name tablespace_name user_name role_name tenant_name opt_default_tablespace opt_alter_user_replace common_json_func_name
            json_set_func_name opt_subpart_tablespace_option opt_seg_name tablespace field_terminate opt_delimited
%type <user_opt> user_option alter_user_option
%type <ts_opt> createts_opt
%type <alts_opt> alterts_opt
%type <boolean> opt_unique opt_if_not_exists csf_or_asf opt_with_grant opt_with_admin opt_alter_ts_db
%type <ival> profile_parameter
%type <profile_limit_item> profile_limit_item
%type <profile_limit_value> profile_limit_value
%type <index_col> index_column table_column
%type <idx_opt> createidx_opt
%type <part_parse_info> partition_index_item
%type <idx_part> part_option
%type <storage_def> storage_opts
%type <storage_opt> storage_opt
%type <part_def> subpartition_index_item
%type <seq_opt> createseq_opt alterseq_opt
%type <cons_state> constraint_state
%type <res> lob_store_param table_partitioning_clause range_partitioning_clause list_partitioning_clause hash_partitioning_clause
            range_partition_item opt_subpartition_clause range_subpartition_item list_subpartition_item hash_subpartition_item
            list_partition_item hash_partition_item opt_interval_partition_clause subpartitioning_clause opt_subpartitions_num
            subpartitions_num partitions_num external_table func_arg_with_default func_arg
%type <keyword> unreserved_keyword
%type <keyword> col_name_keyword reserved_keyword
%type <str> ColId type_function_name alias_without_as param_name hint_string character character_national charset_collate_name opt_purge_partition
            opt_separator substr_func extract_arg alias_clause json_table_column_error ColLabel UserId database_name plain_database_name user_password
            debug_mode_value altsession_set_key altsession_set_value alter_param_value

%type <ival> opt_asc_desc opt_nulls_order opt_ckpt_type opt_charset opt_collate opt_wait opt_wait_time opt_truncate_options truncate_option truncate_options
             year_month_unit day_hour_minute_unit opt_year_month_unit row_or_page opt_compress_for opt_drop_tbsp no_arg_func_name_id delete_or_perserve
             opt_foreign_action partition_type grant_objtype sys_priv_spec obj_priv_spec user_priv_spec
             directory_priv_spec arg_class opt_compress_level compress_algo lock_mode opt_set_scope opt_arch_set_type create_table_prefix
%type <sortby>  sortby
%type <limit_item> opt_limit limit_clause offset_clause select_limit
%type <alter_idx_act> alter_index_action
%type <text> subprogram_body pl_as_is_body pl_type_body pl_trigger_body opt_dump_to_file

%token <str>    IDENT FCONST SCONST XCONST Op CmpOp COMMENTSTRING SET_USER_IDENT SET_IDENT UNDERSCORE_CHARSET FCONST_F FCONST_D
                OPER_CAT OPER_LSHIFT OPER_RSHIFT
%token <ival>   ICONST PARAM

%token            LEX_ERROR_TOKEN
%token            TYPECAST ORA_JOINOP DOT_DOT COLON_EQUALS PARA_EQUALS SET_IDENT_SESSION SET_IDENT_GLOBAL NULLS_FIRST NULLS_LAST
%token <str>      SIZE_B SIZE_KB SIZE_MB SIZE_GB SIZE_TB SIZE_PB SIZE_EB
%token            DIALECT_A_FORMAT_SQL
%token            DIALECT_B_FORMAT_SQL
%token            DIALECT_C_FORMAT_SQL

%token <keyword> ABORT_P ABSENT ABSOLUTE_P ACCESS ACCOUNT ACTION ADD_P ADMIN ADMINISTER AFTER
    AGGREGATE ALGORITHM ALL ALSO ALTER ALWAYS ANALYSE ANALYZE AND ANY APP APPEND APPENDONLY APPLY ARCHIVE_P ARCHIVE_SET ARCHIVELOG ARRAY AS ASC ASF ASN ASOF_P
        ASSERTION ASSIGNMENT ASYMMETRIC AT ATTRIBUTE AUDIT AUTHID AUTHORIZATION AUTOEXTEND AUTOMAPPED AUTOOFFLINE AUTOPURGE AUTO_INCREMENT AUTOALLOCATE

    BACKUP_P BACKUPSET BACKWARD BADBLOCK BARRIER BEFORE BEGIN_NON_ANOYBLOCK BEGIN_P BETWEEN BIGINT BINARY BINARY_BIGINT BINARY_DOUBLE BINARY_DOUBLE_INF BINARY_DOUBLE_NAN BINARY_FLOAT BINARY_INTEGER BIT BLANKS
    BLOB_P BLOCKCHAIN BLOCKRECOVER OGRAC RECOVER BOLCKSIZE BODY_P BOGUS BOOLEAN_P BOTH BPCHAR BUCKETCNT BUCKETS BUFFER_P BUILD BY BYTE_P BYTEAWITHOUTORDER BYTEAWITHOUTORDERWITHEQUAL

    CACHE CALL CALLED CANCEL CANCELABLE CASCADE CASCADED CASE CAST CATALOG_P CATALOG_NAME CHAIN CHANGE CHAR_P
    CHARACTER CHARACTERISTICS CHARACTERSET CHARSET CHECK CHECKPOINT CLASS CLASS_ORIGIN CLEAN CLIENT CLIENT_MASTER_KEY CLIENT_MASTER_KEYS CLOB CLOSE
    CLUSTER_P CLUSTERED COALESCE COLLATE COLLATION COLUMN COLUMN_ENCRYPTION_KEY COLUMN_ENCRYPTION_KEYS COLUMN_NAME COLUMNS COMMENT COMMENTS COMMIT
    COMMITTED COMPACT COMPATIBLE_ILLEGAL_CHARS COMPILE COMPLETE COMPLETION COMPRESS COMPRESSED COMPUTE CONCURRENTLY CONDITION CONDITIONAL CONFIGURATION CONFIG CONNECTION CONSISTENT CONSTANT CONSTRAINT CONSTRAINT_CATALOG CONSTRAINT_NAME CONSTRAINT_SCHEMA CONSTRAINTS
    CONTENT_P CONTENTS CONTINUE_P CONTROLFILE CONTVIEW CONVERSION_P CONVERT_P CONNECT COORDINATOR COORDINATORS COPY COPYCTRL COST CREATE CRMODE
    CROSS CSF CSN CSV CTRLFILE CUBE CUMULATIVE CURRENT_P
    COUNT CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA
    CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR CURSOR_NAME CYCLE
    SHRINK USE_P

    DATA_P DB_P DATABASE DATAFILE DATAFILES DATANODE DATANODES DATATYPE_CL DATE_P DATE_FORMAT_P DAY_P DAY_HOUR_P DAY_MINUTE_P DAY_SECOND_P DBA_RECYCLEBIN DBCOMPATIBILITY_P DEALLOCATE DEC DECIMAL_P DECLARE DECODE DEFAULT DEFAULTS
    DEFERRABLE DEFERRED DEFINER DELETE_P DELIMITED DELIMITER DELIMITERS DELTA DELTAMERGE DENSE_RANK DESC DETERMINISTIC
/* PGXC_BEGIN */
    DEBUG DIAGNOSTICS DICTIONARY DIRECT DIRECT_LOAD DIRECTORY DISABLE_P DISCARD DISTINCT DISTRIBUTE DISTRIBUTION DO DOCUMENT_P DOMAIN_P DOUBLE_P
/* PGXC_END */
    DROP DUPLICATE DISCONNECT DUMP DUMPFILE

    EACH ELASTIC ELSE EMPTY ENABLE_P ENCLOSED ENCODING ENCRYPTED ENCRYPTED_VALUE ENCRYPTION ENCRYPTION_TYPE END_P ENDS ENTRY ENFORCED ENUM_P ERROR_P ERRORS ESCAPE EOL ESCAPING ESTIMATE EXEMPT EVENT EVENTS EVERY EXCEPT EXCHANGE
    EXCLUDE EXCLUDED EXCLUDING EXCLUSIVE EXECUTE EXISTS EXPIRE EXPIRED_P EXPLAIN
    EXTENSION EXTENT EXTENTS EXTERNAL EXTRACT ESCAPED

    FALSE_P FAILED_LOGIN_ATTEMPTS_P FAMILY FAST FENCED FETCH FIELDS FILEHEADER_P FILEID FILENAME FILERECOVER FILL_MISSING_FIELDS FINISH FILLER FILTER FIRST_P FIXED_P FLASHBACK FLUSH FLUSHPAGE FLOAT_P FOLLOWING FOLLOWS_P FOR FORCE FOREIGN FORMAT FORMATTER FORWARD
    FEATURES // DB4AI
    FREEZE FROM FULL FUNCTION FUNCTIONS

    GENERATED GET GLOBAL GRANT GRANTED GREATEST GROUP_P GROUP_CONCAT GROUPING_P GROUPPARENT

    HANDLER HASH HAVING HBA HDFSDIRECTORY HEADER_P HOLD HOUR_P HOUR_MINUTE_P HOUR_SECOND_P

    IDENTIFIED IDENTITY_P IF_P IGNORE IGNORE_EXTRA_DATA ILIKE IMMEDIATE IMMUTABLE IMPLICIT_P IN_P INCLUDE IMCSTORED
    INCLUDING INCREMENT INCREMENTAL INDEX_P INDEXES INDEXCLUSTER INFILE INFINITE_P INHERIT INHERITS INIT INITIAL_P INITIALLY INITRANS INLINE_P

    INNER_P INOUT_P INPUT_P INSENSITIVE INSERT INSTANCE INSTEAD INT_P INTEGER INTERNAL
    INTERACTIVE INTERSECT_P INTERVAL INTO INVISIBLE INVOKER IP IS ISNULL ISOLATION

    JOIN JSON JSON_ARRAY JSON_EXISTS JSON_MERGEPATCH JSON_OBJECT JSON_QUERY JSON_SET JSON_VALUE JSON_TABLE_P JSONB JSONB_EXISTS JSONB_MERGEPATCH JSONB_QUERY JSONB_SET JSONB_VALUE JSONB_TABLE_P

    KEEP KEY KILL KEY_PATH KEY_STORE

    LABEL LANGUAGE LARGE_P LAST_P LATERAL_P LC_COLLATE_P LC_CTYPE_P LEADING LEAKPROOF LIBRARY LINES LINK
    LEAST LESS LEFT LEVEL LFN LIKE LIMIT LIST LISTEN LNNVL LOAD LOADER_P LOB LSNR_ADDR LOCAL LOCALTIME LOCALTIMESTAMP
    LOCATION LOCK_P LOCKED LOG_P LOGFILE LOGGING LOGIN_ANY LOGIN_FAILURE LOGIN_SUCCESS LOGOUT LZ4 LOOP
    MAPPING MANAGE MASKING MASTER MATCH MATERIALIZED MATCHED MAXEXTENTS MAXINSTANCES MAXSIZE MAXTRANS MAXVALUE MERGE MESSAGE_TEXT METHOD MINUS_P MINUTE_P MINUTE_SECOND_P MINVALUE MINEXTENTS MODE
    MODEL MODIFY_P MONTH_P MOVE MOVEMENT MYSQL_ERRNO
    // DB4AI
    NAME_P NAMES NAN_P NATIONAL NATURAL NCHAR NEWLINE NEXT NO NOARCHIVELOG NOCACHE NOCOMPRESS NOCYCLE NODE NOLOGGING NOMAXVALUE NOMINVALUE NONE NOORDER NORELY
    NOT NOTHING NOTIFY NOTNULL NOVALIDATE NOWAIT NTH_VALUE_P NULL_P NULLCOLS NULLIF NULLS_P NUMBER_P NUMERIC NUMSTR NVARCHAR NVARCHAR2 NVL

    OBJECT_P OF_P OFF OFFLINE OFFSET OIDS ON ONLINE ONLY OPERATIONS OPERATOR OPTIMIZATION OPTINFO_LOG OPTION OPTIONALLY OPTIONS OR
    ORDER OUT_P OUTER_P OVER OVERLAPS OVERLAY OWNED OWNER ORDINALITY ORGANIZATION OUTFILE

    PACKAGE PACKAGES PAGE PARALLEL PARALLELISM PARALLEL_ENABLE PARAMETERS PARSER PARTIAL PARTITION PARTITIONS PASSING PASSWORD 
    PASSWORD_GRACE_TIME_P PASSWORD_LIFE_TIME_P PASSWORD_LOCK_TIME_P PASSWORD_MIN_LEN_P PASSWORD_REUSE_MAX_P PASSWORD_REUSE_TIME_P PATH PCTFREE PBL PER_P PERCENT PERFORMANCE PERM PERMANENT PLACING PLAN PLANS POLICY POSITION
    PIPELINED PIVOT
/* PGXC_BEGIN */
    POOL PRECEDING PRECISION
/* PGXC_END */
    PREDICT  // DB4AI
/* PGXC_BEGIN */
    PREFERRED PREFIX PRESERVE PREPARE PREPARED PRIMARY
/* PGXC_END */
    PRECEDES_P PRIVATE PRIOR PRIORER PRIVILEGES PRIVILEGE PROCEDURAL PROCEDURE PROCESS PROFILE PUBLIC PUBLICATION PUBLISH PURGE PUNCH

    QUERY QUOTE

    RANDOMIZED RANGE RATIO RAW READ REAL REASSIGN REBUILD RECHECK RECORDS RECURSIVE REDACTION RECYCLE RECYCLEBIN REDISANYVALUE REF REFERENCES REFRESH RELOAD REGEXP REGEXP_LIKE REINDEX REJECT_P
    RELATIVE_P RELEASE RELOPTIONS RELY REMOTE_P REMOVE RENAME REPAIR REPAIR_COPYCTRL REPAIR_PAGE REPEAT REPEATABLE REPLACE REPLICA REPLICATION_P REPORT
    RESET REWRITE RESIZE RESOURCE RESPECT_P RESTART RESTRICT RESTORE RETURN RETURNED_SQLSTATE RETURNING RETURNS REUSE REVERSE REVOKE RIGHT ROLE ROLES ROLLBACK ROLLUP ROTATE
    ROTATION ROW ROW_COUNT ROWID ROWNUM ROWS ROWSCN SHAREDPOOL ROWTYPE_P RULE

    SAMPLE SWITCH SAVEPOINT SCHEDULE SCHEMA SCHEMA_NAME SCN SCROLL SEARCH SECOND_P SECTION SECURITY SEGMENTS SELECT SEPARATOR_P SEQUENCE SEQUENCES SHARE_MEMORY
    SERIALIZABLE SERVER_P SESSION SESSION_USER SESSIONS_PER_USER_P SET SETS SETOF SHARE SHIPPABLE SHOW SCOPE SHUTDOWN SIBLINGS SIGNED STANDBY
    SIMILAR SIMPLE SIZE SKIP SLAVE SLICE SMALLDATETIME SMALLDATETIME_FORMAT_P SMALLINT SQLPOOL SNAPSHOT SOME SOURCE_P SPACE_P SPECIFICATION SPILL SPLIT STABLE STACKED_P STANDALONE_P START STARTS STARTWITH
    STATEMENT STATEMENT_ID STATISTICS STDIN STDOUT STOP STORAGE STORE_P STORED STRATIFY STREAM STRICT_P STRIP_P SUBCLASS_ORIGIN SUBPARTITION SUBPARTITIONS SUBSCRIPTION SUBSTR SUBSTRING
    SYMMETRIC SYNCPOINT SYNONYM SYSBACKUP_P SYSDBA_P SYSDATE SYSID SYSOPER_P SYSTEM_P SYS_REFCURSOR SYSAUX STARTING SQL_P

    SQL_CALC_FOUND_ROWS

    TABLE_P TABLE_NAME TABLES TABLESAMPLE TABLESPACE TABLESPACES TAG TARGET TEMP TEMPFILE TEMPLATE TEMPORARY TENANT TERMINATED TEXT_P THAN THEN THRESHOLD TIME TIME_FORMAT_P TIES TIMECAPSULE TIMESTAMP TIMESTAMP_FORMAT_P TIMESTAMPDIFF TIMEOUT TIMEZONE_HOUR_P TIMEZONE_MINUTE_P TINYINT
    TO TRAILING TRANSACTION TRANSFORM TREAT TRIGGER TRIGGERS TRIM TRUE_P
    TRUNCATE TRUSTED TSFIELD TSTAG TSTIME TYPE_P TYPES_P

    UNCONDITIONAL UNBOUNDED UNCOMMITTED UNENCRYPTED UNION UNIQUE UNKNOWN UNLIMITED UNLISTEN UNLOCK UNLOGGED UNPIVOT UNSIGNED UNIMCSTORED
    UNTIL UNUSABLE UPDATE USEEOF USER USING

    VACUUM VALID VALIDATE VALIDATION VALIDATOR VALUE_P VALUES VARCHAR VARCHAR2 VARIABLES VARIADIC VARRAY VARYING VCGROUP
    VERBOSE VERIFY VERSION_P VIEW VISIBLE VOLATILE

    WAIT WARNINGS WEAK WHEN WHERE WHILE_P WHITESPACE_P WINDOW WITH WITHIN WITHOUT WORK WORKLOAD WRAPPER WRITE

    XML_P XMLATTRIBUTES XMLCONCAT XMLELEMENT XMLEXISTS XMLFOREST XMLPARSE
    XMLPI XMLROOT XMLSERIALIZE

    YEAR_P YEAR_MONTH_P YES_P

    ZLIB ZSTD ZONE

%token <keyword> CONSTRUCTOR FINAL MAP MEMBER MEMORY RESULT SELF STATIC_P UNDER UNDO

/*
 * Multiword tokens for JSON functions - ERROR ON ERROR, ERROR ON EMPTY, NULL ON ERROR, etc.
 * These are created in base_yylex to avoid shift/reduce conflicts
 */
%token <keyword> ERROR_ON_EMPTY ERROR_ON_ERROR_P
%token <keyword> NULL_ON_ERROR_P NULL_ON_EMPTY
%token <keyword> EMPTY_ON_EMPTY EMPTY_ON_ERROR_P
%token <keyword> EMPTY_ARRAY_ON_EMPTY EMPTY_ARRAY_ON_ERROR_P
%token <keyword> EMPTY_OBJECT_P_ON_EMPTY EMPTY_OBJECT_P_ON_ERROR_P

/*
 * The grammar thinks these are keywords, but they are not in the kwlist.h
 * list and so can never be entered directly.  The filter in parser.c
 * creates these tokens when required (based on looking one token ahead).
 *
 * NOT_LA exists so that productions such as NOT LIKE can be given the same
 * precedence as LIKE; otherwise they'd effectively have the same precedence
 * as NOT, at least with respect to their left-hand subexpression.
 * FORMAT_LA, NULLS_LA, WITH_XX, and WITHOUT_XX are needed to make the grammar
 * LALR(1).
 */
%token  WITH_TIME WITH_LOCAL WITHOUT_TIME WITHOUT_LOCAL PIVOT_TOK UNPIVOT_TOK UNPIVOT_INC UNPIVOT_EXC CONNECT_BY START_WITH
        PARTITION_FOR SUBPARTITION_FOR ORDER_SIBLINGS ABSENT_ON INNER_JOIN JOIN_KEY LEFT_KEY RIGHT_KEY FULL_KEY CROSS_JOIN
        FOREIGN_KEY EXECUTE_ON_DIRECTORY EXECUTE_KEY READ_ON_DIRECTORY READ_KEY

/* Precedence: lowest to highest */
%right       PRIOR
%left        UNION EXCEPT MINUS_P
%left        INTERSECT_P
%left        OR
%left        AND
%right        NOT
%nonassoc    IS ISNULL NOTNULL    /* IS sets precedence for IS NULL, etc */
%nonassoc    '<' '>' '='
%nonassoc    BETWEEN IN_P LIKE ILIKE SIMILAR
%nonassoc    ESCAPE            /* ESCAPE must be just above LIKE/ILIKE/SIMILAR */

/*
 * Sometimes it is necessary to assign precedence to keywords that are not
 * really part of the operator hierarchy, in order to resolve grammar
 * ambiguities.  It's best to avoid doing so whenever possible, because such
 * assignments have global effect and may hide ambiguities besides the one
 * you intended to solve.  (Attaching a precedence to a single rule with
 * %prec is far safer and should be preferred.)  If you must give precedence
 * to a new keyword, try very hard to give it the same precedence as IDENT.
 * If the keyword has IDENT's precedence then it clearly acts the same as
 * non-keywords and other similar keywords, thus reducing the risk of
 * unexpected precedence effects.
 *
 * We used to need to assign IDENT an explicit precedence just less than Op,
 * to support target_el without AS.  While that's not really necessary since
 * we removed postfix operators, we continue to do so because it provides a
 * reference point for a precedence level that we can assign to other
 * keywords that lack a natural precedence level.
 *
 * We need to do this for PARTITION, RANGE, ROWS, and GROUPS to support
 * opt_existing_window_name (see comment there).
 *
 * The frame_bound productions UNBOUNDED PRECEDING and UNBOUNDED FOLLOWING
 * are even messier: since UNBOUNDED is an unreserved keyword (per spec!),
 * there is no principled way to distinguish these from the productions
 * a_expr PRECEDING/FOLLOWING.  We hack this up by giving UNBOUNDED slightly
 * lower precedence than PRECEDING and FOLLOWING.  At present this doesn't
 * appear to cause UNBOUNDED to be treated differently from other unreserved
 * keywords anywhere else in the grammar, but it's definitely risky.  We can
 * blame any funny behavior of UNBOUNDED on the SQL standard, though.
 *
 * To support CUBE and ROLLUP in GROUP BY without reserving them, we give them
 * an explicit priority lower than '(', so that a rule with CUBE '(' will shift
 * rather than reducing a conflicting rule that takes CUBE as a function name.
 * Using the same precedence as IDENT seems right for the reasons given above.
 *
 * SET is likewise assigned the same precedence as IDENT, to support the
 * relation_expr_opt_alias production (see comment there).
 *
 * KEYS, OBJECT_P, SCALAR, VALUE_P, WITH, and WITHOUT are similarly assigned
 * the same precedence as IDENT.  This allows resolving conflicts in the
 * json_predicate_type_constraint and json_key_uniqueness_constraint_opt
 * productions (see comments there).
 *
 * Like the UNBOUNDED PRECEDING/FOLLOWING case, NESTED is assigned a lower
 * precedence than PATH to fix ambiguity in the json_table production.
 */
%nonassoc    UNBOUNDED NESTED /* ideally would have same precedence as IDENT */
%nonassoc    IDENT PARTITION RANGE ROWS GROUPS PRECEDING FOLLOWING CUBE ROLLUP
             SET KEYS OBJECT_P SCALAR VALUE_P WITH WITHOUT PATH FORMAT REGEXP
             SEPARATOR_P AUTO_INCREMENT COMMENT APPENDONLY CACHE CHARSET COMPRESS
             ENABLE_P DISABLE_P INITRANS LOB LOGGING MAXTRANS NOCACHE NOCOMPRESS
             PCTFREE STORAGE SYSTEM_P TABLESPACE CHARACTER

/* Please note that the following line will be replaced with the contents of given file name even if with starting with a comment */
/*$$include "gram-dialect-nonassoc-ident-tokens"*/

%left        '|'    /* OPER_TYPE_BITOR */
%left        '^'    /* OPER_TYPE_BITXOR */
%left        '&'    /* OPER_TYPE_BITAND */
%left        OPER_LSHIFT OPER_RSHIFT /* << and >>, OPER_TYPE_LSHIFT, OPER_TYPE_RSHIFT */
%left        '+' '-' OPER_CAT   /* OPER_TYPE_ADD, OPER_TYPE_SUB, ||(OPER_TYPE_CAT) */
%left        '*' '/' '%'    /* OPER_TYPE_MUL, OPER_TYPE_DIV, OPER_TYPE_MOD */
/* Unary Operators */
%left        AT                /* sets precedence for AT TIME ZONE, AT LOCAL */
%left        COLLATE
%right        UMINUS
%left        '[' ']'
%left        '(' ')'
%left        TYPECAST KEY
%left        '.'
/*
 * These might seem to be low-precedence, but actually they are not part
 * of the arithmetic hierarchy at all in their use as JOIN operators.
 * We make them high-precedence to support their use as function names.
 * They wouldn't be given a precedence at all, were it not that we need
 * left-associativity among the JOIN rules themselves.
 */
%left        NATURAL INNER_JOIN JOIN_KEY LEFT_KEY RIGHT_KEY FULL_KEY CROSS_JOIN
%nonassoc    ON RETURN SQL_CALC_FOUND_ROWS BODY_P IF_P NOLOGGING IGNORE   /* handle table_ref JOIN table_ref JOIN table_ref ON join_qual  */

/* Please note that the following line will be replaced with the contents of given file name even if with starting with a comment */
/*$$include "gram-dialect-decl.y"*/

%%
/*
 *    The target production for the whole parse.
 */
stmtblock:    stmtmulti
            {
                og_yyget_extra(yyscanner)->parsetree = $1;
            }
        ;

stmtmulti:
        InsertStmt
        | SelectStmt
        | DeleteStmt
        | UpdateStmt
        | MergeStmt
        | ReplaceStmt
        | DropStmt
        | TruncateStmt
        | FlashStmt
        | CommentStmt
        | AnalyzeStmt
        | CreatedbStmt
        | CreateUserStmt
        | CreateRoleStmt
        | CreateTenantStmt
        | AlterUserStmt
        | AlterTenantStmt
        | AlterIndexStmt
        | AlterTableStmt
        | AlterDatabaseStmt
        | CreateTablespaceStmt
        | CreateIndexStmt
        | CreateIndexClusterStmt
        | CreateSequenceStmt
        | CreateViewStmt
        | CreateSynonymStmt
        | CreateProfileStmt
        | CreateDirectoryStmt
        | CreateLibraryStmt
        | CreateCtrlfileStmt
        | CreateTableStmt
        | CreateProcedureStmt
        | CreateFunctionStmt
        | CreatePackageStmt
        | CreateTypeStmt
        | CreateTriggerStmt
        | compileFunctionSource
        | compileProcedureSource
        | compileStoredBodySource
        | GrantStmt
        | RevokeStmt
        | PurgeStmt
        | AlterSequenceStmt
        | AlterTablespaceStmt
        | AlterProfileStmt
        | AlterTriggerStmt
        | AlterFunctionStmt
        | TransactionStmt
        | RecoverStmt
        | OgracStmt
        | ShutdownStmt
        | BuildStmt
        | RepairStmt
        | CheckPointStmt
        | ValidateStmt
        | SyncPointStmt
        | LockTableStmt
        | AlterSystemStmt
        | AlterSessionStmt
        | InternalReparseStmt
        | /*EMPTY*/ { $$ = NULL; }
    ;

/*
 * Internal-only parse entries used when catalog metadata is converted back to
 * expression trees.  These are not exposed as standalone SQL statements; the
 * callers in ogsql_stmt.c prepend the marker keywords to make the bison parser
 * reuse the same expression/condition grammar as CREATE TABLE.
 */
InternalReparseStmt:
        DEFAULT a_expr opt_column_on_update
            {
                galist_t *list = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                    parser_yyerror("create default expr list failed.");
                }
                if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                    parser_yyerror("insert default expr failed.");
                }
                if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                    parser_yyerror("insert default update expr failed.");
                }
                $$ = list;
            }
        | CHECK '(' cond_tree_expr ')'
            {
                $$ = $3;
            }
    ;

opt_into:
        INTO                            {}
        | /*EMPTY*/                     {}

opt_ignore:
        IGNORE                                  {  $$ = true; }
        | /*EMPTY*/         %prec UMINUS        {  $$ = false; }
        ;

ignore_nulls:
        IGNORE NULLS_P  {  $$ = true; }
        ;

hint_string:
        COMMENTSTRING
            {
                $$ = $1;
            }
        |
            { 
                $$ = NULL;
            }
        ;

InsertStmt:
        INSERT hint_string opt_ignore opt_into insert_target values_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->table = $5;
            insert_context->pairs = $6;
            insert_context->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_context->pairs, 0))->exprs->count;
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $7;
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target '(' insert_column_list ')' values_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->flags |= INSERT_COLS_SPECIFIED;
            insert_context->table = $5;
            insert_context->pairs = $9;
            column_value_pair_t *pair = NULL;
            galist_t *columns = $7;
            column_parse_info *column = NULL;
            if (insert_context->pairs->count != columns->count) {
                parser_yyerror("insert columns and values not matched");
            }
            for (uint32 i = 0; i < insert_context->pairs->count; i++) {
                column = (column_parse_info*)cm_galist_get(columns, i);
                if (column->owner.str != NULL && !cm_text_equal_ins(&column->owner, &insert_context->table->user.value)) {
                    parser_yyerror("invalid column name");
                }
                if ((column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_context->table->name.value)) &&
                    (column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_context->table->alias.value))) {
                    parser_yyerror("invalid column name");
                }

                pair = (column_value_pair_t*)cm_galist_get(insert_context->pairs, i);
                pair->column_name.value = column->col_name;
            }
            insert_context->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_context->pairs, 0))->exprs->count;
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $10;
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target SelectStmt
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->table = $5;
            insert_context->select_ctx = $6;
            insert_context->select_ctx->type = SELECT_AS_VALUES;
            if (sql_create_list(stmt, &insert_context->pairs) != OG_SUCCESS) {
                parser_yyerror("create column pairs failed.");
            }
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target '(' insert_column_list ')' SelectStmt
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->flags |= INSERT_COLS_SPECIFIED;
            insert_context->table = $5;
            if (column_list_to_column_pairs(stmt, $7, &insert_context->pairs)) {
                parser_yyerror("create column pairs failed.");
            }
            insert_context->select_ctx = $9;
            insert_context->select_ctx->type = SELECT_AS_VALUES;
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target values_clause upsert_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->table = $5;
            insert_context->pairs = $6;
            insert_context->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_context->pairs, 0))->exprs->count;
            insert_context->update_ctx = $7;
            if (sql_array_put(&insert_context->update_ctx->query->tables, insert_context->table) != OG_SUCCESS) {
                parser_yyerror("put table into update_ctx failed.");
            }
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $8;
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target '(' insert_column_list ')' values_clause upsert_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->flags |= INSERT_COLS_SPECIFIED;
            insert_context->table = $5;
            insert_context->pairs = $9;
            column_value_pair_t *pair = NULL;
            galist_t *columns = $7;
            column_parse_info *column = NULL;
            if (insert_context->pairs->count != columns->count) {
                parser_yyerror("insert columns and values not matched");
            }
            for (uint32 i = 0; i < insert_context->pairs->count; i++) {
                column = (column_parse_info*)cm_galist_get(columns, i);
                if (column->owner.str != NULL && !cm_text_equal_ins(&column->owner, &insert_context->table->user.value)) {
                    parser_yyerror("invalid column name");
                }
                if ((column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_context->table->name.value)) &&
                    (column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_context->table->alias.value))) {
                    parser_yyerror("invalid column name");
                }

                pair = (column_value_pair_t*)cm_galist_get(insert_context->pairs, i);
                pair->column_name.value = column->col_name;
            }
            insert_context->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_context->pairs, 0))->exprs->count;
            insert_context->update_ctx = $10;
            if (sql_array_put(&insert_context->update_ctx->query->tables, insert_context->table) != OG_SUCCESS) {
                parser_yyerror("put table into update_ctx failed.");
            }
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $11;
            $$ = insert_context;
        }
        | INSERT hint_string ALL all_insert_into_list SelectStmt
        {
            sql_insert_t *insert_context = NULL;
            sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(og_yyget_extra(yyscanner)->core_yy_extra.stmt, $2, &insert_context->hint_info);
            }
            insert_context->syntax_flag |= INSERT_IS_ALL;
            insert_context->into_list = $4;
            set_insert_ctx(insert_context, 0);
            insert_context->select_ctx = $5;
            insert_context->select_ctx->type = SELECT_AS_VALUES;
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target SelectStmt upsert_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->table = $5;
            insert_context->select_ctx = $6;
            insert_context->select_ctx->type = SELECT_AS_VALUES;
            if (sql_create_list(stmt, &insert_context->pairs) != OG_SUCCESS) {
                parser_yyerror("create column pairs failed.");
            }
            insert_context->update_ctx = $7;
            if (sql_array_put(&insert_context->update_ctx->query->tables, insert_context->table) != OG_SUCCESS) {
                parser_yyerror("put table into update_ctx failed.");
            }
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $8;
            $$ = insert_context;
        }
        | INSERT hint_string opt_ignore opt_into insert_target '(' insert_column_list ')' SelectStmt upsert_clause return_clause
        {
            sql_insert_t *insert_context = NULL;
            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
            sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_context);
            if ($2) {
                og_get_hint_info(stmt, $2, &insert_context->hint_info);
            }
            if ($3) {
                insert_context->syntax_flag |= INSERT_IS_IGNORE;
            }
            insert_context->flags |= INSERT_COLS_SPECIFIED;
            insert_context->table = $5;
            if (column_list_to_column_pairs(stmt, $7, &insert_context->pairs)) {
                parser_yyerror("create column pairs failed.");
            }
            insert_context->select_ctx = $9;
            insert_context->select_ctx->type = SELECT_AS_VALUES;
            insert_context->update_ctx = $10;
            if (sql_array_put(&insert_context->update_ctx->query->tables, insert_context->table) != OG_SUCCESS) {
                parser_yyerror("put table into update_ctx failed.");
            }
            if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                sql_array_concat(&insert_context->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
            }
            insert_context->ret_columns = $11;
            $$ = insert_context;
        }
    ;

return_returning:
        RETURN
        | RETURNING
    ;

return_clause:
        return_returning target_list
        {
            $$ = $2;
        }
        | /* EMPTY */                    { $$ = NULL; }
    ;

upsert_clause:
        ON DUPLICATE KEY UPDATE set_clause_list
        {
            sql_update_t *update_context = NULL;
            sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(sql_update_t), (void **)&update_context);
            if (sql_init_update(og_yyget_extra(yyscanner)->core_yy_extra.stmt, update_context) != OG_SUCCESS) {
                parser_yyerror("init sql_update_t failed.");
            }
            cm_galist_copy(update_context->pairs, $5);
            $$ = update_context;
        }
        ;

set_clause_list:
            set_clause                          { $$ = $1; }
            | set_clause_list ',' set_clause
            {
                galist_t *list = $1;
                cm_galist_copy(list, $3);
                $$ = list;
            }
        ;

set_clause:
            single_set_clause
            {
                galist_t *list = NULL;
                if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                    parser_yyerror("create column pair list failed.");
                }
                cm_galist_insert(list, $1);
                $$ = list;
            }
            | multiple_set_clause                   { $$ = $1; }
        ;

single_set_clause:
            columnref '=' ctext_expr
                {
                    column_value_pair_t *pair = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(column_value_pair_t), (void **)&pair)) {
                        parser_yyerror("init column pair failed");
                    }
                    pair->column_expr = $1;
                    sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &pair->exprs);
                    cm_galist_insert(pair->exprs, $3);
                    $$ = pair;
                }
        ;

multiple_set_clause:
            '(' set_target_list ')' '=' '(' SelectStmt ')'
                {
                    galist_t *list = NULL;
                    expr_tree_t *expr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_select_t *select_ctx = $6;
                    select_ctx->type = SELECT_AS_MULTI_VARIANT;
                    if (sql_create_select_expr(stmt, &expr, select_ctx, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                        @6.loc) != OG_SUCCESS) {
                        parser_yyerror("init select expr failed");
                    }

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column pair list failed.");
                    }
                    column_value_pair_t *pair = $2;
                    sql_create_list(stmt, &pair->exprs);
                    cm_galist_insert(pair->exprs, expr);
                    cm_galist_insert(list, pair);

                    if (pair->column_expr->next != NULL) {
                        expr_tree_t *tmp_expr = pair->column_expr->next;
                        pair->column_expr->next = NULL;
                        int rs_no = 1;
                        pair->rs_no = rs_no = 1; // Ref to subquery rs_column, start with 1, 0 for non-multi set
                        while (tmp_expr != NULL) {
                            column_value_pair_t *next_pair = NULL;
                            cm_galist_new(list, sizeof(column_value_pair_t), (pointer_t *)&next_pair);
                            sql_create_list(stmt, &next_pair->exprs);
                            cm_galist_insert(next_pair->exprs, expr);

                            next_pair->column_expr = tmp_expr;
                            tmp_expr = tmp_expr->next;
                            next_pair->column_expr->next = NULL;
                            ++rs_no;
                            next_pair->rs_no = rs_no;
                        }
                    }
                    $$ = list;
                }
        ;

set_target_list:
            columnref
            {
                column_value_pair_t *pair = NULL;
                if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(column_value_pair_t), (void **)&pair)) {
                    parser_yyerror("init column pair failed");
                }
                pair->column_expr = $1;
                $$ = pair;
            }
            | set_target_list ',' columnref
            {
                column_value_pair_t *pair = $1;
                expr_tree_t *arg_tree = pair->column_expr;
                expr_tree_t **temp = &arg_tree->next;
                while (*temp != NULL) {
                    temp = &(*temp)->next;
                }
                *temp = $3;
                $$ = pair;
            }
        ;

all_insert_into_list:
        all_insert_into
        {
            galist_t *list = NULL;
            if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                parser_yyerror("create all_insert_into list failed.");
            }
            if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                parser_yyerror("insert all_insert_into list failed.");
            }
            $$ = list;
        }
        | all_insert_into_list all_insert_into
        {
            galist_t *list = $1;
            if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                parser_yyerror("insert all_insert_into list failed.");
            }
            $$ = list;
        }
    ;


all_insert_into:
        INTO insert_target values_clause
        {
            insert_all_t *into_item = NULL;
            if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(insert_all_t), (void **)&into_item)) {
                parser_yyerror("init insert_all_t failed");
            }
            into_item->table = $2;
            into_item->pairs = $3;
            into_item->pairs_count = ((column_value_pair_t*)cm_galist_get(into_item->pairs, 0))->exprs->count;
            $$ = into_item;
        }
        | INTO insert_target '(' insert_column_list ')' values_clause
        {
            insert_all_t *into_item = NULL;
            if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(insert_all_t), (void **)&into_item)) {
                parser_yyerror("init insert_all_t failed");
            }
            into_item->flags |= INSERT_COLS_SPECIFIED;
            into_item->table = $2;
            into_item->pairs = $6;
            column_value_pair_t *pair = NULL;
            galist_t *columns = $4;
            column_parse_info *column = NULL;
            if (into_item->pairs->count != columns->count) {
                parser_yyerror("insert columns and values not matched");
            }
            for (uint32 i = 0; i < into_item->pairs->count; i++) {
                column = (column_parse_info*)cm_galist_get(columns, i);
                if (column->owner.str != NULL && !cm_text_equal_ins(&column->owner, &into_item->table->user.value)) {
                    parser_yyerror("invalid column name");
                }
                if ((column->table.str != NULL && !cm_text_equal_ins(&column->table, &into_item->table->name.value)) &&
                    (column->table.str != NULL && !cm_text_equal_ins(&column->table, &into_item->table->alias.value))) {
                    parser_yyerror("invalid column name");
                }

                pair = (column_value_pair_t*)cm_galist_get(into_item->pairs, i);
                pair->column_name.value = column->col_name;
            }
            into_item->pairs_count = ((column_value_pair_t*)cm_galist_get(into_item->pairs, 0))->exprs->count;
            $$ = into_item;
        }

insert_column_list:
        insert_column_item
        {
            galist_t *list = NULL;
            (void)sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list);
            cm_galist_insert(list, $1);
            $$ = list;
        }
        | insert_column_list ',' insert_column_item
        {
            galist_t *list = $1;
            cm_galist_insert(list, $3);
            $$ = list;
        }
        ;

insert_column_item:
            ColId opt_indirection
                {
                    column_parse_info *column = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(column_parse_info), (void **)&column) != OG_SUCCESS) {
                        parser_yyerror("init list failed");
                    }
                    if ($2 == NULL) {
                        column->col_name.str = $1;
                        column->col_name.len = strlen($1);
                    } else {
                        galist_t *list = $2;
                        switch (list->count) {
                            case 1:
                                column->table.str = $1;
                                column->table.len = strlen($1);

                                column->col_name = ((expr_tree_t*)cm_galist_get(list, 0))->root->value.v_text;
                                break;
                            case 2:
                                column->owner.str = $1;
                                column->owner.len = strlen($1);

                                column->table = ((expr_tree_t*)cm_galist_get(list, 0))->root->value.v_text;
                                column->col_name = ((expr_tree_t*)cm_galist_get(list, 1))->root->value.v_text;
                                break;
                            default:
                                parser_yyerror("improper column name (too many dotted names)");
                                break;
                        }
                    }
                    if (!(og_yyget_extra(yyscanner))->core_yy_extra.ident_quoted) {
                        cm_str_upper(column->col_name.str);
                    }
                    $$ = column;
                }

indirection_el:
            '.' ColId
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("init const expr failed");
                    }
                    $$ = expr;
                }
            | '.' '*'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_star_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, @1) != OG_SUCCESS) {
                        parser_yyerror("init expr failed");
                    }
                    $$ = expr;
                }
            | '[' ICONST ']'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_indices_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr,
                        $2, OG_INVALID_ID32, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("init array indices failed");
                    }
                    $$ = expr;
                }
            | '[' ICONST ':' ICONST ']'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_indices_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr,
                        $2, $4, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("init array indices failed");
                    }
                    $$ = expr;
                }
        ;

indirection:
            indirection_el
                {
                    galist_t *list = NULL;
                    (void)sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list);
                    cm_galist_insert(list, $1);
                    $$ = list;
                }
            | indirection indirection_el
                {
                    cm_galist_insert($1, $2);
                    $$ = $1;
                }
        ;

opt_indirection:
            /*EMPTY*/                           { $$ = NULL; }
            | opt_indirection indirection_el
            {
                galist_t *list = $1;
                if (list == NULL) {
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("init list failed");
                    }
                }
                cm_galist_insert(list, $2);
                $$ = list;
            }
        ;

qualified_name:
            ColId
                {
                    sql_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);
                    table->user.implicit = OG_TRUE;
                    table->name.value.str = $1;
                    table->name.value.len = strlen($1);
                    text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
                    if (IS_DUAL_TABLE_NAME(&table->name.value)) {
                        cm_text_upper(&table->name.value);
                    }

                    if (sql_copy_name(stmt->context, &user_name, (text_t *)&table->user) != OG_SUCCESS) {
                        parser_yyerror("copy user name failed.");
                    }

                    bool32 is_withas_table = OG_FALSE;
                    if (sql_try_match_withas_table(stmt, table, &is_withas_table) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    if (!is_withas_table) {
                        sql_regist_table(stmt, table);
                    }
                    $$ = table;
                }
            | ColId indirection
                {
                    sql_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);

                    galist_t *list = $2;

                    switch (list->count)
                    {
                        case 1:
                            table->user.value.str = $1;
                            table->user.value.len = strlen($1);
                            table->name.value = ((expr_tree_t*)cm_galist_get(list, 0))->root->value.v_text;
                            break;
                        default:
                            parser_yyerror("improper qualified name (too many dotted names)");
                            break;
                    }
                    bool32 is_withas_table = OG_FALSE;
                    if (sql_try_match_withas_table(stmt, table, &is_withas_table) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    if (!is_withas_table) {
                        sql_regist_table(stmt, table);
                    }
                    $$ = table;
                }
        ;

alias_clause:
        alias_without_as
            {
                $$ = $1;
            }
        | AS ColId
            {
                $$ = $2;
            }
        ;

alias_without_as:
        IDENT                       { $$ = $1; }
        | unreserved_keyword
            {
                char *tmp = NULL;
                BISON_MEM_STRDUP(tmp, $1);
                cm_str_upper(tmp);
                $$ = tmp;
            }
        ;

insert_target:
        qualified_name          %prec UMINUS
        {
            $$ = $1;
        }
        | qualified_name alias_without_as
        {
            sql_table_t *table = $1;
            table->alias.value.str = $2;
            table->alias.value.len = strlen($2);
            $$ = table;
        }
        | qualified_name AS ColId
        {
            sql_table_t *table = $1;
            table->alias.value.str = $3;
            table->alias.value.len = strlen($3);
            $$ = table;
        }
    ;

values_clause:
            VALUES ctext_row
                {
                    galist_t *pairs = NULL;
                    (void)sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &pairs);
                    column_value_pair_t *pair = NULL;
                    galist_t *row = $2;
                    for (uint32 i = 0; i < row->count; i++) {
                        (void)cm_galist_new(pairs, sizeof(column_value_pair_t), (pointer_t *)&pair);
                        (void)sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &pair->exprs);
                        cm_galist_insert(pair->exprs, cm_galist_get(row, i));
                    }
                    $$ = pairs;
                }
            | values_clause ',' ctext_row
                {
                    galist_t *pairs = $1;
                    column_value_pair_t *pair = NULL;
                    galist_t *row = $3;
                    for (uint32 i = 0; i < row->count; i++) {
                        pair = (column_value_pair_t*)cm_galist_get(pairs, i);
                        cm_galist_insert(pair->exprs, cm_galist_get(row, i));
                    }
                    $$ = pairs;
                }
        ;

ctext_row: '(' ctext_expr_list ')'    { $$ = $2; }
               ;

ctext_expr_list:
            ctext_expr
                {
                    galist_t* row = NULL;
                    (void)sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &row);
                    cm_galist_insert(row, $1);
                    $$ = row;
                }
            | ctext_expr_list ',' ctext_expr
                {
                    galist_t* row = $1;
                    cm_galist_insert(row, $3);
                    $$ = row;
                }
        ;

ctext_expr:
            a_expr    { $$ = $1; }
        ;

multi_expr_list:    expr_list_with_select ',' expr_with_select
                {
                    expr_tree_t *expr = $1;
                    expr_tree_t *temp = sql_expr_list_last(expr);
                    temp->next = $3;
                    $$ = expr;
                }

expr_list:  a_expr
                {
                    galist_t* e_list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &e_list) != OG_SUCCESS) {
                        parser_yyerror("create expr list failed.");
                    }
                    if (cm_galist_insert(e_list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert expr list failed.");
                    }
                    $$ = e_list;
                }
            | expr_list ',' a_expr
                {
                    galist_t* e_list = $1;
                    if (cm_galist_insert(e_list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert expr list failed.");
                    }
                    $$ = e_list;
                }
        ;

with_clause:
            WITH cte_list
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;
                    withas->cur_match_idx = OG_INVALID_ID32;
                    obj_stack_push(&og_yyget_extra(yyscanner)->core_yy_extra.withas_stack, $2);
                    $$ = $2;
                }
        ;

cte_list:
            common_table_expr
                {
                    galist_t* cte_list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &cte_list) != OG_SUCCESS) {
                        parser_yyerror("create expr list failed.");
                    }
                    if (cm_galist_insert(cte_list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert cte list failed.");
                    }
                    $$ = cte_list;
                }
            | cte_list ',' common_table_expr
                {
                    galist_t* cte_list = $1;
                    sql_withas_factor_t *factor = $3;
                    if (cte_list->count > 0) {
                        factor->prev_factor = (sql_withas_factor_t *)cm_galist_get(cte_list, cte_list->count - 1);
                    }
                    if (cm_galist_insert(cte_list, factor) != OG_SUCCESS) {
                        parser_yyerror("insert cte list failed.");
                    }
                    $$ = cte_list;
                }
        ;

common_table_expr:
            ColId AS '(' SelectStmt ')'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_factor_t *factor = NULL;
                    sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;
                    if (withas == NULL) {
                        if (sql_alloc_mem(stmt->context, sizeof(sql_withas_t), &stmt->context->withas_entry) != OG_SUCCESS) {
                            parser_yyerror("alloc mem failed");
                        }
                        withas = (sql_withas_t *)stmt->context->withas_entry;
                        if (sql_create_list(stmt, &withas->withas_factors) != OG_SUCCESS) {
                            parser_yyerror("create list failed");
                        }
                    }
                    if (cm_galist_new(withas->withas_factors, sizeof(sql_withas_factor_t), (void **)&factor) != OG_SUCCESS) {
                        parser_yyerror("new factor failed");
                    }
                    factor->id = withas->withas_factors->count - 1;
                    factor->prev_factor = NULL;
                    factor->owner = NULL;
                    withas->cur_match_idx = withas->withas_factors->count;

                    text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
                    if (sql_copy_name(stmt->context, &user_name, (text_t *)&factor->user) != OG_SUCCESS) {
                        parser_yyerror("copy user name failed.");
                    }
                    factor->name.value.str = $1;
                    factor->name.value.len = strlen($1);
                    ((sql_select_t*)$4)->type = SELECT_AS_TABLE;
                    factor->subquery_ctx = $4;

                    $$ = factor;
                }
        ;

SelectStmt: select_no_parens            %prec UMINUS
            | select_with_parens        %prec UMINUS
        ;

select_with_parens:
            '(' select_no_parens ')'                { $$ = $2; }
            | '(' select_with_parens ')'            { $$ = $2; }
        ;

select_no_parens:
            simple_select                           { $$ = $1; }
            | with_clause select_clause
                {
                    sql_select_t *select_ctx = $2;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_factor_t *factor = NULL;
                    if (select_ctx->withass == NULL && sql_create_list(stmt, &select_ctx->withass) != OG_SUCCESS) {
                        parser_yyerror("create withass failed");
                    }

                    for (uint32 i = 0; i < $1->count; i++) {
                        factor = (sql_withas_factor_t*)cm_galist_get($1, i);
                        factor->owner = select_ctx;
                        cm_galist_insert(select_ctx->withass, factor);
                    }
                    (void)obj_stack_pop(&og_yyget_extra(yyscanner)->core_yy_extra.withas_stack);
                    $$ = select_ctx;
                }
            | select_clause sort_clause
                {
                    sql_select_t *select_ctx = $1;
                    galist_t **sort_items = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                    } else {
                        sort_items = &select_ctx->sort_items;
                    }
                    if (cm_galist_copy(*sort_items, $2) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    $$ = select_ctx;
                }
            | select_clause opt_sort_clause opt_limit for_locking_clause
                {
                    sql_select_t *select_ctx = $1;
                    galist_t **sort_items = NULL;
                    limit_item_t *limit = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                        limit = &select_ctx->first_query->limit;
                    } else {
                        sort_items = &select_ctx->sort_items;
                        limit = &select_ctx->limit;
                    }
                    if ($2 && cm_galist_copy(*sort_items, $2) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    if ($3) {
                        limit->count = $3->count;
                        limit->offset = $3->offset;
                    }
                    select_ctx->for_update = OG_TRUE;
                    select_ctx->for_update_cols = $4->for_update_cols;
                    select_ctx->for_update_params = $4->for_update_params;
                    $$ = select_ctx;
                }
            | select_clause opt_sort_clause select_limit
                {
                    sql_select_t *select_ctx = $1;
                    galist_t **sort_items = NULL;
                    limit_item_t *limit = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                        limit = &select_ctx->first_query->limit;
                    } else {
                        sort_items = &select_ctx->sort_items;
                        limit = &select_ctx->limit;
                    }
                    if ($2 && cm_galist_copy(*sort_items, $2) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    limit->count = $3->count;
                    limit->offset = $3->offset;
                    $$ = select_ctx;
                }
            | with_clause select_clause sort_clause
                {
                    sql_select_t *select_ctx = $2;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_factor_t *factor = NULL;
                    if (select_ctx->withass == NULL && sql_create_list(stmt, &select_ctx->withass) != OG_SUCCESS) {
                        parser_yyerror("create withass failed");
                    }

                    for (uint32 i = 0; i < $1->count; i++) {
                        factor = (sql_withas_factor_t*)cm_galist_get($1, i);
                        factor->owner = select_ctx;
                        cm_galist_insert(select_ctx->withass, factor);
                    }
                    (void)obj_stack_pop(&og_yyget_extra(yyscanner)->core_yy_extra.withas_stack);

                    galist_t **sort_items = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                    } else {
                        sort_items = &select_ctx->sort_items;
                    }
                    if (cm_galist_copy(*sort_items, $3) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    $$ = select_ctx;
                }
            | with_clause select_clause opt_sort_clause opt_limit for_locking_clause
                {
                    sql_select_t *select_ctx = $2;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_factor_t *factor = NULL;
                    if (select_ctx->withass == NULL && sql_create_list(stmt, &select_ctx->withass) != OG_SUCCESS) {
                        parser_yyerror("create withass failed");
                    }

                    for (uint32 i = 0; i < $1->count; i++) {
                        factor = (sql_withas_factor_t*)cm_galist_get($1, i);
                        factor->owner = select_ctx;
                        cm_galist_insert(select_ctx->withass, factor);
                    }
                    (void)obj_stack_pop(&og_yyget_extra(yyscanner)->core_yy_extra.withas_stack);

                    galist_t **sort_items = NULL;
                    limit_item_t *limit = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                        limit = &select_ctx->first_query->limit;
                    } else {
                        sort_items = &select_ctx->sort_items;
                        limit = &select_ctx->limit;
                    }
                    if ($3 && cm_galist_copy(*sort_items, $3) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    if ($4) {
                        limit->count = $4->count;
                        limit->offset = $4->offset;
                    }
                    select_ctx->for_update = OG_TRUE;
                    select_ctx->for_update_cols = $5->for_update_cols;
                    select_ctx->for_update_params = $5->for_update_params;
                    $$ = select_ctx;
                }
            | with_clause select_clause opt_sort_clause select_limit
                {
                    sql_select_t *select_ctx = $2;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_withas_factor_t *factor = NULL;
                    if (select_ctx->withass == NULL && sql_create_list(stmt, &select_ctx->withass) != OG_SUCCESS) {
                        parser_yyerror("create withass failed");
                    }

                    for (uint32 i = 0; i < $1->count; i++) {
                        factor = (sql_withas_factor_t*)cm_galist_get($1, i);
                        factor->owner = select_ctx;
                        cm_galist_insert(select_ctx->withass, factor);
                    }
                    (void)obj_stack_pop(&og_yyget_extra(yyscanner)->core_yy_extra.withas_stack);

                    galist_t **sort_items = NULL;
                    limit_item_t *limit = NULL;
                    if (select_ctx->root->type == SELECT_NODE_QUERY) {
                        sort_items = &select_ctx->first_query->sort_items;
                        limit = &select_ctx->first_query->limit;
                    } else {
                        sort_items = &select_ctx->sort_items;
                        limit = &select_ctx->limit;
                    }
                    if ($3 && cm_galist_copy(*sort_items, $3) != OG_SUCCESS) {
                        parser_yyerror("parse order by failed");
                    }
                    limit->count = $4->count;
                    limit->offset = $4->offset;
                    $$ = select_ctx;
                }
        ;

opt_wait:   WAIT ICONST                         { $$ = $2; }
        ;

opt_nowait_or_skip:
            NOWAIT                              { $$ = ROWMARK_NOWAIT; }
            | SKIP LOCKED                       { $$ = ROWMARK_SKIP_LOCKED; }
            | /* EMPTY */                       { $$ = ROWMARK_WAIT_BLOCK; }
        ;

columnref_list:
            columnref
                {
                    galist_t* e_list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &e_list) != OG_SUCCESS) {
                        parser_yyerror("create columnref list failed.");
                    }
                    if (cm_galist_insert(e_list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert columnref list failed.");
                    }
                    $$ = e_list;
                }
            | columnref_list ',' columnref
                {
                    galist_t* e_list = $1;
                    if (cm_galist_insert(e_list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert columnref list failed.");
                    }
                    $$ = e_list;
                }
        ;

locked_rels_list:
            OF_P columnref_list                        { $$ = $2; }
            | /* EMPTY */                       { $$ = NULL; }
        ;

for_locking_clause:
            FOR UPDATE locked_rels_list opt_wait
                {
                    for_update_clause *for_update = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(for_update_clause), (void **)&for_update) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    for_update->for_update_cols = $3;
                    for_update->for_update_params.type = ROWMARK_WAIT_SECOND;
                    for_update->for_update_params.wait_seconds = $4;
                    $$ = for_update;
                }
            | FOR UPDATE locked_rels_list opt_nowait_or_skip
                {
                    for_update_clause *for_update = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(for_update_clause), (void **)&for_update) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    for_update->for_update_cols = $3;
                    for_update->for_update_params.type = $4;
                    $$ = for_update;
                }
        ;

select_limit:
            limit_clause                            { $$ = $1; }
            | offset_clause                         { $$ = $1; }
        ;

select_clause:
            simple_select                           { $$ = $1; }
            | select_with_parens                    { $$ = $1; }
        ;

opt_found_rows:
            SQL_CALC_FOUND_ROWS                     { $$ = true; }
            | /* EMPTY */          %prec UMINUS     { $$ = false; }
        ;

opt_distinct:
            DISTINCT                                { $$ = true; }
            | /* EMPTY */                           { $$ = false; }
        ;

pivot_in_list:
            pivot_in_list_element
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | pivot_in_list ',' pivot_in_list_element
                {
                    galist_t* list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert target list failed.");
                    }
                    $$ = list;
                }
        ;

pivot_in_item_list:
            pivot_in_item
                {
                    $$ = $1;
                }
            | pivot_in_item_list ',' pivot_in_item
                {
                    expr_with_alias *pivot_expr = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    char temp_str[OG_MAX_NAME_LEN] = { 0 };
                    text_t tmp_alias;
                    tmp_alias.str = temp_str;
                    tmp_alias.len = 0;

                    (sql_expr_list_last(pivot_expr->expr))->next = $3->expr;
                    if (cm_text_copy(&tmp_alias, OG_MAX_NAME_LEN, &pivot_expr->alias) != OG_SUCCESS) {
                        parser_yyerror("cm_text_copy failed");
                    }
                    char *pos = tmp_alias.str + tmp_alias.len;
                    if (tmp_alias.len != 0 && tmp_alias.len < OG_MAX_NAME_LEN) {
                        *pos++ = '_';
                        tmp_alias.len++;
                    }
                    
                    text_t to_be_added = $3->alias;
                    to_be_added.len = MIN(OG_MAX_NAME_LEN - tmp_alias.len, to_be_added.len);
                    if (to_be_added.len > 0) {
                        errno_t ret = memcpy_sp(pos, OG_MAX_NAME_LEN - tmp_alias.len, to_be_added.str, to_be_added.len);
                        if (ret != EOK) {
                            parser_yyerror("memcpy failed");
                        }
                        tmp_alias.len = MIN(tmp_alias.len + to_be_added.len, OG_MAX_NAME_LEN);
                    }
                    if (sql_copy_text(stmt->context, &tmp_alias, &pivot_expr->alias) != OG_SUCCESS) {
                        parser_yyerror("sql_copy_text failed");
                    }
                    $$ = pivot_expr;
                }
        ;

pivot_in_item:
            a_expr    %prec UMINUS
            {
                expr_with_alias *pivot_expr = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(expr_with_alias), (void **)&pivot_expr) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                pivot_expr->expr = $1;
                pivot_expr->alias.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @1.offset;
                pivot_expr->alias.len = yylloc.offset == @1.offset ? strlen(pivot_expr->alias.str) : yylloc.offset - @1.offset;
                $$ = pivot_expr;
            }
        ;

pivot_in_list_element:
            '(' pivot_in_item_list ')' AS ColLabel
                {
                    expr_with_alias *pivot_expr = $2;
                    text_t alias;
                    alias.str = $5;
                    alias.len = strlen($5);

                    if (sql_copy_name(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, &alias, &pivot_expr->alias) != OG_SUCCESS) {
                        parser_yyerror("sql_copy_name failed");
                    }
                    $$ = pivot_expr;
                }
            | '(' pivot_in_item_list ')' IDENT
                {
                    expr_with_alias *pivot_expr = $2;
                    text_t alias;
                    alias.str = $4;
                    alias.len = strlen($4);

                    if (sql_copy_name(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, &alias, &pivot_expr->alias) != OG_SUCCESS) {
                        parser_yyerror("sql_copy_name failed");
                    }
                    $$ = pivot_expr;
                }
            | '(' pivot_in_item_list ')'
                {
                    $$ = $2;
                }
        ;

unpivot_in_list:
            unpivot_in_list_element
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | unpivot_in_list ',' unpivot_in_list_element
                {
                    galist_t* list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert target list failed.");
                    }
                    $$ = list;
                }

unpivot_in_list_element:
            '(' pivot_in_item_list ')' AS implicit_row
                {
                    expr_with_as_expr *unpivot_expr_with_as = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(expr_with_as_expr), (void **)&unpivot_expr_with_as) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    unpivot_expr_with_as->expr_alias = $2;
                    unpivot_expr_with_as->as_expr = $5;
                    $$ = unpivot_expr_with_as;
                }
            | '(' pivot_in_item_list ')' AS expr_with_select
                {
                    expr_with_as_expr *unpivot_expr_with_as = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(expr_with_as_expr), (void **)&unpivot_expr_with_as) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    unpivot_expr_with_as->expr_alias = $2;
                    unpivot_expr_with_as->as_expr = $5;
                    $$ = unpivot_expr_with_as;
                }
            | '(' pivot_in_item_list ')'
                {
                    expr_with_as_expr *unpivot_expr_with_as = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(expr_with_as_expr), (void **)&unpivot_expr_with_as) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    unpivot_expr_with_as->expr_alias = $2;
                    $$ = unpivot_expr_with_as;
                }
            | pivot_in_item AS expr_with_select
                {
                    expr_with_as_expr *unpivot_expr_with_as = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(expr_with_as_expr), (void **)&unpivot_expr_with_as) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    unpivot_expr_with_as->expr_alias = $1;
                    unpivot_expr_with_as->as_expr = $3;
                    $$ = unpivot_expr_with_as;
                }
            | pivot_in_item
                {
                    expr_with_as_expr *unpivot_expr_with_as = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(expr_with_as_expr), (void **)&unpivot_expr_with_as) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    unpivot_expr_with_as->expr_alias = $1;
                    $$ = unpivot_expr_with_as;
                }
        ;

pivot_clause:
            PIVOT_TOK target_list FOR expr_list_with_select IN_P '(' target_list ')' ')'
                {
                    pivot_items_t *pivot_items = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pivot_items_t), (void **)&pivot_items) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (sql_create_pivot_items(stmt, &pivot_items, @1.loc, PIVOT_TYPE) != OG_SUCCESS) {
                        parser_yyerror("init pivot failed");
                    }
                    if (sql_parse_pivot_aggr_list($2, &pivot_items->aggr_expr, pivot_items->aggr_alias, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse pivot aggr list failed");
                    }
                    pivot_items->for_expr = $4;
                    if (sql_parse_pivot_aggr_list($7, &pivot_items->in_expr, pivot_items->alias, OG_TRUE) != OG_SUCCESS) {
                        parser_yyerror("parse pivot in list failed");
                    }
                    $$ = pivot_items;
                }
            | PIVOT_TOK target_list FOR '(' multi_expr_list ')' IN_P '(' pivot_in_list ')' ')'
                {
                    pivot_items_t *pivot_items = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pivot_items_t), (void **)&pivot_items) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (sql_create_pivot_items(stmt, &pivot_items, @1.loc, PIVOT_TYPE) != OG_SUCCESS) {
                        parser_yyerror("init pivot failed");
                    }
                    if (sql_parse_pivot_aggr_list($2, &pivot_items->aggr_expr, pivot_items->aggr_alias, OG_FALSE)  != OG_SUCCESS) {
                        parser_yyerror("parse pivot aggr list failed");
                    }
                    pivot_items->for_expr = $5;
                    if (sql_parse_pivot_in_list(pivot_items, $9) != OG_SUCCESS) {
                        parser_yyerror("parse pivot in list failed");
                    }
                    $$ = pivot_items;
                }
            | unpivot_include_or_exclude_nulls expr_list_with_paren FOR expr_list_with_paren IN_P '(' unpivot_in_list ')' ')'
                {
                    pivot_items_t *pivot_items = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pivot_items_t), (void **)&pivot_items) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (sql_create_pivot_items(stmt, &pivot_items, @1.loc, UNPIVOT_TYPE) != OG_SUCCESS) {
                        parser_yyerror("init unpivot failed");
                    }

                    pivot_items->include_nulls = $1;

                    if (sql_parse_unpivot_data_rs(stmt, pivot_items->unpivot_data_rs, $2) != OG_SUCCESS) {
                        parser_yyerror("parse unpivot unpivot_data_rs failed");
                    }

                    if (sql_parse_unpivot_data_rs(stmt, pivot_items->unpivot_alias_rs, $4) != OG_SUCCESS) {
                        parser_yyerror("parse unpivot unpivot_alias_rs failed");
                    }

                    if (sql_parse_unpivot_in_list(stmt, pivot_items, $7) != OG_SUCCESS) {
                        parser_yyerror("parse unpivot in list failed");
                    }
                    $$ = pivot_items;
                }
        ;

unpivot_include_or_exclude_nulls:
            UNPIVOT_INC NULLS_P '('                 { $$ = true; }
            | UNPIVOT_EXC NULLS_P '('               { $$ = false; }
            | UNPIVOT_TOK                           { $$ = false; }
        ;

expr_list_with_paren:
            a_expr                      { $$ = $1; }
            | '(' multi_expr_list ')'   { $$ = $2; }
        ;

pivot_clause_list:
            pivot_clause
                {
                    galist_t *pivot_list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &pivot_list) != OG_SUCCESS) {
                        parser_yyerror("create expr list failed.");
                    }
                    cm_galist_insert(pivot_list, $1);
                    $$ = pivot_list;
                }
            | pivot_clause_list pivot_clause
                {
                    galist_t *pivot_list = $1;
                    cm_galist_insert(pivot_list, $2);
                    $$ = pivot_list;
                }
        ;

select_pivot_clause:
            pivot_clause_list                   { $$ = $1; }
            | /* EMPTY */                       { $$ = NULL; }
        ;

expr_or_implicit_row_list:
            expr_or_implicit_row
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | expr_or_implicit_row_list ',' expr_or_implicit_row
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

expr_or_implicit_row:
            a_expr                              { $$ = $1; }
            | implicit_row                      { $$ = $1; }
        ;

cube_clause:
            CUBE '(' expr_or_implicit_row_list ')'
                {
                    galist_t *group_sets = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (sql_extract_group_cube(og_yyget_extra(yyscanner)->core_yy_extra.stmt, $3, group_sets) != OG_SUCCESS) {
                        parser_yyerror("extract group cube failed.");
                    }
                    $$ = group_sets;
                }
        ;

rollup_clause:
            ROLLUP '(' expr_or_implicit_row_list ')'
                {
                    galist_t *group_sets = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (sql_extract_group_rollup(og_yyget_extra(yyscanner)->core_yy_extra.stmt, $3, group_sets) != OG_SUCCESS) {
                        parser_yyerror("extract group cube failed.");
                    }
                    $$ = group_sets;
                }
        ;

group_sets_item:
            a_expr
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *group_sets = NULL;
                    group_set_t *group_set = NULL;

                    if (sql_create_list(stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_new(group_sets, sizeof(group_set_t), (void **)&group_set) != OG_SUCCESS) {
                        parser_yyerror("new group_set_t failed.");
                    }
                    if (sql_create_list(stmt, &group_set->items) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(group_set->items, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = group_sets;
                }
            | '(' expr_list ',' a_expr ')'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *group_sets = NULL;
                    group_set_t *group_set = NULL;

                    if (sql_create_list(stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_new(group_sets, sizeof(group_set_t), (void **)&group_set) != OG_SUCCESS) {
                        parser_yyerror("new group_set_t failed.");
                    }
                    group_set->items = $2;
                    if (cm_galist_insert(group_set->items, $4) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = group_sets;
                }
            | cube_clause                           { $$ = $1; }
            | rollup_clause                         { $$ = $1; }
            | '(' ')'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *group_sets = NULL;
                    group_set_t *group_set = NULL;

                    if (sql_create_list(stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_new(group_sets, sizeof(group_set_t), (void **)&group_set) != OG_SUCCESS) {
                        parser_yyerror("new group_set_t failed.");
                    }
                    if (sql_create_list(stmt, &group_set->items) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    $$ = group_sets;
                }
        ;

group_sets_list:
            group_sets_item                                   { $$ = $1; }
            | group_sets_list ',' group_sets_item
                {
                    galist_t *list = $1;
                    if (cm_galist_copy(list, $3) != OG_SUCCESS) {
                        parser_yyerror("copy list failed");
                    }
                    $$ = list;
                }
        ;

grouping_sets_clause:
            GROUPING_P SETS '(' group_sets_list ')'
                {
                    $$ = $4;
                }
        ;

group_by_cartesian_item:
            grouping_sets_clause                        { $$ = $1; }
            | cube_clause                               { $$ = $1; }
            | rollup_clause                             { $$ = $1; }
        ;

group_by_list:
            a_expr      %prec UMINUS
                {
                    galist_t *group_sets = NULL;
                    group_set_t *group_set = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &group_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_new(group_sets, sizeof(group_set_t), (void **)&group_set) != OG_SUCCESS) {
                        parser_yyerror("new group_set_t failed.");
                    }
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &group_set->items) != OG_SUCCESS) {
                        parser_yyerror("create group_set items failed.");
                    }
                    if (cm_galist_insert(group_set->items, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = group_sets;
                }
            | group_by_cartesian_item
                {
                    $$ = $1;
                }
            | group_by_list ',' a_expr
                {
                    galist_t *group_sets = $1;
                    group_set_t *group_set = NULL;

                    for (uint32 i = 0; i < group_sets->count; i++) {
                        group_set = (group_set_t *)cm_galist_get(group_sets, i);
                        if (cm_galist_insert(group_set->items, $3) != OG_SUCCESS) {
                            parser_yyerror("insert group_sets failed.");
                        }
                    }
                    $$ = group_sets;
                }
            | group_by_list ',' group_by_cartesian_item
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *new_grp_sets = NULL;
                    galist_t *group_sets = $1;
                    group_set_t *group_set = NULL;

                    if (sql_create_list(stmt, &new_grp_sets) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }

                    for (uint32 i = 0; i < $3->count; i++) {
                        group_set = (group_set_t *)cm_galist_get($3, i);
                        if (sql_cartesin_one_group_set(stmt, group_sets, group_set, new_grp_sets) != OG_SUCCESS) {
                            parser_yyerror("cartesin group set failed.");
                        }
                    }
                    $$ = new_grp_sets;
                }
        ;

group_clause:
            GROUP_P BY group_by_list                        { $$ = $3; }
            | GROUP_P BY '(' group_by_list ')'              { $$ = $4; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

having_clause:
            HAVING cond_tree_expr                           { $$ = $2; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

simple_select:
        SELECT hint_string opt_found_rows opt_distinct opt_target_list from_clause
        select_pivot_clause where_clause start_with_clause group_clause having_clause
        opt_siblings_clause
            {
                sql_select_t *select_ctx = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_build_select_context(stmt, &select_ctx, $5, $6, @1.loc, @6.loc) != OG_SUCCESS) {
                    parser_yyerror("build select context failed");
                }
                if ($2) {
                    og_get_hint_info(stmt, $2, &select_ctx->first_query->hint_info);
                }
                select_ctx->calc_found_rows = select_ctx->first_query->calc_found_rows = $3;
                select_ctx->first_query->has_distinct = $4;

                if (sql_parse_pivot_clause_list(stmt, select_ctx->first_query, $7) != OG_SUCCESS) {
                    parser_yyerror("create pivot subselect failed");
                }

                select_ctx->first_query->cond = $8;

                if ($9) {
                    select_ctx->first_query->start_with_cond = $9->start_with_cond;
                    select_ctx->first_query->connect_by_cond = $9->connect_by_cond;
                    select_ctx->first_query->connect_by_nocycle = $9->connect_by_nocycle;
                }
                if ($10 && cm_galist_copy(select_ctx->first_query->group_sets, $10) != OG_SUCCESS) {
                    parser_yyerror("parse group by failed");
                }
                select_ctx->first_query->having_cond = $11;
                if ($12) {
                    if (select_ctx->first_query->connect_by_cond == NULL ||
                        select_ctx->first_query->group_sets->count > 0 ||
                        select_ctx->first_query->having_cond != NULL) {
                        parser_yyerror("ORDER SIBLINGS BY clause not allowed here.");
                    }
                    select_ctx->first_query->order_siblings = OG_TRUE;
                    cm_galist_copy(select_ctx->first_query->sort_items, $12);
                }
                if (attach_pending_subselects_to_query(select_ctx->first_query,
                    &og_yyget_extra(yyscanner)->core_yy_extra.ssa) != OG_SUCCESS) {
                    parser_yyerror("attach subselects failed");
                }
                $$ = select_ctx;
            }
        | select_clause UNION opt_all select_clause
            {
                sql_select_t *select_ctx = NULL;
                if (sql_build_set_select_context(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &select_ctx,
                    $1, $4, $3 ? SELECT_NODE_UNION_ALL : SELECT_NODE_UNION) != OG_SUCCESS) {
                    parser_yyerror("build set query failed");
                }
                $$ = select_ctx;
            }
        | select_clause INTERSECT_P opt_all_distinct select_clause
            {
                sql_select_t *select_ctx = NULL;
                if (sql_build_set_select_context(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &select_ctx,
                    $1, $4, $3 ? SELECT_NODE_INTERSECT_ALL : SELECT_NODE_INTERSECT) != OG_SUCCESS) {
                    parser_yyerror("build set query failed");
                }
                $$ = select_ctx;
            }
        | select_clause EXCEPT opt_all_distinct select_clause
            {
                sql_select_t *select_ctx = NULL;
                if (sql_build_set_select_context(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &select_ctx,
                    $1, $4, $3 ? SELECT_NODE_EXCEPT_ALL : SELECT_NODE_EXCEPT) != OG_SUCCESS) {
                    parser_yyerror("build set query failed");
                }
                $$ = select_ctx;
            }
        | select_clause MINUS_P select_clause
            {
                sql_select_t *select_ctx = NULL;
                if (sql_build_set_select_context(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &select_ctx,
                    $1, $3, SELECT_NODE_MINUS) != OG_SUCCESS) {
                    parser_yyerror("build set query failed");
                }
                $$ = select_ctx;
            }
    ;

opt_all:
            ALL                         { $$ = true; }
            | /* EMPTY */               { $$ = false; }

opt_all_distinct:
            opt_all                     { $$ = $1; }
            | DISTINCT                  { $$ = false; }
        ;

opt_nocycle:
            NOCYCLE                     { $$ = true; }
            | /* EMPTY */               { $$ = false; }
        ;

start_with_clause:
            START_WITH cond_tree_expr CONNECT_BY opt_nocycle cond_tree_expr
                {
                    swcb_clause *swcb = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(swcb_clause), (void **)&swcb) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    swcb->start_with_cond = $2;
                    swcb->connect_by_cond = $5;
                    swcb->connect_by_nocycle = $4;
                    $$ = swcb;
                }
            | CONNECT_BY opt_nocycle cond_tree_expr START_WITH cond_tree_expr
                {
                    swcb_clause *swcb = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(swcb_clause), (void **)&swcb) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    swcb->start_with_cond = $5;
                    swcb->connect_by_cond = $3;
                    swcb->connect_by_nocycle = $2;
                    $$ = swcb;
                }
            | CONNECT_BY opt_nocycle cond_tree_expr
                {
                    swcb_clause *swcb = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(swcb_clause), (void **)&swcb) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    swcb->connect_by_cond = $3;
                    swcb->connect_by_nocycle = $2;
                    $$ = swcb;
                }
            | /* EMPTY */
                {
                    $$ = NULL;
                }
        ;

cond_tree_expr:     cond_node
                    {
                        cond_tree_t *cond = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        if (sql_create_cond_tree(stmt->context, &cond) != OG_SUCCESS) {
                            parser_yyerror("alloc cond tree failed");
                        }
                        sql_add_cond_node(cond, $1);
                        $$ = cond;
                    }
            ;

cond_node:
            a_expr %prec UMINUS
            {
                cond_node_t *node = NULL;
                if (sql_expr_tree_to_cond_node(og_yyget_extra(yyscanner)->core_yy_extra.stmt, $1, &node) != OG_SUCCESS) {
                    parser_yyerror("transform expr tree to cond node failed");
                }
                $$ = node;
            }
            | '(' cond_node ')'
            {
                $$ = $2;
            }
            | NOT cond_node
            {
                cond_node_t *node = $2;
                if (sql_conver_not_node(og_yyget_extra(yyscanner)->core_yy_extra.stmt, node) != OG_SUCCESS) {
                    parser_yyerror("convert not cond failed");
                }
                $$ = node;
            }
            | cond_node AND cond_node
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_AND;
                node->left = $1;
                node->right = $3;
                $$ = node;
            }
            | cond_node OR cond_node
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_OR;
                node->left = $1;
                node->right = $3;
                $$ = node;
            }
            | expr_with_select '=' expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_EQUAL;
                node->cmp->left = $1;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select '>' expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_GREAT;
                node->cmp->left = $1;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select '<' expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_LESS;
                node->cmp->left = $1;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select CmpOp expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                if (strcmp($2, "<>") == 0) {
                    node->cmp->type = CMP_TYPE_NOT_EQUAL;
                } else if (strcmp($2, ">=") == 0) {
                    node->cmp->type = CMP_TYPE_GREAT_EQUAL;
                } else if (strcmp($2, "<=") == 0) {
                    node->cmp->type = CMP_TYPE_LESS_EQUAL;
                } else if (strcmp($2, "<=>") == 0) {
                    node->cmp->type = CMP_TYPE_NULL_CMP_OP;
                }

                node->cmp->left = $1;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select '=' sub_type select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_EQUAL_ANY : CMP_TYPE_EQUAL_ALL;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select '=' sub_type '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_EQUAL_ANY : CMP_TYPE_EQUAL_ALL;
                node->cmp->left = $1;
                node->cmp->right = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select '>' sub_type select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_GREAT_ANY : CMP_TYPE_GREAT_ALL;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select '>' sub_type '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_GREAT_ANY : CMP_TYPE_GREAT_ALL;
                node->cmp->left = $1;
                node->cmp->right = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select '<' sub_type select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_LESS_ANY : CMP_TYPE_LESS_ALL;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select '<' sub_type '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = $3 ? CMP_TYPE_LESS_ANY : CMP_TYPE_LESS_ALL;
                node->cmp->left = $1;
                node->cmp->right = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select CmpOp sub_type select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                if (strcmp($2, "<>") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_NOT_EQUAL_ANY : CMP_TYPE_NOT_EQUAL_ALL;
                } else if (strcmp($2, ">=") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_GREAT_EQUAL_ANY : CMP_TYPE_GREAT_EQUAL_ALL;
                } else if (strcmp($2, "<=") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_LESS_EQUAL_ANY : CMP_TYPE_LESS_EQUAL_ALL;
                } else if (strcmp($2, "<=>") == 0) {
                    node->cmp->type = CMP_TYPE_NULL_CMP_OP;
                }

                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select CmpOp sub_type '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                if (strcmp($2, "<>") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_NOT_EQUAL_ANY : CMP_TYPE_NOT_EQUAL_ALL;
                } else if (strcmp($2, ">=") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_GREAT_EQUAL_ANY : CMP_TYPE_GREAT_EQUAL_ALL;
                } else if (strcmp($2, "<=") == 0) {
                    node->cmp->type = $3 ? CMP_TYPE_LESS_EQUAL_ANY : CMP_TYPE_LESS_EQUAL_ALL;
                } else if (strcmp($2, "<=>") == 0) {
                    node->cmp->type = CMP_TYPE_NULL_CMP_OP;
                }

                node->cmp->left = $1;
                node->cmp->right = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select IN_P select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IN;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $3, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @3.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select IN_P '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IN;
                node->cmp->left = $1;
                node->cmp->right = $4;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | implicit_row IN_P select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IN;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $3, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @3.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | implicit_row IN_P '(' expr_list_with_select_rows ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IN;
                node->cmp->left = $1;
                if (!check_in_rows_match($4, sql_expr_list_len($1), &node->cmp->right)) {
                    parser_yyerror("not enough values");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select NOT IN_P select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_IN;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select NOT IN_P '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_IN;
                node->cmp->left = $1;
                node->cmp->right = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | implicit_row NOT IN_P select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_IN;
                node->cmp->left = $1;
                if (sql_create_select_expr(stmt, &node->cmp->right, $4, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @4.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | implicit_row NOT IN_P '(' expr_list_with_select_rows ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_IN;
                node->cmp->left = $1;
                if (!check_in_rows_match($5, sql_expr_list_len($1), &node->cmp->right)) {
                    parser_yyerror("not enough values");
                }
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | expr_with_select IS NULL_P
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IS_NULL;
                node->cmp->left = $1;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select IS NOT NULL_P
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IS_NOT_NULL;
                node->cmp->left = $1;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select IS JSON
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IS_JSON;
                node->cmp->left = $1;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select IS NOT JSON
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_IS_NOT_JSON;
                node->cmp->left = $1;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select LIKE expr_with_select opt_escape
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_LIKE;
                node->cmp->left = $1;
                node->cmp->right = $3;
                node->cmp->right->next = $4;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select NOT LIKE expr_with_select opt_escape
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_LIKE;
                node->cmp->left = $1;
                node->cmp->right = $4;
                node->cmp->right->next = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select REGEXP expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_REGEXP;
                node->cmp->left = $1;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select NOT REGEXP expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_REGEXP;
                node->cmp->left = $1;
                node->cmp->right = $4;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select BETWEEN expr_with_select AND expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_BETWEEN;
                node->cmp->left = $1;
                node->cmp->right = $3;
                node->cmp->right->next = $5;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | expr_with_select NOT BETWEEN expr_with_select AND expr_with_select
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_NOT_BETWEEN;
                node->cmp->left = $1;
                node->cmp->right = $4;
                node->cmp->right->next = $6;
                fix_type_for_select_node(node->cmp->left, SELECT_AS_VARIANT);
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
            | EXISTS select_with_parens
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_EXISTS;
                if (sql_create_select_expr(stmt, &node->cmp->right, $2, &og_yyget_extra(yyscanner)->core_yy_extra.ssa,
                    @2.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                fix_type_for_select_node(node->cmp->right, SELECT_AS_LIST);
                $$ = node;
            }
            | REGEXP_LIKE '(' expr_list_with_select ')'
            {
                cond_node_t *node = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&node) != OG_SUCCESS) {
                    parser_yyerror("alloc cond node failed");
                }
                node->type = COND_NODE_COMPARE;
                if (sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&node->cmp) != OG_SUCCESS) {
                    parser_yyerror("alloc cmp node failed");
                }
                node->cmp->type = CMP_TYPE_REGEXP_LIKE;
                node->cmp->right = $3;
                fix_type_for_select_node(node->cmp->right, SELECT_AS_VARIANT);
                $$ = node;
            }
        ;

sub_type:   ANY                                     { $$ = true; }
            | SOME                                  { $$ = true; }
            | ALL                                   { $$ = false; }
        ;

implicit_row:	'(' expr_list_with_select ',' expr_with_select ')'
            {
                expr_tree_t *expr = $2;
                expr_tree_t **temp = &expr->next;
                while (*temp != NULL) {
                    temp = &(*temp)->next;
                }
                *temp = $4;
                $$ = expr;
            }
        ;

expr_list_with_select_rows:
        expr_list_with_select_row
            {
                galist_t *list = NULL;
                if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                    parser_yyerror("create expr list failed.");
                }
                cm_galist_insert(list, $1);
                $$ = list;
            }
        | expr_list_with_select_rows ',' expr_list_with_select_row
            {
                galist_t *list = $1;
                cm_galist_insert(list, $3);
                $$ = list;
            }
        ;

expr_list_with_select_row: '(' expr_list_with_select ')'                { $$ = $2; }
        ;

expr_list_with_select:
        expr_with_select
            {
                $$ = $1;
            }
        | expr_list_with_select ',' expr_with_select
            {
                expr_tree_t *expr = $1;
                expr_tree_t **temp = &expr->next;
                while (*temp != NULL) {
                    temp = &(*temp)->next;
                }
                *temp = $3;
                $$ = expr;
            }
        ;

expr_with_select:
        a_expr
            {
                $$ = $1;
            }
        ;

opt_escape:
        ESCAPE SCONST
            {
                expr_tree_t *escape_expr = NULL;
                if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &escape_expr, $2, @2.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                variant_t *escape_var = &escape_expr->root->value;
                char escape_char;
                if (lex_check_asciichar(&escape_var->v_text, &(@2.loc), &escape_char, OG_FALSE) != OG_SUCCESS) {
                    parser_yyerror("invalid escape character");
                }
                escape_var->v_text.str[0] = escape_char;
                escape_var->v_text.len = 1;
                $$ = escape_expr;

            }
        | ESCAPE PARAM
            {
                expr_tree_t *expr = NULL;
                if (sql_create_paramref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &expr, $2, @2) != OG_SUCCESS) {
                    parser_yyerror("init paramref expr failed");
                }
                $$ = expr;
            }
        | /* EMPTY */                       { $$ = NULL; }
        ;

where_clause:
            WHERE cond_tree_expr
                {
                    $$ = $2;
                }
            | /*EMPTY*/                         { $$ = NULL; }
        ;

DeleteStmt: DELETE_P hint_string FROM delete_target_list using_clause where_clause opt_sort_clause opt_limit return_clause
            {
                sql_delete_t *delete_ctx = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(sql_delete_t), (void **)&delete_ctx) != OG_SUCCESS) {
                    parser_yyerror("alloc delete context failed");
                }
                if ($2) {
                    og_get_hint_info(stmt, $2, &delete_ctx->hint_info);
                }

                sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&delete_ctx->query);
                sql_init_query(stmt, NULL, @1.loc, delete_ctx->query);
                sql_copy_str(stmt->context, "DEL$1", &delete_ctx->query->block_info->origin_name);
                delete_ctx->plan = NULL;
                delete_ctx->ret_columns = NULL;
                delete_ctx->hint_info = NULL;

                delete_ctx->objects = $4;
                sql_join_node_t *join_node = $5;
                if (delete_ctx->objects->count > 1 && join_node == NULL) {
                    parser_yyerror("USING expected");
                }

                if (join_node != NULL) {
                    sql_array_concat(&delete_ctx->query->tables, &join_node->tables);
                    if (join_node->type != JOIN_TYPE_NONE) {
                        delete_ctx->query->join_assist.join_node = join_node;
                        delete_ctx->query->join_assist.outer_node_count = sql_outer_join_count(join_node);
                        if (delete_ctx->query->join_assist.outer_node_count > 0) {
                            sql_parse_join_set_table_nullable(delete_ctx->query->join_assist.join_node);
                        }
                        sql_remove_join_table(stmt, delete_ctx->query);
                    }
                } else {
                    sql_array_put(&delete_ctx->query->tables, ((del_object_t *)cm_galist_get(delete_ctx->objects, 0))->table);
                }

                if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                    if (attach_pending_subselects_to_query(delete_ctx->query,
                        &og_yyget_extra(yyscanner)->core_yy_extra.ssa) != OG_SUCCESS) {
                        parser_yyerror("attach subselects failed");
                    }
                }

                delete_ctx->query->cond = $6;

                if (delete_ctx->query->tables.count > 1 && $7 != NULL) {
                    parser_yyerror("multi delete do not support order by");
                }
                if ($7 != NULL) {
                    cm_galist_copy(delete_ctx->query->sort_items, $7);
                }

                if (delete_ctx->query->tables.count > 1 && $8 != NULL) {
                    parser_yyerror("multi delete do not support limit");
                }
                if ($8) {
                    delete_ctx->query->limit.count = $8->count;
                    delete_ctx->query->limit.offset = $8->offset;
                }

                delete_ctx->ret_columns = $9;
                if (sql_set_table_qb_name(stmt, delete_ctx->query) != OG_SUCCESS) {
                    parser_yyerror("sql_set_table_qb_name failed ");
                }
                $$ = delete_ctx;
            }
            | DELETE_P hint_string delete_target_list from_clause where_clause opt_sort_clause opt_limit return_clause
            {
                sql_delete_t *delete_ctx = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(sql_delete_t), (void **)&delete_ctx) != OG_SUCCESS) {
                    parser_yyerror("alloc delete context failed");
                }
                if ($2) {
                    og_get_hint_info(stmt, $2, &delete_ctx->hint_info);
                }

                sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&delete_ctx->query);
                sql_init_query(stmt, NULL, @1.loc, delete_ctx->query);
                sql_copy_str(stmt->context, "DEL$1", &delete_ctx->query->block_info->origin_name);
                delete_ctx->plan = NULL;
                delete_ctx->ret_columns = NULL;
                delete_ctx->hint_info = NULL;

                delete_ctx->objects = $3;
                sql_join_node_t *join_node = $4;
                if (delete_ctx->objects->count > 1 && join_node == NULL) {
                    parser_yyerror("FROM expected");
                }

                if (join_node != NULL) {
                    sql_array_concat(&delete_ctx->query->tables, &join_node->tables);
                    if (join_node->type != JOIN_TYPE_NONE) {
                        delete_ctx->query->join_assist.join_node = join_node;
                        delete_ctx->query->join_assist.outer_node_count = sql_outer_join_count(join_node);
                        if (delete_ctx->query->join_assist.outer_node_count > 0) {
                            sql_parse_join_set_table_nullable(delete_ctx->query->join_assist.join_node);
                        }
                        sql_remove_join_table(stmt, delete_ctx->query);
                    }
                } else {
                    sql_array_put(&delete_ctx->query->tables, ((del_object_t *)cm_galist_get(delete_ctx->objects, 0))->table);
                }

                if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                    if (attach_pending_subselects_to_query(delete_ctx->query,
                        &og_yyget_extra(yyscanner)->core_yy_extra.ssa) != OG_SUCCESS) {
                        parser_yyerror("attach subselects failed");
                    }
                }

                delete_ctx->query->cond = $5;
                if (delete_ctx->query->tables.count > 1 && $6 != NULL) {
                    parser_yyerror("multi delete do not support order by");
                }
                if ($6 != NULL) {
                    cm_galist_copy(delete_ctx->query->sort_items, $6);
                }

                if (delete_ctx->query->tables.count > 1 && $7 != NULL) {
                    parser_yyerror("multi delete do not support limit");
                }

                if ($7) {
                    delete_ctx->query->limit.count = $7->count;
                    delete_ctx->query->limit.offset = $7->offset;
                }

                delete_ctx->ret_columns = $8;
                if (sql_set_table_qb_name(stmt, delete_ctx->query) != OG_SUCCESS) {
                    parser_yyerror("sql_set_table_qb_name failed ");
                }
                $$ = delete_ctx;
            }
    ;

delete_target_list:
        delete_target
        {
            galist_t *list = NULL;
            if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                parser_yyerror("create delete objects failed");
            }
            cm_galist_insert(list, $1);
            $$ = list;

        }
        | delete_target_list ',' delete_target
        {
            galist_t *list = $1;
            del_object_t *delete_obj = $3;
            del_object_t *prev_obj = NULL;
            for (uint32 i = 0; i < list->count; i++) {
                prev_obj = (del_object_t *)cm_galist_get(list, i);
                if (cm_text_equal((text_t *)&prev_obj->user, (text_t *)&delete_obj->user) &&
                    cm_text_equal((text_t *)&prev_obj->name, (text_t *)&delete_obj->name)) {
                    parser_yyerror("duplicated object found");
                }
            }
            cm_galist_insert(list, delete_obj);
            $$ = list;
        }
    ;

delete_target:
        insert_target
        {
            sql_table_t *table = $1;
            del_object_t *delete_obj = NULL;
            if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(del_object_t), (void **)&delete_obj) != OG_SUCCESS) {
                parser_yyerror("alloc delete obj failed");
            }

            delete_obj->user = table->user;
            delete_obj->name = table->name;
            delete_obj->alias = table->alias;
            delete_obj->table = table;
            $$ = delete_obj;
        }
    ;

/*****************************************************************************
 *
 *    target list for SELECT
 *
 *****************************************************************************/

opt_target_list: target_list                         { $$ = $1; }
        ;

target_list:
            target_el
                {
                    galist_t* t_list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &t_list) != OG_SUCCESS) {
                        parser_yyerror("create target list failed.");
                    }
                    if (cm_galist_insert(t_list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert target list failed.");
                    }
                    $$ = t_list;
                }
            | target_list ',' target_el
                {
                    galist_t* t_list = $1;
                    if (cm_galist_insert(t_list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert target list failed.");
                    }
                    $$ = t_list;
                }
        ;

target_el:  a_expr AS ColLabel
            {
                query_column_t *query_column = NULL;
                if (sql_create_target_entry(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &query_column, $1, $3, strlen($3), false) != OG_SUCCESS) {
                    parser_yyerror("create target entry failed.");
                }
                $$ = query_column;
            }
            | a_expr IDENT
            {
                query_column_t *query_column = NULL;
                if (sql_create_target_entry(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &query_column, $1, $2, strlen($2), false) != OG_SUCCESS) {
                    parser_yyerror("create target entry failed.");
                }
                $$ = query_column;
            }
            | a_expr
            {
                uint32 alias_len = yylloc.offset == @1.offset ? 1 : yylloc.offset - @1.offset;
                query_column_t *query_column = NULL;
                if (sql_create_target_entry(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &query_column, $1, og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @1.offset,
                    alias_len, true) != OG_SUCCESS) {
                    parser_yyerror("create target entry failed.");
                }
                $$ = query_column;
            }
            | '*'
            {
                expr_tree_t *expr = NULL;
                query_column_t *query_column = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_create_star_expr(stmt, &expr, @1) != OG_SUCCESS) {
                    parser_yyerror("create star expr failed.");
                }
                if (sql_alloc_mem(stmt->context, sizeof(query_column_t), (void **)&query_column) != OG_SUCCESS) {
                    parser_yyerror("create target entry failed.");
                }
                query_column->expr = expr;
                $$ = query_column;
            }
        ;

/*****************************************************************************
 *
 *    clauses common to all Optimizable Stmts:
 *        from_clause        - allow list of both JOIN expressions and table names
 *        where_clause    - qualifications for joins or restrictions
 *
 *****************************************************************************/

from_clause:
            FROM from_list
                {
                    $$ = $2;
                }
            | /*EMPTY*/
                {
                    $$ = NULL;
                }
        ;
using_clause:
                USING from_list
                {
                    $$ = $2;
                }
            | /*EMPTY*/                         { $$ = NULL; }
        ;

from_list:
            table_ref
                {
                    $$ = $1;
                }
            | from_list ',' table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_COMMA, NULL, NULL, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
        ;

/*
 * table_ref is where an alias clause can be attached.
 */
table_ref:
            relation_expr           %prec UMINUS
                {
                    sql_table_t *table = $1;
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr alias_clause
                {
                    sql_table_t *table = $1;
                    table->alias.value.str = $2;
                    table->alias.value.len = strlen($2);

                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr PARTITION '(' ColId ')'
                {
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_FALSE;
                    table->part_info.type = SPECIFY_PART_NAME;
                    table->part_info.part_name.str = $4;
                    table->part_info.part_name.len = strlen($4);

                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr PARTITION '(' ColId ')' alias_clause
                {
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_FALSE;
                    table->part_info.type = SPECIFY_PART_NAME;
                    table->part_info.part_name.str = $4;
                    table->part_info.part_name.len = strlen($4);
                    table->alias.value.str = $6;
                    table->alias.value.len = strlen($6);

                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr SUBPARTITION '(' ColId ')'
                {
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_TRUE;
                    table->part_info.type = SPECIFY_PART_NAME;
                    table->part_info.part_name.str = $4;
                    table->part_info.part_name.len = strlen($4);

                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr SUBPARTITION '(' ColId ')' alias_clause
                {
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_TRUE;
                    table->part_info.type = SPECIFY_PART_NAME;
                    table->part_info.part_name.str = $4;
                    table->part_info.part_name.len = strlen($4);
                    table->alias.value.str = $6;
                    table->alias.value.len = strlen($6);

                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr PARTITION_FOR '(' expr_list_with_select ')'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_FALSE;
                    table->part_info.type = SPECIFY_PART_VALUE;
                    convert_expr_tree_to_galist(stmt, $4, &table->part_info.values);

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr PARTITION_FOR '(' expr_list_with_select ')' alias_clause
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_FALSE;
                    table->part_info.type = SPECIFY_PART_VALUE;
                    convert_expr_tree_to_galist(stmt, $4, &table->part_info.values);
                    table->alias.value.str = $6;
                    table->alias.value.len = strlen($6);

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr SUBPARTITION_FOR '(' expr_list_with_select ')'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_TRUE;
                    table->part_info.type = SPECIFY_PART_VALUE;
                    convert_expr_tree_to_galist(stmt, $4, &table->part_info.values);

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | relation_expr SUBPARTITION_FOR '(' expr_list_with_select ')' alias_clause
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_table_t *table = $1;
                    table->part_info.is_subpart = OG_TRUE;
                    table->part_info.type = SPECIFY_PART_VALUE;
                    convert_expr_tree_to_galist(stmt, $4, &table->part_info.values);
                    table->alias.value.str = $6;
                    table->alias.value.len = strlen($6);

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | joined_table
                {
                    $$ = $1;
                }
            | select_with_parens                %prec UMINUS
                {
                    sql_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);
                    text_t curr_schema;
                    cm_str2text(stmt->session->curr_schema, &curr_schema);
                    table->user.value = curr_schema;
                    table->user.loc = @1.loc;
                    table->type = SUBSELECT_AS_TABLE;
                    table->select_ctx = $1;
                    table->select_ctx->first_query->owner->type = SELECT_AS_TABLE;

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | select_with_parens alias_clause
                {
                    sql_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);
                    text_t curr_schema;
                    cm_str2text(stmt->session->curr_schema, &curr_schema);
                    table->user.value = curr_schema;
                    table->user.loc = @1.loc;
                    table->type = SUBSELECT_AS_TABLE;
                    table->select_ctx = $1;
                    table->select_ctx->first_query->owner->type = SELECT_AS_TABLE;
                    table->alias.value.str = $2;
                    table->alias.value.len = strlen($2);

                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_func                %prec UMINUS
                {
                    sql_table_t *table = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_func alias_clause
                {
                    sql_table_t *table = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    table->alias.value.str = $2;
                    table->alias.value.len = strlen($2);
                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | json_table                %prec UMINUS
                {
                    sql_table_t *table = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | json_table alias_clause
                {
                    sql_table_t *table = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    table->alias.value.str = $2;
                    table->alias.value.len = strlen($2);
                    sql_join_node_t *join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                } 
        ;   

table_func:  TABLE_P '(' func_name '(' expr_list_with_select ')' ')'
            {
                sql_table_t *table = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);
                galist_t *func_name = $3;
                var_word_t word;
                if (sql_expr_list_as_func(stmt, func_name, &word) != OG_SUCCESS) {
                    parser_yyerror("parse function name failed.");
                }
                table->func.user = word.func.user.value;
                table->func.package = word.func.pack.value;
                table->func.name = word.func.name.value;
                if (table->func.user.len == 0) {
                    text_t schema;
                    cm_str2text(stmt->session->curr_schema, &schema);
                    table->func.user = schema;
                }
                table->func.args = $5;
                table->user.value.str = stmt->session->curr_schema;
                table->user.value.len = (uint32)strlen(stmt->session->curr_schema);
                table->user.loc = @1.loc;
                table->type = FUNC_AS_TABLE;
                $$ = table;
            }
            | TABLE_P '(' CAST '(' expr_with_select AS Typename ')' ')'
            {
                sql_table_t *table = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table);
                table->func.name.str = "cast";
                table->func.name.len = 4;
                text_t schema;
                cm_str2text(stmt->session->curr_schema, &schema);
                table->func.user = schema;

                table->func.args = $5;
                if (sql_parse_table_cast_type(stmt, &table->func.args->next, $7->str, @7.loc) != OG_SUCCESS) {
                    parser_yyerror("parse type name failed.");
                }
                table->user.value.str = stmt->session->curr_schema;
                table->user.value.len = (uint32)strlen(stmt->session->curr_schema);
                table->user.loc = @1.loc;
                table->type = FUNC_AS_TABLE;
                $$ = table;
            }
        ;

format_json: FORMAT JSON                            { $$ = true; }
            | /* EMPTY */                           { $$ = false; }
        ;

json_on_error_or_null:
            ERROR_ON_ERROR_P                                 { $$ = true; }
            | NULL_ON_ERROR_P                                { $$ = false; }
        ;

format_json_attr:
            WITH WRAPPER                            { $$ = JSON_FUNC_ATT_WITH_WRAPPER; }
            | WITHOUT ARRAY WRAPPER                 { $$ = JSON_FUNC_ATT_WITHOUT_WRAPPER; }
            | WITHOUT WRAPPER                       { $$ = JSON_FUNC_ATT_WITHOUT_WRAPPER; }
        ;

json_table_column_error:
            EXISTS
            {
                $$ = "JSON_EXISTS";
            }
            | format_json format_json_attr
            {
                $$ = "JSON_QUERY";
            }
            | /* EMPTY */
            {
                $$ = "JSON_VALUE";
            }
        ;

json_column:
            insert_column_item FOR ORDINALITY
            {
                rs_column_t *new_col = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(rs_column_t), (void **)&new_col) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_create_expr(stmt, &new_col->expr) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                column_parse_info *column_info = $1;
                new_col->expr->root->word.column.user.value = column_info->owner;
                new_col->expr->root->word.column.table.value = column_info->table;
                new_col->expr->root->word.column.name.value = column_info->col_name;

                new_col->name = new_col->expr->root->word.column.name.value;
                new_col->type = RS_COL_CALC;
                OG_BIT_SET(new_col->rs_flag, RS_NULLABLE);

                new_col->expr->loc = @1.loc;
                new_col->expr->root->owner = new_col->expr;
                new_col->expr->root->loc = @1.loc;
                new_col->expr->root->dis_info.need_distinct = OG_FALSE;
                new_col->expr->root->dis_info.idx = OG_INVALID_ID32;
                new_col->expr->root->format_json = OG_FALSE;
                new_col->expr->root->json_func_attr = (json_func_attr_t) { 0, 0 };
                new_col->expr->root->typmod.is_array = OG_FALSE;

                new_col->expr->root->type = EXPR_NODE_CONST;
                new_col->expr->root->value.type = OG_TYPE_BIGINT;
                new_col->expr->root->value.v_bigint = 0;
                new_col->expr->root->value.is_null = OG_FALSE;

                $$ = new_col;
            }
            | insert_column_item CLOB json_table_column_error PATH SCONST json_on_error
            {
                rs_column_t *new_col = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(rs_column_t), (void **)&new_col) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_create_expr(stmt, &new_col->expr) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                column_parse_info *column_info = $1;
                new_col->expr->root->word.column.user.value = column_info->owner;
                new_col->expr->root->word.column.table.value = column_info->table;
                new_col->expr->root->word.column.name.value = column_info->col_name;

                new_col->name = new_col->expr->root->word.column.name.value;
                new_col->type = RS_COL_CALC;
                OG_BIT_SET(new_col->rs_flag, RS_NULLABLE);

                new_col->expr->loc = @1.loc;
                new_col->expr->root->owner = new_col->expr;
                new_col->expr->root->loc = @1.loc;
                new_col->expr->root->dis_info.need_distinct = OG_FALSE;
                new_col->expr->root->dis_info.idx = OG_INVALID_ID32;
                new_col->expr->root->format_json = OG_FALSE;
                new_col->expr->root->json_func_attr = (json_func_attr_t) { 0, 0 };
                new_col->expr->root->typmod.is_array = OG_FALSE;

                expr_node_t *func_node = new_col->expr->root;
                func_node->type = EXPR_NODE_FUNC;
                func_node->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_CLOB;
                func_node->word.func.name.value.str = $3;
                func_node->word.func.name.value.len = strlen($3);

                if (sql_create_expr(stmt, &func_node->argument) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&func_node->argument->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                func_node->argument->root->value.type = OG_TYPE_INTEGER;
                func_node->argument->root->value.v_int = 0;
                func_node->argument->root->value.is_null = OG_FALSE;
                func_node->argument->root->type = EXPR_NODE_CONST;
                if (sql_create_expr(stmt, &func_node->argument->next) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root->argument->next->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                expr_node_t *path_node = new_col->expr->root->argument->next->root;
                path_node->type = EXPR_NODE_CONST;
                path_node->value.type = OG_TYPE_STRING;

                char *path = $5;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                path_node->value.v_text.str = path;
                path_node->value.v_text.len = len;

                func_node->json_func_attr.ids |= $6;
                $$ = new_col;
            }
            | insert_column_item JSONB json_table_column_error PATH SCONST json_on_error
            {
                rs_column_t *new_col = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(rs_column_t), (void **)&new_col) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_create_expr(stmt, &new_col->expr) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                column_parse_info *column_info = $1;
                new_col->expr->root->word.column.user.value = column_info->owner;
                new_col->expr->root->word.column.table.value = column_info->table;
                new_col->expr->root->word.column.name.value = column_info->col_name;

                new_col->name = new_col->expr->root->word.column.name.value;
                new_col->type = RS_COL_CALC;
                OG_BIT_SET(new_col->rs_flag, RS_NULLABLE);

                new_col->expr->loc = @1.loc;
                new_col->expr->root->owner = new_col->expr;
                new_col->expr->root->loc = @1.loc;
                new_col->expr->root->dis_info.need_distinct = OG_FALSE;
                new_col->expr->root->dis_info.idx = OG_INVALID_ID32;
                new_col->expr->root->format_json = OG_FALSE;
                new_col->expr->root->json_func_attr = (json_func_attr_t) { 0, 0 };
                new_col->expr->root->typmod.is_array = OG_FALSE;

                expr_node_t *func_node = new_col->expr->root;
                func_node->type = EXPR_NODE_FUNC;
                func_node->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_JSONB;
                func_node->word.func.name.value.str = $3;
                func_node->word.func.name.value.len = strlen($3);

                if (sql_create_expr(stmt, &func_node->argument) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&func_node->argument->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                func_node->argument->root->value.type = OG_TYPE_INTEGER;
                func_node->argument->root->value.v_int = 0;
                func_node->argument->root->value.is_null = OG_FALSE;
                func_node->argument->root->type = EXPR_NODE_CONST;
                if (sql_create_expr(stmt, &func_node->argument->next) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root->argument->next->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                expr_node_t *path_node = new_col->expr->root->argument->next->root;
                path_node->type = EXPR_NODE_CONST;
                path_node->value.type = OG_TYPE_STRING;

                char *path = $5;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                path_node->value.v_text.str = path;
                path_node->value.v_text.len = len;

                func_node->json_func_attr.ids |= $6;
                $$ = new_col;
            }
            | insert_column_item VARCHAR2 json_table_column_error PATH SCONST json_on_error
            {
                rs_column_t *new_col = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(rs_column_t), (void **)&new_col) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_create_expr(stmt, &new_col->expr) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                column_parse_info *column_info = $1;
                new_col->expr->root->word.column.user.value = column_info->owner;
                new_col->expr->root->word.column.table.value = column_info->table;
                new_col->expr->root->word.column.name.value = column_info->col_name;

                new_col->name = new_col->expr->root->word.column.name.value;
                new_col->type = RS_COL_CALC;
                OG_BIT_SET(new_col->rs_flag, RS_NULLABLE);

                new_col->expr->loc = @1.loc;
                new_col->expr->root->owner = new_col->expr;
                new_col->expr->root->loc = @1.loc;
                new_col->expr->root->dis_info.need_distinct = OG_FALSE;
                new_col->expr->root->dis_info.idx = OG_INVALID_ID32;
                new_col->expr->root->format_json = OG_FALSE;
                new_col->expr->root->json_func_attr = (json_func_attr_t) { 0, 0 };
                new_col->expr->root->typmod.is_array = OG_FALSE;

                expr_node_t *func_node = new_col->expr->root;
                func_node->type = EXPR_NODE_FUNC;
                func_node->json_func_attr.return_size = JSON_FUNC_LEN_DEFAULT;
                func_node->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
                func_node->word.func.name.value.str = $3;
                func_node->word.func.name.value.len = strlen($3);

                if (sql_create_expr(stmt, &func_node->argument) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&func_node->argument->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                func_node->argument->root->value.type = OG_TYPE_INTEGER;
                func_node->argument->root->value.v_int = 0;
                func_node->argument->root->value.is_null = OG_FALSE;
                func_node->argument->root->type = EXPR_NODE_CONST;
                if (sql_create_expr(stmt, &func_node->argument->next) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root->argument->next->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                expr_node_t *path_node = new_col->expr->root->argument->next->root;
                path_node->type = EXPR_NODE_CONST;
                path_node->value.type = OG_TYPE_STRING;

                char *path = $5;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                path_node->value.v_text.str = path;
                path_node->value.v_text.len = len;

                func_node->json_func_attr.ids |= $6;
                $$ = new_col;
            }
            | insert_column_item VARCHAR2 '(' ICONST ')' json_table_column_error PATH SCONST json_on_error
            {
                rs_column_t *new_col = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(rs_column_t), (void **)&new_col) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_create_expr(stmt, &new_col->expr) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                column_parse_info *column_info = $1;
                new_col->expr->root->word.column.user.value = column_info->owner;
                new_col->expr->root->word.column.table.value = column_info->table;
                new_col->expr->root->word.column.name.value = column_info->col_name;

                new_col->name = new_col->expr->root->word.column.name.value;
                new_col->type = RS_COL_CALC;
                OG_BIT_SET(new_col->rs_flag, RS_NULLABLE);

                new_col->expr->loc = @1.loc;
                new_col->expr->root->owner = new_col->expr;
                new_col->expr->root->loc = @1.loc;
                new_col->expr->root->dis_info.need_distinct = OG_FALSE;
                new_col->expr->root->dis_info.idx = OG_INVALID_ID32;
                new_col->expr->root->format_json = OG_FALSE;
                new_col->expr->root->json_func_attr = (json_func_attr_t) { 0, 0 };
                new_col->expr->root->typmod.is_array = OG_FALSE;

                expr_node_t *func_node = new_col->expr->root;
                func_node->type = EXPR_NODE_FUNC;
                if ($4 <= 0 || $4 > JSON_MAX_STRING_LEN) {
                    parser_yyerror("specified length invalid for its datatype");
                }
                func_node->json_func_attr.return_size = $4;
                func_node->json_func_attr.ids |= JSON_FUNC_ATT_RETURNING_VARCHAR2;
                func_node->word.func.name.value.str = $6;
                func_node->word.func.name.value.len = strlen($6);

                if (sql_create_expr(stmt, &func_node->argument) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&func_node->argument->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                func_node->argument->root->value.type = OG_TYPE_INTEGER;
                func_node->argument->root->value.v_int = 0;
                func_node->argument->root->value.is_null = OG_FALSE;
                func_node->argument->root->type = EXPR_NODE_CONST;
                if (sql_create_expr(stmt, &func_node->argument->next) != OG_SUCCESS) {
                    parser_yyerror("create expr failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&new_col->expr->root->argument->next->root) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                expr_node_t *path_node = new_col->expr->root->argument->next->root;
                path_node->type = EXPR_NODE_CONST;
                path_node->value.type = OG_TYPE_STRING;

                char *path = $8;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                path_node->value.v_text.str = path;
                path_node->value.v_text.len = len;

                func_node->json_func_attr.ids |= $9;
                $$ = new_col;
            }
        ;

json_column_list:
            json_column
            {
                galist_t *list = NULL;
                if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                    parser_yyerror("create column pair list failed.");
                }
                cm_galist_insert(list, $1);
                $$ = list;
            }
            | json_column_list ',' json_column
            {
                galist_t *list = $1;
                cm_galist_insert(list, $3);
                $$ = list;
            }
        ;

jsonb_table: JSON_TABLE_P                               { $$ = false; }
            | JSONB_TABLE_P                             { $$ = true; }
        ;

json_table: jsonb_table '(' expr_with_select format_json ',' SCONST json_on_error_or_null COLUMNS '(' json_column_list ')' ')'
            {
                sql_table_t *table = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                
                if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(json_table_info_t), (void **)&table->json_table_info) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                sql_init_json_table_info(stmt, table->json_table_info);

                table->json_table_info->data_expr = $3;
                table->json_table_info->data_expr->root->format_json = $4;
                table->json_table_info->basic_path_loc = @5.loc;

                char *path = $6;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                table->json_table_info->basic_path_txt.str = path;
                table->json_table_info->basic_path_txt.len = len;
                table->json_table_info->json_error_info.type = $7 ? JSON_RETURN_ERROR : JSON_RETURN_NULL;

                cm_galist_copy(&table->json_table_info->columns, $10);
                rs_column_t *new_col = NULL;
                expr_node_t *func_node = NULL;
                for (uint32 i = 0; i < table->json_table_info->columns.count; i++) {
                    new_col = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, i);
                    func_node = new_col->expr->root;
                    if (!JSON_FUNC_ATT_HAS_ON_ERROR(func_node->json_func_attr.ids)) {
                        set_json_func_default_error_type(func_node, table->json_table_info->json_error_info.type);
                    }
                }
                table->type = JSON_TABLE;
                table->is_jsonb_table = $1;
                $$ = table;
            }
            | jsonb_table '(' expr_with_select format_json ',' SCONST DEFAULT a_expr ON ERROR_P COLUMNS '(' json_column_list ')' ')'
            {
                sql_table_t *table = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&table) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                if (sql_alloc_mem(stmt->context, sizeof(json_table_info_t), (void **)&table->json_table_info) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                sql_init_json_table_info(stmt, table->json_table_info);

                table->json_table_info->data_expr = $3;
                table->json_table_info->data_expr->root->format_json = $4;
                table->json_table_info->basic_path_loc = @5.loc;

                char *path = $6;
                size_t len = strlen(path);
                if (len > OG_SHARED_PAGE_SIZE) {
                    parser_yyerror("current json table column path is longer than the maximum 16K");
                } else if (len == 0) {
                    parser_yyerror("json table column path cannot be empty");
                }
                table->json_table_info->basic_path_txt.str = path;
                table->json_table_info->basic_path_txt.len = len;
                table->json_table_info->json_error_info.type = JSON_RETURN_DEFAULT;
                table->json_table_info->json_error_info.default_value = $8;

                cm_galist_copy(&table->json_table_info->columns, $13);
                rs_column_t *new_col = NULL;
                expr_node_t *func_node = NULL;
                for (uint32 i = 0; i < table->json_table_info->columns.count; i++) {
                    new_col = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, i);
                    func_node = new_col->expr->root;
                    if (!JSON_FUNC_ATT_HAS_ON_ERROR(func_node->json_func_attr.ids)) {
                        set_json_func_default_error_type(func_node, table->json_table_info->json_error_info.type);
                    }
                }
                table->type = JSON_TABLE;
                table->is_jsonb_table = $1;
                $$ = table;
            }
        ;

join_type:	FULL_KEY join_outer                         { $$ = JOIN_TYPE_FULL; }
            | LEFT_KEY join_outer                       { $$ = JOIN_TYPE_LEFT; }
            | RIGHT_KEY join_outer                      { $$ = JOIN_TYPE_RIGHT; }
        ;

join_outer: OUTER_P
            | /*EMPTY*/
        ;

joined_table:
            '(' joined_table ')'
                {
                    $$ = $2;
                }
            | table_ref CROSS_JOIN table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_CROSS, NULL, NULL, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref join_type JOIN_KEY table_ref ON cond_tree_expr
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, $2, NULL, $6, $1, $4, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref INNER_JOIN table_ref ON cond_tree_expr
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, $5, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref INNER_JOIN table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref JOIN_KEY table_ref ON cond_tree_expr
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, $5, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref JOIN_KEY table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
        ;

relation_expr:
            qualified_name
                {
                    $$ = $1;
                }
        ;
/*****************************************************************************
 *
 *     expression grammar
 *
 *****************************************************************************/

/*
 * Define SQL-style CASE clause.
 * - Full specification
 *    CASE WHEN a = b THEN c ... ELSE d END
 * - Implicit argument
 *    CASE a WHEN b THEN c ... ELSE d END
 */
case_expr:      CASE a_expr when_expr_clause_list case_default END_P
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_case_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $2, $3, $4, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("create case when expr failed.");
                        }
                        $$ = expr;
                    }
                | CASE when_cond_clause_list case_default END_P
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_case_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, NULL, $2, $3, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("create case when expr failed.");
                        }
                        $$ = expr;
                    }
        ;

when_cond_clause_list:
            when_cond_clause
                {
                    galist_t *case_pairs = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &case_pairs) != OG_SUCCESS) {
                        parser_yyerror("create case pair list failed.");
                    }
                    if (cm_galist_insert(case_pairs, $1) != OG_SUCCESS) {
                        parser_yyerror("insert case pair failed.");
                    }
                    $$ = case_pairs;
                }
            | when_cond_clause_list when_cond_clause
                {
                    galist_t *case_pairs = $1;
                    if (cm_galist_insert(case_pairs, $2) != OG_SUCCESS) {
                        parser_yyerror("insert case pair failed.");
                    }
                    $$ = case_pairs;
                }
        ;

when_cond_clause:
            WHEN cond_tree_expr THEN a_expr
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    case_pair_t *case_pair = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(case_pair_t), (void **)&case_pair) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    case_pair->when_cond = $2;
                    case_pair->value = $4;
                    $$ = case_pair;
                }
        ;

when_expr_clause_list:
            /* There must be at least one */
            when_expr_clause
                {
                    galist_t *case_pairs = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &case_pairs) != OG_SUCCESS) {
                        parser_yyerror("create case pair list failed.");
                    }
                    if (cm_galist_insert(case_pairs, $1) != OG_SUCCESS) {
                        parser_yyerror("insert case pair failed.");
                    }
                    $$ = case_pairs;
                }
            | when_expr_clause_list when_expr_clause
                {
                    galist_t *case_pairs = $1;
                    if (cm_galist_insert(case_pairs, $2) != OG_SUCCESS) {
                        parser_yyerror("insert case pair failed.");
                    }
                    $$ = case_pairs;
                }
        ;

when_expr_clause:
            WHEN a_expr THEN a_expr
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    case_pair_t *case_pair = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(case_pair_t), (void **)&case_pair) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    case_pair->when_expr = $2;
                    case_pair->value = $4;
                    $$ = case_pair;
                }
        ;

case_default:
            ELSE a_expr                                { $$ = $2; }
            | /*EMPTY*/                                { $$ = NULL; }
        ;

/*
 * General expressions
 * This is the heart of the expression syntax.
 *
 * We have two expression types: a_expr is the unrestricted kind, and
 * b_expr is a subset that must be used in some places to avoid shift/reduce
 * conflicts.  For example, we can't do BETWEEN as "BETWEEN a_expr AND a_expr"
 * because that use of AND conflicts with AND as a boolean operator.  So,
 * b_expr is used in BETWEEN and we remove boolean keywords from b_expr.
 *
 * Note that '(' a_expr ')' is a b_expr, so an unrestricted expression can
 * always be used by surrounding it with parens.
 *
 * c_expr is all the productions that are common to a_expr and b_expr;
 * it's factored out just to eliminate redundant coding.
 *
 * Be careful of productions involving more than one terminal token.
 * By default, bison will assign such productions the precedence of their
 * last terminal, but in nearly all cases you want it to be the precedence
 * of the first terminal instead; otherwise you will not get the behavior
 * you expect!  So we use %prec annotations freely to set precedences.
 */
a_expr:     c_expr    { $$ = $1; }
            | a_expr TYPECAST Typename
            {
                expr_tree_t *expr = NULL;
                if (sql_create_cast_convert_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &expr, $1, $3, "cast", @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create cast func expr failed");
                }
                $$ = expr;
            }
            | '+' a_expr %prec UMINUS
            {
                // Unary plus operator is a no-op, just return the operand
                $$ = $2;
            }
            | '-' a_expr %prec UMINUS
            {
                expr_tree_t *expr = NULL;
                if (sql_create_negative_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $2->root, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create negative expr failed");
                }
                $$ = expr;
            }
            /*
            * These operators must be called out explicitly in order to make use
            * of bison's automatic operator-precedence handling.
            *
            * If you add more explicitly-known operators, be sure to add them
            * also to b_expr
            */
            | a_expr '+' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_ADD, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '-' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_SUB, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '*' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_MUL, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '/' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_DIV, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '%' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_MOD, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '|' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_BITOR, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr OPER_CAT a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_CAT, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '&' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_BITAND, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr '^' a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_BITXOR, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr OPER_LSHIFT a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_LSHIFT, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
            | a_expr OPER_RSHIFT a_expr
            {
                expr_tree_t *expr = NULL;
                if (sql_create_oper_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1->root, $3->root, EXPR_NODE_RSHIFT, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("create operator expr failed");
                }
                $$ = expr;
            }
        ;

/*
 * Productions that can be used in both a_expr and b_expr.
 *
 * Note: productions that refer recursively to a_expr or b_expr mostly
 * cannot appear here. However, it's OK to refer to a_exprs that occur
 * inside parentheses, such as function arguments; that cannot introduce
 * ambiguity to the b_expr syntax.
 */
c_expr:     columnref       { $$ = $1; }
            | AexprConst    { $$ = $1; }
            | PARAM
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_paramref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, @1) != OG_SUCCESS) {
                        parser_yyerror("init paramref expr failed");
                    }
                    $$ = expr;
                }
            | '(' a_expr ')'    { $$ = $2; }
            | case_expr         { $$ = $1; }
            | func_expr         { $$ = $1; }
            | select_with_parens    %prec UMINUS
                {
                    expr_tree_t *expr = NULL;
                    sql_select_t *select_ctx = $1;
                    if (sql_create_select_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, select_ctx,
                        &og_yyget_extra(yyscanner)->core_yy_extra.ssa, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init select expr failed");
                    }
                    $$ = expr;
                }
            | PRIOR columnref
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_prior_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $2->root, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init prior expr failed");
                    }
                    $$ = expr;
                }
            | LEVEL
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_reserved_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, RES_WORD_LEVEL, OG_FALSE, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init LEVEL reserved expr failed");
                    }
                    $$ = expr;
                }
            | ARRAY '[' ']'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_array_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create array expr failed");
                    }
                    $$ = expr;
                }
            | ARRAY '[' expr_elem_list ']'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_array_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create array expr failed");
                    }
                    $$ = expr;
                }
        ;

func_application: func_name '(' ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, NULL, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        $$ = expr;
                    }
                | func_name '(' a_expr ignore_nulls ')'
                    {
                        if ($1->count != 1) {
                            parser_yyerror("only first_value/last_value func support IGNORE NULLS option");
                        }
                        expr_tree_t *expr = NULL;
                        const text_t *name = &(((expr_tree_t*)cm_galist_get($1, 0))->root->value.v_text);
                        text_t target_text_1 = {(char*)"FIRST_VALUE", strlen("FIRST_VALUE")};
                        text_t target_text_2 = {(char*)"LAST_VALUE", strlen("LAST_VALUE")};
                        if (!cm_text_equal(name, &target_text_1) && !cm_text_equal(name, &target_text_2)) {
                            parser_yyerror("only first_value/last_value func support IGNORE NULLS option");
                        }
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, $3, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        expr->root->ignore_nulls = $4;
                        $$ = expr;
                    }
                | func_name '(' func_arg_list ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, $3, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        $$ = expr;
                    }
                | func_name '(' ALL func_arg_list ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, $4, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        $$ = expr;
                    }
                | func_name '(' DISTINCT func_arg_list ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, $4, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        expr->root->dis_info.need_distinct = OG_TRUE;
                        $$ = expr;
                    }
                | func_name '(' '*' ')'
                    {
                        expr_tree_t *star_expr = NULL;
                        if (sql_create_expr_tree(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &star_expr, OG_TYPE_UNKNOWN,
                            EXPR_NODE_STAR, @3.loc) != OG_SUCCESS) {
                            parser_yyerror("init star expr failed");
                        }
                        expr_tree_t *expr = NULL;
                        if (sql_create_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, star_expr, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init function call expr failed");
                        }
                        $$ = expr;
                    }
            ;

func_arg_list:  func_arg_expr
                {
                    $$ = $1;
                }
            | func_arg_list ',' func_arg_expr
                {
                    expr_tree_t *first_expr = $1;
                    expr_tree_t *tmp_expr = $1;
                    while (tmp_expr->next != NULL) {
                        tmp_expr = tmp_expr->next;
                    }
                    tmp_expr->next = $3;
                    $$ = first_expr;
                }
        ;

func_arg_expr:  a_expr
                {
                    $$ = $1;
                }
            | param_name COLON_EQUALS a_expr
                {
                    expr_tree_t *arg_expr = $3;
                    arg_expr->arg_name.str = $1;
                    arg_expr->arg_name.len = strlen($1);
                    $$ = arg_expr;
                }
            | param_name PARA_EQUALS a_expr
                {
                    expr_tree_t *arg_expr = $3;
                    arg_expr->arg_name.str = $1;
                    arg_expr->arg_name.len = strlen($1);
                    $$ = arg_expr;
                }
        ;

expr_elem_list: a_expr
                {
                    $$ = $1;
                }
            | expr_elem_list ',' a_expr
                {
                    expr_tree_t *first_expr = $1;
                    expr_tree_t *tmp_expr = $1;
                    while (tmp_expr->next != NULL) {
                        tmp_expr = tmp_expr->next;
                    }
                    tmp_expr->next = $3;
                    $$ = first_expr;
                }
        ;

/*
 * Ideally param_name should be ColId, but that causes too many conflicts.
 */
param_name: type_function_name
    ;

opt_sort_clause:
            sort_clause { $$ = $1; }
            | /*EMPTY*/ { $$ = NULL; }
        ;

sort_clause:
            ORDER BY sortby_list            { $$ = $3; }
        ;

opt_siblings_clause:
            siblings_clause                 { $$ = $1; }
            | /* EMPTY */                   { $$ = NULL; }
        ;

siblings_clause:
            ORDER_SIBLINGS BY sortby_list          { $$ = $3; }
        ;

sortby_list:
            sortby
                {
                    galist_t *sort_items = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &sort_items) != OG_SUCCESS) {
                        parser_yyerror("create sort item list failed.");
                    }
                    if (cm_galist_insert(sort_items, $1) != OG_SUCCESS) {
                        parser_yyerror("insert sort item list failed.");
                    }
                    $$ = sort_items;
                }
            | sortby_list ',' sortby
                {
                    galist_t *sort_items = $1;
                    if (cm_galist_insert(sort_items, $3) != OG_SUCCESS) {
                        parser_yyerror("insert sort item list failed.");
                    }
                    $$ = sort_items;
                }
        ;

sortby: a_expr opt_asc_desc opt_nulls_order
            {
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                sort_item_t *sort_item = NULL;
                if (sql_alloc_mem(stmt->context, sizeof(sort_item_t), (void **)&sort_item) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                sort_item->expr = $1;
                sort_item->direction = $2;
                if ($3 == SORT_NULLS_DEFAULT) {
                    sort_item->nulls_pos = DEFAULT_NULLS_SORTING_POSITION($2);
                } else {
                    sort_item->nulls_pos = $3;
                }
                $$ = sort_item;
            }
    ;

opt_limit:
            limit_clause                                { $$ = $1; }
            | offset_clause                             { $$ = $1; }
            | /* EMPTY */                               { $$ = NULL; }
    ;

limit_clause:
            LIMIT a_expr OFFSET a_expr
                {
                    limit_item_t *limit_item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(limit_item_t), (void **)&limit_item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    limit_item->count = (void*)$2;
                    limit_item->offset = (void*)$4;
                    if (sql_verify_limit_offset(stmt, limit_item)) {
                        parser_yyerror("verify limit clause failed");
                    }
                    $$ = limit_item;
                }
            | LIMIT a_expr ',' a_expr
                {
                    limit_item_t *limit_item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(limit_item_t), (void **)&limit_item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    limit_item->count = (void*)$2;
                    limit_item->offset = (void*)$4;
                    if (sql_verify_limit_offset(stmt, limit_item)) {
                        parser_yyerror("verify limit clause failed");
                    }
                    $$ = limit_item;
                }
            | LIMIT a_expr
                {
                    limit_item_t *limit_item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(limit_item_t), (void **)&limit_item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    limit_item->count = (void*)$2;
                    if (sql_verify_limit_offset(stmt, limit_item)) {
                        parser_yyerror("verify limit clause failed");
                    }
                    $$ = limit_item;
                }
    ;

offset_clause:
            OFFSET a_expr LIMIT a_expr
                {
                    limit_item_t *limit_item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(limit_item_t), (void **)&limit_item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    limit_item->count = (void*)$4;
                    limit_item->offset = (void*)$2;
                    if (sql_verify_limit_offset(stmt, limit_item)) {
                        parser_yyerror("verify limit clause failed");
                    }
                    $$ = limit_item;
                }
            | OFFSET a_expr
                {
                    limit_item_t *limit_item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(limit_item_t), (void **)&limit_item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    limit_item->offset = (void*)$2;
                    if (sql_verify_limit_offset(stmt, limit_item)) {
                        parser_yyerror("verify limit clause failed");
                    }
                    $$ = limit_item;
                }
    ;

opt_asc_desc: ASC       { $$ = SORT_MODE_ASC; }
            | DESC      { $$ = SORT_MODE_DESC; }
            | /*EMPTY*/ { $$ = SORT_MODE_ASC; } /* default asc */
        ;

opt_nulls_order: NULLS_FIRST    { $$ = SORT_NULLS_FIRST; }
            | NULLS_LAST        { $$ = SORT_NULLS_LAST; }
            | /*EMPTY*/         { $$ = SORT_NULLS_DEFAULT; }
        ;

/*
 * Aggregate decoration clauses
 */
within_group_clause:
            WITHIN GROUP_P '(' sort_clause ')'      { $$ = $4; }
            | /*EMPTY*/                             { $$ = NULL; }
        ;

over_clause: OVER window_specification
                { $$ = $2; }
            | /*EMPTY*/
                { $$ = NULL; }
        ;

window_specification: '(' opt_partition_clause
                        opt_sort_clause opt_frame_clause ')'
                {
                    winsort_args_t *winsort_args = NULL;
                    if (sql_build_winsort_node_bison(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &winsort_args,
                        $2, $3, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create window sort node failed");
                    }
                    $$ = winsort_args;
                }
        ;

/*
 * If we see PARTITION, RANGE, ROWS or GROUPS as the first token after the '('
 * of a window_specification, we want the assumption to be that there is
 * no existing_window_name; but those keywords are unreserved and so could
 * be ColIds.  We fix this by making them have the same precedence as IDENT
 * and giving the empty production here a slightly higher precedence, so
 * that the shift/reduce conflict is resolved in favor of reducing the rule.
 * These keywords are thus precluded from being an existing_window_name but
 * are not reserved for any other purpose.
 */
opt_partition_clause: PARTITION BY expr_list            { $$ = $3; }
            | /*EMPTY*/                                 { $$ = NULL; }
        ;

/*
 * For frame clauses, we return a WindowDef, but only some fields are used:
 * frameOptions, startOffset, and endOffset.
 */
opt_frame_clause: RANGE frame_extent
                {
                    windowing_args_t *windowing_args = $2;
                    windowing_args->is_range = OG_TRUE;
                    $$ = windowing_args;
                }
            | ROWS frame_extent
                {
                    $$ = $2;
                }
            | /*EMPTY*/
                {
                    $$ = NULL;
                }
        ;

frame_extent: frame_bound
                {
                    windowing_args_t *windowing_args = NULL;
                    if (sql_create_windowing_arg(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &windowing_args, $1, NULL) != OG_SUCCESS) {
                        parser_yyerror("create window arg node failed");
                    }
                    $$ = windowing_args;
                }
            | BETWEEN frame_bound AND frame_bound
                {
                    windowing_args_t *windowing_args = NULL;
                    if (sql_create_windowing_arg(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &windowing_args, $2, $4) != OG_SUCCESS) {
                        parser_yyerror("create window arg node failed");
                    }
                    $$ = windowing_args;
                }
        ;

/*
 * This is used for both frame start and frame end, with output set up on
 * the assumption it's frame start; the frame_extent productions must reject
 * invalid cases.
 */
frame_bound:
            UNBOUNDED PRECEDING
                {
                    windowing_border_t *windowing_border = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(windowing_border_t), (void **)&windowing_border) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    windowing_border->expr = NULL;
                    windowing_border->border_type = WB_TYPE_UNBOUNDED_PRECED;
                    $$ = windowing_border;
                }
            | UNBOUNDED FOLLOWING
                {
                    windowing_border_t *windowing_border = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(windowing_border_t), (void **)&windowing_border) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    windowing_border->expr = NULL;
                    windowing_border->border_type = WB_TYPE_UNBOUNDED_FOLLOW;
                    $$ = windowing_border;
                }
            | CURRENT_P ROW
                {
                    windowing_border_t *windowing_border = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(windowing_border_t), (void **)&windowing_border) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    windowing_border->expr = NULL;
                    windowing_border->border_type = WB_TYPE_CURRENT_ROW;
                    $$ = windowing_border;
                }
            | a_expr PRECEDING
                {
                    windowing_border_t *windowing_border = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(windowing_border_t), (void **)&windowing_border) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    windowing_border->expr = $1;
                    windowing_border->border_type = WB_TYPE_VALUE_PRECED;
                    $$ = windowing_border;
                }
            | a_expr FOLLOWING
                {
                    windowing_border_t *windowing_border = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(windowing_border_t), (void **)&windowing_border) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    windowing_border->expr = $1;
                    windowing_border->border_type = WB_TYPE_VALUE_FOLLOW;
                    $$ = windowing_border;
                }
        ;

/*
 * func_expr and its cousin func_expr_windowless are split out from c_expr just
 * so that we have classifications for "everything that is a function call or
 * looks like one".  This isn't very important, but it saves us having to
 * document which variants are legal in places like "FROM function()" or the
 * backwards-compatible functional-index syntax for CREATE INDEX.
 * (Note that many of the special SQL functions wouldn't actually make any
 * sense as functional index entries, but we ignore that consideration here.)
 */
func_expr: func_application within_group_clause over_clause
                {
                    expr_tree_t *expr = $1;
                    expr_node_t *node = expr->root;
                    node->sort_items = $2;
                    if (sql_create_winsort_node_bison(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        expr, node, $3, @3.loc) != OG_SUCCESS) {
                        parser_yyerror("create window sort node failed");
                    }
                    $$ = expr;
                }
            | func_expr_common_subexpr
                { $$ = $1; }
        ;

/*
 * Special expressions that are considered to be functions.
 */
func_expr_common_subexpr:
            CAST '(' a_expr AS Typename ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_cast_convert_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $5, "cast", @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create cast func expr failed");
                    }
                    $$ = expr;
                }
            | CAST '(' a_expr AS SIGNED NoSignedInteger ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_cast_convert_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $6, "cast", @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create cast func expr failed");
                    }
                    $$ = expr;
                }
            | CONVERT_P '(' a_expr ',' Typename ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_cast_convert_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $5, "convert", @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create convert func expr failed");
                    }
                    $$ = expr;
                }
            | CONVERT_P '(' a_expr ',' SIGNED NoSignedInteger ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_cast_convert_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $6, "convert", @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create convert func expr failed");
                    }
                    $$ = expr;
                }
            | IF_P '(' cond_tree_expr ',' a_expr ',' a_expr ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_if_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $5, $7, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create if func expr failed");
                    }
                    $$ = expr;
                }
            | LNNVL '(' cond_tree_expr ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_lnnvl_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create lnnvl func expr failed");
                    }
                    $$ = expr;
                }
            | TRIM '(' BOTH opt_from trim_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_trim_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $5, FUNC_BOTH, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create trim func expr failed");
                    }
                    $$ = expr;
                }
            | TRIM '(' LEADING opt_from trim_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_trim_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $5, FUNC_LTRIM, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create trim func expr failed");
                    }
                    $$ = expr;
                }
            | TRIM '(' TRAILING opt_from trim_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_trim_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $5, FUNC_RTRIM, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create trim func expr failed");
                    }
                    $$ = expr;
                }
            | TRIM '(' trim_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_trim_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, FUNC_BOTH, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create trim func expr failed");
                    }
                    $$ = expr;
                }
            | GROUP_CONCAT '(' DISTINCT func_arg_list opt_sort_clause opt_separator ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_groupconcat_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $4, $5, $6, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create group_concat func expr failed");
                    }
                    expr->root->dis_info.need_distinct = OG_TRUE;
                    $$ = expr;
                }
            | GROUP_CONCAT '(' func_arg_list opt_sort_clause opt_separator ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_groupconcat_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $4, $5, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create group_concat func expr failed");
                    }
                    $$ = expr;
                }
            | substr_func'(' func_arg_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_substr_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $1, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create substr func expr failed");
                    }
                    $$ = expr;
                }
            | substr_func'(' substr_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_substr_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, $1, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create substr func expr failed");
                    }
                    $$ = expr;
                }
            | EXTRACT '(' extract_list ')'
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_extract_funccall_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $3, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create substr func expr failed");
                    }
                    $$ = expr;
                }
            | JSON_ARRAY '(' json_array_args json_on_null json_returning ')'
                {
                    expr_tree_t *expr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    json_func_attr_t attr;
                    attr.ids = $4 | $5.attr;
                    attr.return_size = $5.return_size;
                    attr.ignore_returning = OG_FALSE;
                    if (sql_create_json_func_expr(stmt, &expr, $3, "json_array", attr, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create json_object func expr failed");
                    }
                    $$ = expr;
                }
            | JSON_OBJECT '(' json_object_args json_on_null json_returning ')'
                {
                    expr_tree_t *expr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    json_func_attr_t attr;
                    attr.ids = $4 | $5.attr;
                    attr.return_size = $5.return_size;
                    attr.ignore_returning = OG_FALSE;
                    if (sql_create_json_func_expr(stmt, &expr, $3, "json_object", attr, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create json_object func expr failed");
                    }
                    $$ = expr;
                }
            | common_json_func_name '(' a_expr ',' a_expr json_attr_all ')'
                {
                    expr_tree_t *expr = NULL;
                    $3->next = $5;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_json_func_expr(stmt, &expr, $3, $1, $6, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create json func expr failed");
                    }
                    $$ = expr;
                }
            | json_set_func_name '(' func_arg_list json_attr_all ')'
                {
                    expr_tree_t *expr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_json_func_expr(stmt, &expr, $3, $1, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("create json_set/jsonb_set func expr failed");
                    }
                    $$ = expr;
                }
            | no_arg_func_name_id
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_reserved_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, OG_FALSE, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init function call expr failed");
                    }
                    $$ = expr;
                }
        ;

no_arg_func_name_id:
            USER        { $$ = RES_WORD_USER; }
            | ROWNUM    { $$ = RES_WORD_ROWNUM; }
            | SYSDATE   { $$ = RES_WORD_SYSDATE; }
            | ROWID     { $$ = RES_WORD_ROWID; }
            | ROWSCN    { $$ = RES_WORD_ROWSCN; }
        ;

common_json_func_name:
            JSON_QUERY          { $$ = "json_query"; }
            | JSON_MERGEPATCH   { $$ = "json_mergepatch"; }
            | JSON_VALUE        { $$ = "json_value"; }
            | JSON_EXISTS       { $$ = "json_exists"; }
            | JSONB_QUERY       { $$ = "jsonb_query"; }
            | JSONB_MERGEPATCH  { $$ = "jsonb_mergepatch"; }
            | JSONB_VALUE       { $$ = "jsonb_value"; }
            | JSONB_EXISTS      { $$ = "jsonb_exists"; }
        ;

json_set_func_name:
            JSON_SET    { $$ = "json_set"; }
            | JSONB_SET { $$ = "jsonb_set"; }
        ;

json_attr_all:
            json_returning json_array_wrapper json_on_error json_on_empty
            {
                $$.ids = $1.attr | $2 | $3 | $4;
                $$.return_size = $1.return_size;
                $$.ignore_returning = OG_FALSE;
            }

json_array_args:
            json_array_arg_item
            {
                $$ = $1;
            }
            | json_array_args ',' json_array_arg_item
            {
                expr_tree_t *last = $1;
                while (last->next != NULL) {
                    last = last->next;
                }
                last->next = $3;
                $$ = $1;
            }
        ;

json_array_arg_item:
            a_expr format_json
            {
                $1->root->format_json = $2;
                $$ = $1;
            }
        ;

json_on_null:
            ABSENT_ON NULL_P
            {
                $$ = JSON_FUNC_ATT_ABSENT_ON_NULL;
            }
            | NULL_P ON NULL_P
            {
                $$ = JSON_FUNC_ATT_NULL_ON_NULL;
            }
            | /* EMPTY */
            {
                $$ = JSON_FUNC_ATT_INVALID;
            }
        ;

json_returning:
            RETURNING VARCHAR2
            {
                $$.attr = JSON_FUNC_ATT_RETURNING_VARCHAR2;
                $$.return_size = JSON_FUNC_LEN_DEFAULT;
            }
            | RETURNING VARCHAR2 '(' ICONST ')'
            {
                if ($4 <= 0 || $4 > JSON_MAX_STRING_LEN) {
                    parser_yyerror("specified length invalid for its datatype");
                }
                $$.attr = JSON_FUNC_ATT_RETURNING_VARCHAR2;
                $$.return_size = $4;
            }
            | RETURNING CLOB
            {
                $$.attr = JSON_FUNC_ATT_RETURNING_CLOB;
                $$.return_size = JSON_FUNC_LEN_DEFAULT;
            }
            | RETURNING JSONB
            {
                $$.attr = JSON_FUNC_ATT_RETURNING_JSONB;
                $$.return_size = JSON_FUNC_LEN_DEFAULT;
            }
            | /* EMPTY */
            {
                $$.attr = JSON_FUNC_ATT_INVALID;
                $$.return_size = JSON_FUNC_LEN_DEFAULT;
            }
        ;

json_array_wrapper:
            format_json_attr
            {
                $$ = $1;
            }
            | WITH ARRAY WRAPPER
            {
                $$ = JSON_FUNC_ATT_WITH_WRAPPER;
            }
            | WITH CONDITIONAL WRAPPER
            {
                $$ = JSON_FUNC_ATT_WITH_CON_WRAPPER;
            }
            | WITH UNCONDITIONAL WRAPPER
            {
                $$ = JSON_FUNC_ATT_WITH_WRAPPER;
            }
            | WITH CONDITIONAL ARRAY WRAPPER
            {
                $$ = JSON_FUNC_ATT_WITH_CON_WRAPPER;
            }
            | WITH UNCONDITIONAL ARRAY WRAPPER
            {
                $$ = JSON_FUNC_ATT_WITH_WRAPPER;
            }
            | /* EMPTY */
            {
                $$ = JSON_FUNC_ATT_INVALID;
            }
        ;

json_on_error:
            ERROR_ON_ERROR_P
            {
                $$ = JSON_FUNC_ATT_ERROR_ON_ERROR;
            }
            | FALSE_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_FALSE_ON_ERROR;
            }
            | NULL_ON_ERROR_P
            {
                $$ = JSON_FUNC_ATT_NULL_ON_ERROR;
            }
            | TRUE_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_TRUE_ON_ERROR;
            }
            | EMPTY_ON_ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_ON_ERROR;
            }
            | EMPTY_ARRAY_ON_ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_ARRAY_ON_ERROR;
            }
            | EMPTY_OBJECT_P_ON_ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_OBJECT_ON_ERROR;
            }
            | /* EMPTY */
            {
                $$ = JSON_FUNC_ATT_INVALID;
            }
        ;
json_on_empty_null_or_error:
            NULL_ON_EMPTY
            {
                $$ = JSON_FUNC_ATT_NULL_ON_EMPTY;
            }
            | ERROR_ON_EMPTY
            {
                $$ = JSON_FUNC_ATT_ERROR_ON_EMPTY;
            }
            | /* EMPTY */
            {
                $$ = JSON_FUNC_ATT_INVALID;
            }
        ;

json_on_empty:
            json_on_empty_null_or_error
            {
                $$ = $1;
            }
            | EMPTY_ON_EMPTY
            {
                $$ = JSON_FUNC_ATT_EMPTY_ON_EMPTY;
            }
            | EMPTY_ARRAY_ON_EMPTY
            {
                $$ = JSON_FUNC_ATT_EMPTY_ARRAY_ON_EMPTY;
            }
            | EMPTY_OBJECT_P_ON_EMPTY
            {
                $$ = JSON_FUNC_ATT_EMPTY_OBJECT_ON_EMPTY;
            }
        ;

json_object_args:
            json_object_arg_item
            {
                $$ = $1;
            }
            | json_object_args ',' json_object_arg_item
            {
                expr_tree_t *last = $1;
                while (last->next != NULL) {
                    last = last->next;
                }
                last->next = $3;
                $$ = $1;
            }
        ;

json_object_arg_item:
            a_expr IS a_expr format_json
            {
                expr_tree_t *key_expr = $1;
                expr_tree_t *value_expr = $3;
                value_expr->root->format_json = $4;
                key_expr->next = value_expr;
                $$ = key_expr;
            }
            | KEY a_expr IS a_expr format_json
            {
                expr_tree_t *key_expr = $2;
                expr_tree_t *value_expr = $4;
                value_expr->root->format_json = $5;
                key_expr->next = value_expr;
                $$ = key_expr;
            }
        ;

extract_list:
            extract_arg FROM a_expr
                {
                    extract_list_t *extract_list = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(extract_list_t), (void **)&extract_list) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    extract_list->arg = $3;
                    extract_list->extract_type = $1;
                    $$ = extract_list;
                }
        ;

extract_arg:
            YEAR_P          { $$ = "year"; }
            | MONTH_P       { $$ = "month"; }
            | DAY_P         { $$ = "day"; }
            | HOUR_P        { $$ = "hour"; }
            | MINUTE_P      { $$ = "minute"; }
            | SECOND_P      { $$ = "second"; }
        ;

substr_func:    SUBSTR      { $$ = "substr"; }
               | SUBSTRING  { $$ = "substring"; }
           ;

substr_list:    a_expr FROM a_expr FOR a_expr
                {
                    $3->next = $5;
                    $1->next = $3;
                    $$ = $1;
                }
               | a_expr FROM a_expr
                {
                    $1->next = $3;
                    $$ = $1;
                }
        ;

opt_from:   FROM        {}
            | /*EMPTY*/ {}
        ;

trim_list:  a_expr FROM a_expr
            {
                trim_list_t *trim = NULL;
                if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                    sizeof(trim_list_t), (void **)&trim) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                trim->first_expr = $1;
                trim->second_expr = $3;
                trim->reverse = OG_TRUE;
                $$ = trim;
            }
           | a_expr
            {
                trim_list_t *trim = NULL;
                if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                    sizeof(trim_list_t), (void **)&trim) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                trim->first_expr = $1;
                $$ = trim;
            }
           | a_expr ',' a_expr
            {
                trim_list_t *trim = NULL;
                if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                    sizeof(trim_list_t), (void **)&trim) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }
                trim->first_expr = $1;
                trim->second_expr = $3;
                $$ = trim;
            }
        ;

opt_separator:  SEPARATOR_P SCONST   { $$ = $2; }
                | /*EMPTY*/ {  $$ = NULL; }
        ;

opt_orajoin:
        ORA_JOINOP      { $$ = true; }
        | /* EMPTY */   { $$ = false; }
        ;

columnref:  ColId opt_orajoin
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_columnref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, NULL, $2 ? EXPR_NODE_JOIN : EXPR_NODE_COLUMN, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init columnref expr failed");
                    }
                    $$ = expr;
                }
            | ColId indirection opt_orajoin
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_columnref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, $2, $3 ? EXPR_NODE_JOIN : EXPR_NODE_COLUMN, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init columnref expr failed");
                    }
                    $$ = expr;
                }
        ;

/*****************************************************************************
 *
 *    Type syntax
 *        SQL introduces a large amount of type-specific syntax.
 *        Define individual clauses to handle these cases, and use
 *         the generic case to handle regular type-extensible syntax.
 *
 *****************************************************************************/

Typename:    SimpleTypename opt_array_bounds
                {
                    type_word_t *type = $1;
                    if ($2 != NULL) {
                        type->is_array = OG_TRUE;
                        type->array_size = *((int*)cm_galist_get($2, 0));
                    }
                    $$ = type;
                }
        ;

opt_array_bounds:
            '[' ']'
                {
                    galist_t *opt_array_bounds = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &opt_array_bounds) != OG_SUCCESS) {
                        parser_yyerror("create array bounds list failed.");
                    }
                    int *ival = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(int), (void **)&ival) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    *ival = -1;
                    if (cm_galist_insert(opt_array_bounds, ival) != OG_SUCCESS) {
                        parser_yyerror("insert array bounds list failed.");
                    }
                    $$ = opt_array_bounds;
                }
            | '[' ICONST ']'
                {
                    galist_t *opt_array_bounds = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &opt_array_bounds) != OG_SUCCESS) {
                        parser_yyerror("create array bounds list failed.");
                    }
                    int *ival = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(int), (void **)&ival) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    *ival = $2;
                    if (cm_galist_insert(opt_array_bounds, ival) != OG_SUCCESS) {
                        parser_yyerror("insert array bounds list failed.");
                    }
                    $$ = opt_array_bounds;
                }
            | /*EMPTY*/ {  $$ = NULL; }
        ;

SimpleTypename:
            GenericType                 { $$ = $1; }
            | Numeric                   { $$ = $1; }
            | Character                 { $$ = $1; }
            | ConstDatetime             { $$ = $1; }
            | ConstInterval             { $$ = $1; }
            | JsonType                  { $$ = $1; }
        ;

/*
 * GenericType covers all type names that don't have special syntax mandated
 * by the standard, including qualified names.  We also allow type modifiers.
 * To avoid parsing conflicts against function invocations, the modifiers
 * have to be shown as expr_list here, but parse analysis will only accept
 * constants for them.
 */
GenericType:
            type_function_name opt_type_modifiers
                {
                    type_word_t *type;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(type_word_t), (void **)&type) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    type->str = $1;
                    type->typemode = $2;
                    type->loc = @1.loc;
                    $$ = type;
                }
        ;

opt_type_modifiers: '(' expr_list ')'   { $$ = $2; }
                    | /* EMPTY */       { $$ = NULL; }
        ;

opt_signed:
            SIGNED                      { $$ = OG_TRUE; }
            | UNSIGNED                  { $$ = OG_FALSE; }
        ;

/*
 * SQL numeric data types
 */
Numeric:     NoSignedInteger
                {
                    $$ = $1;
                }
            | BIGINT
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "bigint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | SignedInteger
                {
                    $$ = $1;
                }
            | BINARY_DOUBLE
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "binary_double", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BINARY_FLOAT
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "binary_float", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | REAL opt_float
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "real", $2, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | FLOAT_P opt_float
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "float", $2, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | DOUBLE_P PRECISION
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "double", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | DECIMAL_P opt_type_modifiers
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "decimal", $2, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | NUMBER_P opt_type_modifiers
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "number", $2, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | NUMERIC opt_type_modifiers
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "numeric", $2, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BOOLEAN_P
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "boolean", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

NoSignedInteger:  INT_P
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "int", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | INTEGER
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "int", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | SMALLINT
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "smallint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BINARY_INTEGER
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "binary_integer", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | TINYINT
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "tinyint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BINARY_BIGINT
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "binary_bigint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

SignedInteger:  INT_P opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "int" : "uint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | INTEGER opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "int" : "uint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | SMALLINT opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "smallint" : "usmallint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BINARY_INTEGER opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "binary_integer" : "binary_uint32", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | TINYINT opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "tinyint" : "utinyint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BINARY_BIGINT opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "binary_bigint" : "ubigint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
            | BIGINT opt_signed
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $2 ? "bigint" : "ubigint", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

opt_float:    '(' expr_list ')'
                {
                    $$ = $2;
                }
            | /*EMPTY*/
                {
                    $$ = NULL;
                }
        ;

/*
 * SQL character data types
 * The following implements CHAR() and VARCHAR().
 */
Character:  CharacterWithLength opt_charset opt_collate
                {
                    type_word_t *type = $1;
                    type->charset = (uint8)$2;
                    type->collation = (uint8)$3;
                    $$ = type;
                }
            | CharacterWithoutLength opt_charset opt_collate
                {
                    type_word_t *type = $1;
                    type->charset = (uint8)$2;
                    type->collation = (uint8)$3;
                    $$ = type;
                }
        ;

CharacterWithLength:  character '(' ICONST opt_charbyte ')'
                {
                    galist_t *list = NULL;
                    if (make_type_modifiers(yyscanner, &list, $3, @3.loc) != OG_SUCCESS) {
                        parser_yyerror("make type modifiers failed");
                    }
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $1, list, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    type->is_char = $4;
                    $$ = type;
                }
               | character_national '(' ICONST ')'
                {
                    galist_t *list = NULL;
                    if (make_type_modifiers(yyscanner, &list, $3, @3.loc) != OG_SUCCESS) {
                        parser_yyerror("make type modifiers failed");
                    }
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $1, list, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

CharacterWithoutLength:     character
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $1, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
               | character_national
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, $1, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

character:    CHARACTER opt_varying     { $$ = $2 ? "varchar": "char"; }
            | CHAR_P opt_varying        { $$ = $2 ? "varchar": "char"; }
            | BPCHAR opt_varying        { $$ = $2 ? "varchar": "char"; }
            | VARCHAR                   { $$ = "varchar"; }
            | VARCHAR2                  { $$ = "varchar2"; }
        ;

character_national: NCHAR opt_varying              { $$ = $2 ? "nvarchar" : "nchar"; }
            | NVARCHAR                             { $$ = "nvarchar"; }
            | NVARCHAR2                            { $$ = "nvarchar2"; }
            | NATIONAL CHARACTER opt_varying       { $$ = $3 ? "nvarchar" : "nchar"; }
            | NATIONAL CHAR_P opt_varying          { $$ = $3 ? "nvarchar" : "nchar"; }
        ;

opt_varying:
            VARYING                                    { $$ = OG_TRUE; }
            | /*EMPTY*/                                { $$ = OG_FALSE; }
        ;

opt_charbyte: CHAR_P    { $$ = OG_TRUE; }
             | BYTE_P   { $$ = OG_FALSE; }
             | /* EMPTY */ {$$ = OG_FALSE; }
        ;

opt_charset:    CHARACTER SET charset_collate_name
                {
                    text_t name = {$3, strlen($3)};
                    uint16 charset_id = cm_get_charset_id_ex(&name);
                    if (charset_id == OG_INVALID_ID16) {
                        parser_yyerror("unknown charset option");
                    }
                    $$ = charset_id;
                }
                | /*EMPTY*/ { $$ = 0;}
        ;

charset_collate_name:
            ColId           { $$ = $1; }
            | SCONST        { $$ = $1; }
        ;

opt_collate:    COLLATE charset_collate_name
                {
                    text_t name = {$2, strlen($2)};
                    uint16 collate_id = cm_get_collation_id(&name);
                    if (collate_id == OG_INVALID_ID16) {
                        parser_yyerror("unknown collation option");
                    }
                    $$ = collate_id;
                }
                | /*EMPTY*/   %prec AT   { $$ = 0;}
        ;

/*
 * SQL date/time types
 */
ConstDatetime:
            TIMESTAMP '(' ICONST ')' opt_timezone
                {
                    galist_t *list = NULL;
                    if (make_type_modifiers(yyscanner, &list, $3, @3.loc) != OG_SUCCESS) {
                        parser_yyerror("make type modifiers failed");
                    }
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "timestamp", list, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    type->timezone = $5;
                    $$ = type;
                }
            | TIMESTAMP opt_timezone
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "timestamp", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    type->timezone = $2;
                    $$ = type;
                }
        ;

ConstInterval:
            INTERVAL YEAR_P opt_type_modifiers TO MONTH_P
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "interval year to month", $3, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
           | INTERVAL DAY_P opt_type_modifiers TO SECOND_P opt_type_modifiers
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "interval day to second", $3, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    type->second_typemde = $6;
                    $$ = type;
                }
        ;

opt_timezone:
            WITH_TIME ZONE                          { $$ = WITH_TIMEZONE; }
            | WITH_LOCAL TIME ZONE                  { $$ = WITH_LOCAL_TIMEZONE; }
            | WITHOUT_TIME ZONE                     { $$ = WITHOUT_TIMEZONE; }
            | WITHOUT_LOCAL TIME ZONE               { $$ = WITHOUT_TIMEZONE; }
            | /*EMPTY*/                             { $$ = WITHOUT_TIMEZONE; }
        ;

JsonType:
            JSON
                {
                    type_word_t *type = NULL;
                    if (make_type_word(yyscanner, &type, "json", NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    $$ = type;
                }
        ;

/*
 * Name classification hierarchy.
 *
 * IDENT is the lexeme returned by the lexer for identifiers that match
 * no known keyword.  In most cases, we can accept certain keywords as
 * names, not only IDENTs.     We prefer to accept as many such keywords
 * as possible to minimize the impact of "reserved words" on programmers.
 * So, we divide names into several possible classes.  The classification
 * is chosen in part to make keywords acceptable as names wherever possible.
 */

/* Column identifier --- names that can be column, table, etc names.
 */
ColId:      IDENT                   { $$ = $1; }
            | unreserved_keyword
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $1);
                    cm_str_upper(tmp);
                    $$ = tmp;
                }
            | col_name_keyword
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $1);
                    cm_str_upper(tmp);
                    $$ = tmp;
                }
        ;

/* Type/function identifier --- names that can be type or function names.
 */
type_function_name:    IDENT                        { $$ = $1; }
                       | unreserved_keyword
                        {
                            char *tmp = NULL;
                            BISON_MEM_STRDUP(tmp, $1);
                            cm_str_upper(tmp);
                            $$ = tmp;
                        }
    ;

func_name:      type_function_name
                    {
                        galist_t *name_list = NULL;
                        if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &name_list) != OG_SUCCESS) {
                            parser_yyerror("create function name list failed.");
                        }
                        expr_tree_t *expr = NULL;
                        if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init const expr failed");
                        }
                        if (cm_galist_insert(name_list, expr) != OG_SUCCESS) {
                            parser_yyerror("insert function list failed.");
                        }
                        $$ = name_list;
                    }
                | ColId indirection
                    {
                        galist_t *name_list = NULL;
                        if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &name_list) != OG_SUCCESS) {
                            parser_yyerror("create function name list failed.");
                        }
                        expr_tree_t *expr = NULL;
                        if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                            &expr, $1, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init const expr failed");
                        }
                        if (cm_galist_insert(name_list, expr) != OG_SUCCESS) {
                            parser_yyerror("insert function list failed.");
                        }
                        if (cm_galist_copy(name_list, $2)  != OG_SUCCESS) {
                            parser_yyerror("copy function list  failed.");
                        }
                        $$ = name_list;
                    }
        ;

AexprConst: ICONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_int_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | FCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_float_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | FCONST_F
            {
                expr_tree_t *expr = NULL;
                if (sql_create_binary_float_double_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | FCONST_D
            {
                expr_tree_t *expr = NULL;
                if (sql_create_binary_float_double_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | SCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | DATE_P SCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_datetime_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &expr, $2, DTYP_DATE, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init date expr failed");
                }
                $$ = expr;
            }
            | TIMESTAMP SCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_datetime_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                    &expr, $2, DTYP_TIMESTAMP, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init timestamp expr failed");
                }
                $$ = expr;
            }
            | NCHAR SCONST
            {
                /* National character string literal (N'...') - treat as regular string */
                expr_tree_t *expr = NULL;
                if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $2, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | XCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_hex_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init hex const expr failed");
                }
                $$ = expr;
            }
            | TRUE_P
            {
                expr_tree_t *expr = NULL;
                if (sql_create_bool_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, OG_TRUE, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | FALSE_P
            {
                expr_tree_t *expr = NULL;
                if (sql_create_bool_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, OG_FALSE, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | NULL_P
            {
                expr_tree_t *expr = NULL;
                if (sql_create_null_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
                }
                $$ = expr;
            }
            | INTERVAL SCONST interval_type
            {
                expr_tree_t *expr = NULL;
                if (sql_create_interval_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $2, $3, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init interval expr failed");
                }
                $$ = expr;
            }
        ;

year_month_unit:
            YEAR_P { $$ = IUO_YEAR; }
            | MONTH_P { $$ = IUO_MONTH; }
        ;

day_hour_minute_unit:
            DAY_P       { $$ = IUO_DAY; }
            | HOUR_P    { $$ = IUO_HOUR; }
            | MINUTE_P  { $$ = IUO_MINUTE; }
        ;

opt_year_month_unit:
            TO year_month_unit      { $$ = $2; }
            | /* EMPTY */           { $$ = IUO_MAX; }

interval_type:
            year_month_unit opt_type_modifiers opt_year_month_unit
                {
                    interval_info_t info;
                    int32 prec = ITVL_DEFAULT_YEAR_PREC;
                    info.type.datatype = OG_TYPE_INTERVAL_YM;
                    info.type.size = sizeof(interval_ym_t);
                    info.type.reserved = 0;
                    info.fmt = get_interval_unit($1);
                    if ($2 != NULL && $2->count > 0) {
                        if (sql_parse_datetime_precision_bison($2, @1.loc, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC, ITVL_MAX_YEAR_PREC, "YEAR") != OG_SUCCESS) {
                            parser_yyerror("invalid year precision");
                        }
                    }
                    if ($3 != IUO_MAX) {
                        if ($1 != IUO_YEAR) {
                            parser_yyerror("invalid field name");
                        }
                        info.fmt |= get_interval_unit($3);
                    }
                    info.type.year_prec = (uint8)prec;
                    $$ = info;
                }
            | day_hour_minute_unit opt_type_modifiers
                {
                    interval_info_t info;
                    int32 prec = ITVL_DEFAULT_DAY_PREC;
                    info.type.datatype = OG_TYPE_INTERVAL_DS;
                    info.type.size = sizeof(interval_ds_t);
                    info.type.frac_prec = 0;
                    info.fmt = get_interval_unit($1);
                    if ($2 != NULL && $2->count > 0) {
                        if (sql_parse_datetime_precision_bison($2, @1.loc, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
                            ITVL_MAX_DAY_PREC, ds_unit_to_str($1)) != OG_SUCCESS) {
                            parser_yyerror("invalid day precision");
                        }
                    }
                    info.type.day_prec = (uint8)prec;
                    $$ = info;
                }
            | day_hour_minute_unit opt_type_modifiers TO day_hour_minute_unit
                {
                    if ($4 < $1) {
                        parser_yyerror("-- invalid field name");
                    }
                    interval_info_t info;
                    int32 day_prec = ITVL_DEFAULT_DAY_PREC;
                    info.type.datatype = OG_TYPE_INTERVAL_DS;
                    info.type.size = sizeof(interval_ds_t);
                    info.fmt = get_interval_unit($1) | generate_interval_unit($1, $4);
                    if ($2 != NULL && $2->count > 0) {
                        if (sql_parse_datetime_precision_bison($2, @1.loc, &day_prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
                            ITVL_MAX_DAY_PREC, ds_unit_to_str($1)) != OG_SUCCESS) {
                            parser_yyerror("invalid day precision");
                        }
                    }
                    info.type.day_prec = (uint8)day_prec;
                    info.type.frac_prec = 0;
                    $$ = info;
                }
            | day_hour_minute_unit opt_type_modifiers TO SECOND_P opt_type_modifiers
                {
                    interval_info_t info;
                    int32 day_prec = ITVL_DEFAULT_DAY_PREC;
                    int32 frac_prec = ITVL_DEFAULT_SECOND_PREC;
                    info.type.datatype = OG_TYPE_INTERVAL_DS;
                    info.type.size = sizeof(interval_ds_t);
                    info.fmt = get_interval_unit($1) | generate_interval_unit($1, IUO_SECOND);
                    if ($2 != NULL && $2->count > 0) {
                        if (sql_parse_datetime_precision_bison($2, @1.loc, &day_prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
                            ITVL_MAX_DAY_PREC, ds_unit_to_str($1)) != OG_SUCCESS) {
                            parser_yyerror("invalid day precision");
                        }
                    }
                    if ($5 != NULL && $5->count > 0) {
                        if (sql_parse_datetime_precision_bison($5, @4.loc, &frac_prec, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
                            ITVL_MAX_SECOND_PREC, "fractional second") != OG_SUCCESS) {
                            parser_yyerror("invalid second precision");
                        }
                    }
                    info.type.day_prec = (uint8)day_prec;
                    info.type.frac_prec = (uint8)frac_prec;
                    $$ = info;
                }
            | SECOND_P opt_type_modifiers
                {
                    interval_info_t info;
                    int32 lead_prec = ITVL_DEFAULT_DAY_PREC;
                    int32 frac_prec = ITVL_DEFAULT_SECOND_PREC;
                    info.type.datatype = OG_TYPE_INTERVAL_DS;
                    info.type.size = sizeof(interval_ds_t);
                    info.fmt = IU_SECOND;
                    if ($2 != NULL && $2->count > 0) {
                        if (sql_parse_second_precision_bison($2, @1.loc, &lead_prec, &frac_prec) != OG_SUCCESS) {
                            parser_yyerror("invalid second precision");
                        }
                    }
                    info.type.day_prec = (uint8)lead_prec;
                    info.type.frac_prec = (uint8)frac_prec;
                    $$ = info;
                }
        ;

UpdateStmt: UPDATE hint_string from_list SET set_clause_list where_clause return_clause
            {
                sql_update_t *update_context = NULL;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                if (sql_alloc_mem(stmt->context, sizeof(sql_update_t), (void **)&update_context)) {
                    parser_yyerror("alloc mem failed.");
                }
                if (sql_init_update(og_yyget_extra(yyscanner)->core_yy_extra.stmt, update_context) != OG_SUCCESS) {
                    parser_yyerror("init sql_update_t failed.");
                }
                if ($2) {
                    og_get_hint_info(stmt, $2, &update_context->hint_info);
                }

                sql_join_node_t *join_node = $3;
                sql_array_concat(&update_context->query->tables, &join_node->tables);
                update_context->query->join_assist.join_node = join_node;
                update_context->query->join_assist.outer_node_count = sql_outer_join_count(join_node);
                if (update_context->query->join_assist.outer_node_count > 0) {
                    sql_parse_join_set_table_nullable(update_context->query->join_assist.join_node);
                }
                sql_remove_join_table(stmt, update_context->query);

                if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                    if (attach_pending_subselects_to_query(update_context->query,
                        &og_yyget_extra(yyscanner)->core_yy_extra.ssa) != OG_SUCCESS) {
                        parser_yyerror("attach subselects failed");
                    }
                }

                cm_galist_copy(update_context->pairs, $5);
                update_context->query->cond = $6;
                update_context->ret_columns = $7;
                if (sql_set_table_qb_name(stmt, update_context->query) != OG_SUCCESS) {
                    parser_yyerror("sql_set_table_qb_name failed ");
                }
                $$ = update_context;
            }
        ;

/* Column label --- allowed labels in "AS" clauses.
 * This presently includes *all* Postgres keywords.
 */
ColLabel:   IDENT                                   { $$ = $1; }
            | unreserved_keyword
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $1);
                    $$ = tmp;
                }
            | col_name_keyword
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $1);
                    $$ = tmp;
                }
            | reserved_keyword
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $1);
                    $$ = tmp;
                }
        ;

opt_merge_where_condition:
            WHERE cond_tree_expr                { $$ = $2; }
            | /* EMPTY */                       { $$ = NULL; }        ;

merge_update:
            UPDATE SET set_clause_list
                {
                    sql_update_t *update_context = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(sql_update_t), (void **)&update_context) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_update(og_yyget_extra(yyscanner)->core_yy_extra.stmt, update_context) != OG_SUCCESS) {
                        parser_yyerror("init sql_update_t failed.");
                    }
                    cm_galist_copy(update_context->pairs, $3);
                    $$ = update_context;
                }
        ;

merge_insert:
            INSERT '(' insert_column_list ')' values_clause
                {
                    sql_insert_t *insert_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_insert(stmt, insert_ctx) != OG_SUCCESS) {
                        parser_yyerror("init insert context failed ");
                    }
                    insert_ctx->pairs = $5;
                    column_value_pair_t *pair = NULL;
                    galist_t *columns = $3;
                    column_parse_info *column = NULL;
                    if (insert_ctx->pairs->count != columns->count) {
                        parser_yyerror("insert columns and values not matched");
                    }
                    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
                        column = (column_parse_info*)cm_galist_get(columns, i);
                        pair = (column_value_pair_t*)cm_galist_get(insert_ctx->pairs, i);
                        pair->column_name.value = column->col_name;
                    }
                    insert_ctx->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_ctx->pairs, 0))->exprs->count;
                    $$ = insert_ctx;
                }
            | INSERT values_clause
                {
                    sql_insert_t *insert_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)&insert_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_insert(stmt, insert_ctx) != OG_SUCCESS) {
                        parser_yyerror("init insert context failed ");
                    }
                    insert_ctx->pairs = $2;
                    insert_ctx->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_ctx->pairs, 0))->exprs->count;
                    $$ = insert_ctx;
                }
        ;

merge_when_update_clause: WHEN MATCHED THEN merge_update                        { $$ = $4; }
            ;

merge_when_insert_clause: WHEN NOT MATCHED THEN merge_insert                    { $$ = $5; }
        ;

merge_when_list:
            merge_when_update_clause opt_merge_where_condition merge_when_insert_clause opt_merge_where_condition
                {
                    merge_when_clause *merge_when = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(merge_when_clause), (void **)&merge_when) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    merge_when->update_ctx = $1;
                    merge_when->update_filter_cond = $2;
                    merge_when->insert_ctx = $3;
                    merge_when->insert_filter_cond = $4;
                    $$ = merge_when;
                }
            | merge_when_insert_clause opt_merge_where_condition merge_when_update_clause opt_merge_where_condition
                {
                    merge_when_clause *merge_when = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(merge_when_clause), (void **)&merge_when) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    merge_when->update_ctx = $3;
                    merge_when->update_filter_cond = $4;
                    merge_when->insert_ctx = $1;
                    merge_when->insert_filter_cond = $2;
                    $$ = merge_when;
                }
            | merge_when_insert_clause opt_merge_where_condition
                {
                    merge_when_clause *merge_when = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(merge_when_clause), (void **)&merge_when) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    merge_when->insert_ctx = $1;
                    merge_when->insert_filter_cond = $2;
                    $$ = merge_when;
                }
            | merge_when_update_clause opt_merge_where_condition
                {
                    merge_when_clause *merge_when = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(merge_when_clause), (void **)&merge_when) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    merge_when->update_ctx = $1;
                    merge_when->update_filter_cond = $2;
                    $$ = merge_when;
                }
        ;

MergeStmt:
            MERGE hint_string INTO insert_target
            USING table_ref
            ON '(' cond_tree_expr ')'
            merge_when_list
                {
                    sql_merge_t *merge_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_merge_t), (void **)&merge_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_merge(stmt, merge_ctx) != OG_SUCCESS) {
                        parser_yyerror("init merge context failed ");
                    }
                    if ($2) {
                        og_get_hint_info(stmt, $2, &merge_ctx->hint_info);
                    }
                    sql_table_t *merge_into_table = $4;
                    merge_into_table->id = 0;
                    if (sql_array_put(&merge_ctx->query->tables, merge_into_table) != OG_SUCCESS) {
                        parser_yyerror("put table into merge_ctx failed ");
                    }
                    sql_join_node_t *merge_into_join_node = NULL;
                    if (sql_create_join_node(stmt, JOIN_TYPE_NONE, merge_into_table, NULL, NULL, NULL, &merge_into_join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    sql_join_node_t *merge_using_join_node = $6;
                    if (merge_using_join_node->type != JOIN_TYPE_NONE) {
                        parser_yyerror("expect select query after 'USING'");
                    }
                    sql_table_t *merge_using_table = (sql_table_t*)sql_array_get(&merge_using_join_node->tables, 0);
                    merge_using_table->id = 1;
                    if (sql_array_put(&merge_ctx->query->tables, merge_using_table) != OG_SUCCESS) {
                        parser_yyerror("put table into merge_ctx failed ");
                    }
                    if (sql_create_join_node(stmt, JOIN_TYPE_COMMA, NULL, NULL, merge_into_join_node, merge_using_join_node,
                        &merge_ctx->query->join_assist.join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    merge_ctx->query->cond = $9;
                    merge_ctx->insert_ctx = $11->insert_ctx;
                    merge_ctx->insert_filter_cond = $11->insert_filter_cond;
                    merge_ctx->update_ctx = $11->update_ctx;
                    merge_ctx->update_filter_cond = $11->update_filter_cond;
                    if (merge_ctx->insert_ctx) {
                        merge_ctx->insert_ctx->table = merge_into_table;
                    }
                    if (merge_ctx->update_ctx) {
                        if (sql_array_put(&merge_ctx->update_ctx->query->tables, merge_into_table) != OG_SUCCESS) {
                            parser_yyerror("put table failed.");
                        }
                    }
                    if (sql_set_table_qb_name(stmt, merge_ctx->query) != OG_SUCCESS) {
                        parser_yyerror("sql_set_table_qb_name failed ");
                    }
                    $$ = merge_ctx;
                }
        ;

ReplaceStmt:
            REPLACE hint_string INTO insert_target '(' insert_column_list ')' values_clause
                {
                    sql_replace_t *replace_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)&replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_replace(stmt, replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("init replace context failed ");
                    }
                    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);
                    if ($2) {
                        og_get_hint_info(stmt, $2, &insert_ctx->hint_info);
                    }
                    insert_ctx->table = $4;
                    insert_ctx->flags |= INSERT_COLS_SPECIFIED;
                    insert_ctx->pairs = $8;
                    column_value_pair_t *pair = NULL;
                    galist_t *columns = $6;
                    column_parse_info *column = NULL;
                    if (insert_ctx->pairs->count != columns->count) {
                        parser_yyerror("insert columns and values not matched");
                    }
                    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
                        column = (column_parse_info*)cm_galist_get(columns, i);
                        if (column->owner.str != NULL && !cm_text_equal_ins(&column->owner, &insert_ctx->table->user.value)) {
                            parser_yyerror("invalid column name");
                        }
                        if ((column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_ctx->table->name.value)) &&
                            (column->table.str != NULL && !cm_text_equal_ins(&column->table, &insert_ctx->table->alias.value))) {
                            parser_yyerror("invalid column name");
                        }

                        pair = (column_value_pair_t*)cm_galist_get(insert_ctx->pairs, i);
                        pair->column_name.value = column->col_name;
                    }
                    insert_ctx->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_ctx->pairs, 0))->exprs->count;
                    if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                        sql_create_array(stmt->context, &insert_ctx->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                        sql_array_concat(&insert_ctx->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                        sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    }
                    $$ = replace_ctx;
                }
            | REPLACE hint_string INTO insert_target '(' insert_column_list ')' SelectStmt
                {
                    sql_replace_t *replace_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)&replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_replace(stmt, replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("init replace context failed ");
                    }
                    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);
                    if ($2) {
                        og_get_hint_info(stmt, $2, &insert_ctx->hint_info);
                    }
                    insert_ctx->table = $4;
                    insert_ctx->flags |= INSERT_COLS_SPECIFIED;
                    if (column_list_to_column_pairs(stmt, $6, &insert_ctx->pairs)) {
                        parser_yyerror("create column pairs failed.");
                    }
                    insert_ctx->select_ctx = $8;
                    insert_ctx->select_ctx->type = SELECT_AS_VALUES;
                    if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                        sql_create_array(stmt->context, &insert_ctx->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                        sql_array_concat(&insert_ctx->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                        sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    }
                    $$ = replace_ctx;
                }
            | REPLACE hint_string INTO insert_target values_clause
                {
                    sql_replace_t *replace_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)&replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_replace(stmt, replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("init replace context failed ");
                    }
                    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);
                    if ($2) {
                        og_get_hint_info(stmt, $2, &insert_ctx->hint_info);
                    }
                    insert_ctx->table = $4;
                    insert_ctx->pairs = $5;
                    insert_ctx->pairs_count = ((column_value_pair_t*)cm_galist_get(insert_ctx->pairs, 0))->exprs->count;
                    if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                        sql_create_array(stmt->context, &insert_ctx->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                        sql_array_concat(&insert_ctx->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                        sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    }
                    $$ = replace_ctx;
                }
            | REPLACE hint_string INTO insert_target SelectStmt
                {
                    sql_replace_t *replace_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)&replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_replace(stmt, replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("init replace context failed ");
                    }
                    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);
                    if ($2) {
                        og_get_hint_info(stmt, $2, &insert_ctx->hint_info);
                    }
                    insert_ctx->table = $4;
                    insert_ctx->select_ctx = $5;
                    insert_ctx->select_ctx->type = SELECT_AS_VALUES;
                    if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                        sql_create_array(stmt->context, &insert_ctx->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                        sql_array_concat(&insert_ctx->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                        sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    }
                    $$ = replace_ctx;
                }
            | REPLACE hint_string INTO insert_target SET replace_set_clause_list
                {
                    sql_replace_t *replace_ctx = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)&replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if (sql_init_replace(stmt, replace_ctx) != OG_SUCCESS) {
                        parser_yyerror("init replace context failed ");
                    }
                    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);
                    if ($2) {
                        og_get_hint_info(stmt, $2, &insert_ctx->hint_info);
                    }
                    insert_ctx->table = $4;
                    insert_ctx->pairs = $6;
                    column_value_pair_t *pair = NULL;
                    var_word_t var;
                    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
                        pair = (column_value_pair_t*)cm_galist_get(insert_ctx->pairs, i);
                        var = pair->column_expr->root->word;
                        if (var.column.user.value.str != NULL && !cm_text_equal_ins(&var.column.user.value, &insert_ctx->table->user.value)) {
                            parser_yyerror("invalid column name");
                        }
                        if ((var.column.table.value.str != NULL && !cm_text_equal_ins(&var.column.table.value, &insert_ctx->table->name.value)) &&
                            (var.column.table.value.str != NULL && !cm_text_equal_ins(&var.column.table.value, &insert_ctx->table->alias.value))) {
                            parser_yyerror("invalid column name");
                        }
                        pair->column_name = var.column.name;
                    }
                    insert_ctx->pairs_count++;
                    insert_ctx->flags |= INSERT_COLS_SPECIFIED;
                    if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                        sql_create_array(stmt->context, &insert_ctx->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                        sql_array_concat(&insert_ctx->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                        sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    }
                    $$ = replace_ctx;
                }
        ;

replace_set_clause_list:
            single_set_clause
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column pair list failed.");
                    }
                    cm_galist_insert(list, $1);
                    $$ = list;
                }
            | replace_set_clause_list ',' single_set_clause
                {
                    galist_t *list = $1;
                    cm_galist_insert(list, $3);
                    $$ = list;
                }
        ;

opt_if_exists: IF_P EXISTS                      { $$ = true; }
        | /*EMPTY*/        %prec UMINUS       { $$ = false; }
        ;

opt_or_replace: OR REPLACE                      { $$ = true; }
        | /*EMPTY*/                             { $$ = false; }
        ;

opt_drop_behavior:
            CASCADE                             { $$ = true; }
            | CASCADE CONSTRAINTS               { $$ = true; }
            | /* EMPTY */                       { $$ = false; /* default */ }
        ;

opt_cascade:
            CASCADE                             { $$ = true; }
            | /* EMPTY */                       { $$ = false; /* default */ }
        ;

opt_purge:
            PURGE                               { $$ = true; }
            | /* EMPTY */                       { $$ = false; }
        ;

opt_temporary:
            TEMPORARY                           { $$ = true; }
            | /* EMPTY */                       { $$ = false; }
        ;

on_list:
 	        ON any_name
 	            {
 	                $$ = $2;
 	            }
 	        | /*EMPTY*/
 	            {
 	                $$ = NULL;
 	            }
 	    ;

any_name:
            ColId
                {
                    name_with_owner *ret = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(name_with_owner), (void **)&ret) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    ret->name.str = $1;
                    ret->name.len = strlen($1);
                    $$ = ret;
                }
            | ColId '.' ColId
                {
                    name_with_owner *ret = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, sizeof(name_with_owner), (void **)&ret) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    ret->owner.str = $1;
                    ret->owner.len = strlen($1);
                    ret->name.str = $3;
                    ret->name.len = strlen($3);
                    $$ = ret;
                }
        ;

DropStmt:   DROP opt_temporary TABLE_P opt_if_exists any_name opt_drop_behavior opt_purge
                {
                    knl_drop_def_t *def = NULL;
                    knl_dictionary_t dc;
                    dc.type = DICT_TYPE_TABLE;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    def->temp = $2;
                    def->owner = $5->owner;
                    def->name = $5->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if ($6) {
                        def->options |= DROP_CASCADE_CONS;
                    }
                    def->purge = $7;
                    if (!$4) {
                        if (knl_open_dc_with_public(&stmt->session->knl_session, &def->owner, OG_TRUE, &def->name, &dc) != OG_SUCCESS) {
                            parser_yyerror("The table does not exist");
                        }
                        knl_close_dc(&dc);
                    } else {
                        def->options |= DROP_IF_EXISTS;
                    }
                    $$ = def;
                }
            | DROP INDEX_P opt_if_exists any_name on_list
                {
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_INDEX;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if ($3) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    def->owner = $4->owner;
                    def->name = $4->name;
                    if ($5) {
 	                    def->ex_owner = $5->owner;
 	                    def->ex_name = $5->name;
 	                }
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if ($5 && def->ex_owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->ex_owner);
                    }
                    if ($5 && (cm_compare_text_ins(&def->owner, &def->ex_owner) != 0)) {
                        parser_yyerror("index user is not consistent with table user");
                    }
                    $$ = def;
                }
            | DROP SEQUENCE opt_if_exists any_name
                {
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_SEQUENCE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if ($3) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    def->owner = $4->owner;
                    def->name = $4->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    $$ = def;
                }
            | DROP TABLESPACE any_name opt_drop_tbsp
                {
                    knl_drop_space_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_TABLESPACE;
                    if ($3->owner.str != NULL) {
                        parser_yyerror("incorrect tablespace name");
                    }
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->obj_name = $3->name;
                    def->options |= $4;
                    $$ = def;
                }
            | DROP VIEW opt_if_exists any_name opt_drop_behavior
                {
                    knl_drop_def_t *def = NULL;
                    knl_dictionary_t dc;
                    dc.type = OGSQL_TYPE_DROP_VIEW;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_VIEW;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    def->owner = $4->owner;
                    def->name = $4->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if ($5) {
                        def->options |= DROP_CASCADE_CONS;
                    }
                    if (!$3) {
                        if (knl_open_dc_with_public(&stmt->session->knl_session, &def->owner, OG_TRUE, &def->name, &dc) != OG_SUCCESS) {
                            parser_yyerror("The view does not exist");
                        }
                        knl_close_dc(&dc);
                    } else {
                        def->options |= DROP_IF_EXISTS;
                    }
                    $$ = def;
                }
            | DROP USER opt_if_exists UserId opt_cascade
                {
                    knl_drop_user_t *def = NULL;
                    text_t user;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_USER;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_user_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    if ($3) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    if (contains_nonnaming_char($4)) {
                        parser_yyerror("invalid user name");
                    }
                    cm_str2text($4, &user);
                    if (sql_copy_prefix_tenant(stmt, (text_t *)&user, &def->owner, sql_copy_name) != OG_SUCCESS) {
                        parser_yyerror("copy prefix tenant failed");
                    }
                    def->purge = $5;
                    $$ = def;
                }
            | DROP TENANT opt_if_exists tenant_name opt_cascade
                {
                    knl_drop_tenant_t *def = NULL;
                    text_t tenant;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_TENANT;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_tenant_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    CM_MAGIC_SET(def, knl_drop_tenant_t);
                    if ($3) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    if (contains_nonnaming_char($4)) {
                        OG_SRC_THROW_ERROR(@4.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
                        YYABORT;
                    }
                    cm_str2text($4, &tenant);
                    if (sql_copy_name(stmt->context, &tenant, &def->name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed");
                    }
                    if ($5) {
                        def->options |= DROP_CASCADE_CONS;
                    }
                    $$ = def;
                }
            | DROP opt_public SYNONYM opt_if_exists any_name opt_force
                {
                    knl_drop_def_t *def = NULL;
                    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_SYNONYM;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($4) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    if ($5->owner.str != NULL) {
                        if ($2) {
                            if (cm_compare_text_str_ins(&($5->owner), PUBLIC_USER) != 0) {
                                parser_yyerror("owner of object should be public");
                            }
                            if (sql_copy_name(stmt->context, &public_user, &def->owner) != OG_SUCCESS) {
                                parser_yyerror("copy name failed");
                            }
                        } else if (sql_copy_prefix_tenant(stmt, &($5->owner), &def->owner, sql_copy_name) != OG_SUCCESS) {
                            parser_yyerror("copy name failed");
                        }
                        def->name = $5->name;
                    } else {
                        if ($2 && sql_copy_text(stmt->context, &public_user, &def->owner) != OG_SUCCESS) {
                            parser_yyerror("copy name failed");
                        } else if (!$2) {
                            cm_str2text(stmt->session->curr_schema, &def->owner);
                        }
                        def->name = $5->name;
                    }
                    if ($6) {
                        def->options |= DROP_CASCADE_CONS;
                    }
                    $$ = def;
                }
            | DROP ROLE UserId
                {
                    knl_drop_def_t *def = NULL;
                    text_t user;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_ROLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cm_str2text($3, &user);
                    if (sql_copy_name(stmt->context, &user, &def->name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed");
                    }
                    $$ = def;
                }
            | DROP PROFILE DEFAULT opt_cascade
                {
                    parser_yyerror("cannot drop PUBLIC_DEFAULT profile");
                }
            | DROP PROFILE ColId opt_cascade
                {
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_PROFILE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->name.str = $3;
                    def->name.len = strlen($3);
                    if ($4) {
                        def->options |= DROP_CASCADE_CONS;
                    }
                    $$ = def;
                }
            | DROP DIRECTORY ColId
                {
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_DIRECTORY;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->name.str = $3;
                    def->name.len = strlen($3);
                    $$ = def;
                }
            | DROP FUNCTION opt_if_exists any_name
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_FUNC;
                    drop_def->type = PL_FUNCTION;
                    if ($3) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $4->owner;
                    drop_def->obj.name = $4->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    $$ = drop_def;
                }
            | DROP PROCEDURE opt_if_exists any_name
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_PROC;
                    drop_def->type = PL_PROCEDURE;
                    if ($3) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $4->owner;
                    drop_def->obj.name = $4->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    $$ = drop_def;
                }
            | DROP TRIGGER opt_if_exists any_name
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_TRIG;
                    drop_def->type = PL_PROCEDURE;
                    if ($3) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $4->owner;
                    drop_def->obj.name = $4->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    $$ = drop_def;
                }
            | DROP PACKAGE opt_if_exists any_name
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_PACK_SPEC;
                    drop_def->type = PL_PACKAGE_SPEC;
                    if ($3) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $4->owner;
                    drop_def->obj.name = $4->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    $$ = drop_def;
                }
            | DROP PACKAGE BODY_P opt_if_exists any_name
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_PACK_BODY;
                    drop_def->type = PL_PACKAGE_BODY;
                    if ($4) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $5->owner;
                    drop_def->obj.name = $5->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    $$ = drop_def;
                }
            | DROP TYPE_P opt_if_exists any_name opt_force
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_TYPE_SPEC;
                    drop_def->type = PL_TYPE_SPEC;
                    if ($3) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $4->owner;
                    drop_def->obj.name = $4->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    if ($5) {
                        drop_def->option |= DROP_TYPE_FORCE;
                    }
                    $$ = drop_def;
                }
            | DROP TYPE_P BODY_P opt_if_exists any_name opt_force
                {
                    pl_drop_def_t *drop_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_drop_def_t), (void **)&drop_def)) {
                        parser_yyerror("alloc mem failed");
                    }
                    stmt->context->type = OGSQL_TYPE_DROP_TYPE_BODY;
                    drop_def->type = PL_TYPE_BODY;
                    if ($4) {
                        drop_def->option |= DROP_IF_EXISTS;
                    }
                    sql_init_udo(&drop_def->obj);
                    drop_def->obj.user = $5->owner;
                    drop_def->obj.name = $5->name;
                    if (drop_def->obj.user.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &drop_def->obj.user);
                    }
                    if ($6) {
                        drop_def->option |= DROP_TYPE_FORCE;
                    }
                    $$ = drop_def;
                }
            | DROP DATABASE ddl_passthrough_tail
                {
                    OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "DROP DATABASE");
                    YYABORT;
                    $$ = NULL;
                }
            | DROP LIBRARY opt_if_exists any_name
                {
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_LIBRARY;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($3) {
                        def->options |= DROP_IF_EXISTS;
                    }
                    def->owner = $4->owner;
                    def->name = $4->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    $$ = def;
                }
        ;

AlterSystemStmt:
            ALTER SYSTEM_P SWITCH LOGFILE
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_SWITCHLOG;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P SET IDENT '=' alter_param_value opt_set_scope
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->is_coord_conn = IS_COORD_CONN(stmt->session);
                    sys_def->action = ALTER_SYS_SET_PARAM;
                    BISON_MEM_STRDUP(sys_def->param, $4);
                    cm_str_upper(sys_def->param);
                    BISON_MEM_STRDUP(sys_def->value, $6);
                    sys_def->scope = $7;

                    if (sql_bison_verify_sys_param(&stmt->session->knl_session, sys_def) != OG_SUCCESS) {
                        parser_yyerror("verify system parameter failed");
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P SET REPLICATION_P ON SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    BISON_MEM_STRDUP(sys_def->value, $6);

                    sys_def->action = ALTER_SYS_MODIFY_REPLICA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P SET REPLICATION_P OFF
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_STOP_REPLICA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P LOAD DICTIONARY FOR any_name
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    name_with_owner *name_owner = $6;
                    text_t owner_name;
                    text_t object_name;

                    if (CM_IS_EMPTY(&name_owner->owner)) {
                        cm_str2text(stmt->session->curr_schema, &owner_name);
                    } else {
                        owner_name = name_owner->owner;
                    }

                    if (sql_copy_prefix_tenant(stmt, &owner_name, &object_name, sql_copy_name) != OG_SUCCESS) {
                        parser_yyerror("copy prefix tenant failed");
                    }
                    if (cm_text2str(&object_name, sys_def->param, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
                        parser_yyerror("copy user name failed");
                    }
                    if (sql_copy_name(stmt->context, &name_owner->name, &object_name) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }
                    if (cm_text2str(&object_name, sys_def->value, OG_PARAM_BUFFER_SIZE) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }

                    sys_def->action = ALTER_SYS_LOAD_DC;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P INIT DICTIONARY
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_INIT_ENTRY;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P FLUSH BUFFER_P
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_FLUSH_BUFFER;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P FLUSH SQLPOOL
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_FLUSH_SQLPOOL;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P RECYCLE SHAREDPOOL opt_force
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_RECYCLE_SHAREDPOOL;
                    sys_def->force_recycle = $5;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DUMP DATAFILE ICONST PAGE ICONST opt_dump_to_file
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_DUMP_PAGE;
                    sys_def->page_id.file = $5;
                    sys_def->page_id.page = $7;

                    if ($8 != NULL && $8->len > 0) {
                        BISON_MEM_STRDUP(sys_def->out_file.str, $8->str);
                        sys_def->out_file.len = strlen($8->str);

                        char real_name[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
                        if (sql_get_real_path(&sys_def->out_file, real_name) != OG_SUCCESS) {
                            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt", T2S(&sys_def->out_file));
                            YYABORT;
                        }
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DUMP CTRLFILE opt_dump_to_file
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_DUMP_CTRLPAGE;

                    if ($5 != NULL && $5->len > 0) {
                        BISON_MEM_STRDUP(sys_def->out_file.str, $5->str);
                        sys_def->out_file.len = strlen($5->str);
                        
                        char real_name[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
                        if (sql_get_real_path(&sys_def->out_file, real_name) != OG_SUCCESS) {
                            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt", T2S(&sys_def->out_file));
                            YYABORT;
                        }
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DUMP CATALOG_P TABLE_P any_name opt_dump_to_file
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_DUMP_DC;
                    sys_def->dump_info.dump_type = DC_DUMP_TABLE;

                    name_with_owner *name_owner = $6;
                    text_t owner_name;

                    if (CM_IS_EMPTY(&name_owner->owner)) {
                        cm_str2text(stmt->session->curr_schema, &owner_name);
                    } else {
                        owner_name = name_owner->owner;
                    }

                    if (sql_copy_prefix_tenant(stmt, &owner_name, &sys_def->dump_info.user_name,
                        sql_copy_name) != OG_SUCCESS) {
                        parser_yyerror("copy prefix tenant failed");
                    }
                    if (sql_copy_name(stmt->context, &name_owner->name, &sys_def->dump_info.table_name)
                        != OG_SUCCESS) {
                        parser_yyerror("copy table name failed");
                    }
                    if (sql_check_dump_priv(stmt, sys_def) != OG_SUCCESS) {
                        parser_yyerror("check dump priv failed");
                    }

                    if ($7 != NULL && $7->len > 0) {
                        BISON_MEM_STRDUP(sys_def->dump_info.dump_file.str, $7->str);
                        sys_def->dump_info.dump_file.len = strlen($7->str);

                        char real_name[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
                        if (sql_get_real_path(&sys_def->dump_info.dump_file, real_name) != OG_SUCCESS) {
                            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt",
                                T2S(&sys_def->dump_info.dump_file));
                            YYABORT;
                        }
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DUMP CATALOG_P USER IDENT opt_dump_to_file
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_DUMP_DC;
                    sys_def->dump_info.dump_type = DC_DUMP_USER;

                    text_t text;
                    cm_str2text($6, &text);
                    if (sql_copy_prefix_tenant(stmt, &text, &sys_def->dump_info.user_name, sql_copy_name)
                        != OG_SUCCESS) {
                        parser_yyerror("copy prefix tenant failed");
                    }
                    if (sql_check_dump_priv(stmt, sys_def) != OG_SUCCESS) {
                        parser_yyerror("check dump priv failed");
                    }

                    if ($7 != NULL && $7->len > 0) {
                        BISON_MEM_STRDUP(sys_def->dump_info.dump_file.str, $7->str);
                        sys_def->dump_info.dump_file.len = strlen($7->str);

                        char real_name[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
                        if (sql_get_real_path(&sys_def->dump_info.dump_file, real_name) != OG_SUCCESS) {
                            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt",
                                T2S(&sys_def->dump_info.dump_file));
                            YYABORT;
                        }
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P KILL SESSION SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t sid_str;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    cm_str2text($5, &sid_str);
                    if (sql_parse_sid_serial_bison(&sid_str, @5.loc, &sys_def->session_id, &sys_def->serial_id, &sys_def->node_id) != OG_SUCCESS) {
                        parser_yyerror("parse sid serial failed");
                    }

                    sys_def->action = ALTER_SYS_KILL_SESSION;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P RESET STATISTICS
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_RESET_STATISTIC;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P CHECKPOINT opt_ckpt_type
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_CHECKPOINT;
                    sys_def->ckpt_type = $4;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P ARCHIVE_SET IDENT '=' alter_param_value opt_set_scope opt_arch_set_type
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->is_coord_conn = IS_COORD_CONN(stmt->session);
                    sys_def->action = ALTER_SYS_ARCHIVE_SET;
                    BISON_MEM_STRDUP(sys_def->param, $4);
                    cm_str_upper(sys_def->param);
                    BISON_MEM_STRDUP(sys_def->value, $6);
                    sys_def->scope = $7;
                    sys_def->arch_set_type = $8;

                    if (sql_bison_verify_sys_param(&stmt->session->knl_session, sys_def) != OG_SUCCESS) {
                        parser_yyerror("verify system parameter failed");
                    }

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P ARCHIVE_SET REPLICATION_P ON SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    BISON_MEM_STRDUP(sys_def->value, $6);
                    sys_def->action = ALTER_SYS_MODIFY_REPLICA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P ARCHIVE_SET REPLICATION_P OFF
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_STOP_REPLICA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P RELOAD HBA CONFIG
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_RELOAD_HBA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P RELOAD PBL CONFIG
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_RELOAD_PBL;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P REFRESH SYSDBA_P PRIVILEGE
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_REFRESH_SYSDBA;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P ADD_P HBA ENTRY SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t hba_text;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cm_str2text($6, &hba_text);
                    if (hba_text.len > HBA_MAX_LINE_SIZE) {
                        OG_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, 1);
                        YYABORT;
                    }
                    if (cm_check_hba_entry_legality($6) != OG_SUCCESS) {
                        parser_yyerror("check hba entry legality failed");
                    }
                    errno_t ret = memcpy_s(sys_def->hba_node, HBA_MAX_LINE_SIZE, $6, hba_text.len);
                    knl_securec_check(ret);
                    sys_def->hba_node[hba_text.len] = '\0';

                    sys_def->action = ALTER_SYS_ADD_HBA_ENTRY;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P ADD_P LSNR_ADDR SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    BISON_MEM_STRDUP(sys_def->value, $5);

                    sys_def->action = ALTER_SYS_ADD_LSNR_ADDR;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DELETE_P HBA ENTRY SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t hba_text;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    cm_str2text($6, &hba_text);
                    if (hba_text.len > HBA_MAX_LINE_SIZE) {
                        OG_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, 1);
                        YYABORT;
                    }
                    if (cm_check_hba_entry_legality($6) != OG_SUCCESS) {
                        parser_yyerror("check hba entry legality failed");
                    }
                    errno_t ret = memcpy_s(sys_def->hba_node, HBA_MAX_LINE_SIZE, $6, hba_text.len);
                    knl_securec_check(ret);
                    sys_def->hba_node[hba_text.len] = '\0';

                    sys_def->action = ALTER_SYS_DEL_HBA_ENTRY;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DELETE_P LSNR_ADDR SCONST
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    BISON_MEM_STRDUP(sys_def->value, $5);

                    sys_def->action = ALTER_SYS_DELETE_LSNR_ADDR;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P DEBUG MODE IDENT '=' debug_mode_value
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    BISON_MEM_STRDUP(sys_def->param, $5);
                    cm_str_upper(sys_def->param);
                    BISON_MEM_STRDUP(sys_def->value, $7);

                    sys_def->action = ALTER_SYS_DEBUG_MODE;
                    debug_config_item_t *debug_params = NULL;
                    debug_config_item_t *item = NULL;
                    uint32 count;

                    srv_get_debug_config_info(&debug_params, &count);

                    for (uint32 i = 0; i < count; i++) {
                        if (cm_str_equal_ins(debug_params[i].name, sys_def->param)) {
                            item = &debug_params[i];
                            break;
                        }
                    }

                    if (item == NULL) {
                        OG_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, sys_def->param);
                        YYABORT;
                    }
                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P STOP BUILD
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_STOP_BUILD;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
            | ALTER SYSTEM_P REPAIR CATALOG_P
                {
                    knl_alter_sys_def_t *sys_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    SQL_SET_IGNORE_PWD(stmt->session);
                    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
                    stmt->context->type = OGSQL_TYPE_ALTER_SYSTEM;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    sys_def->action = ALTER_SYS_REPAIR_CATALOG;

                    stmt->context->entry = sys_def;
                    $$ = sys_def;
                }
        ;

AlterSessionStmt:
            ALTER SESSION SET altsession_set_key '=' altsession_set_value
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_SET;
                    if (sql_parse_altses_set_bison(stmt, &def->setting, $4, $6, @4.loc) != OG_SUCCESS) {
                        parser_yyerror("parse alter session set failed");
                    }

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION DISABLE_P TRIGGERS
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_DISABLE;
                    def->setable.enable = OG_FALSE;
                    def->setable.able_type = ABLE_TRIGGERS;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION DISABLE_P INTERACTIVE TIMEOUT
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_DISABLE;
                    def->setable.enable = OG_FALSE;
                    def->setable.able_type = ABLE_INAV_TO;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION DISABLE_P NOLOGGING
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_DISABLE;
                    def->setable.enable = OG_FALSE;
                    def->setable.able_type = ABLE_NOLOGGING;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION DISABLE_P OPTINFO_LOG
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_DISABLE;
                    def->setable.enable = OG_FALSE;
                    def->setable.able_type = ABLE_OPTINFO;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION ENABLE_P TRIGGERS
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_ENABLE;
                    def->setable.enable = OG_TRUE;
                    def->setable.able_type = ABLE_TRIGGERS;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION ENABLE_P INTERACTIVE TIMEOUT
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_ENABLE;
                    def->setable.enable = OG_TRUE;
                    def->setable.able_type = ABLE_INAV_TO;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION ENABLE_P NOLOGGING
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_ENABLE;
                    def->setable.enable = OG_TRUE;
                    def->setable.able_type = ABLE_NOLOGGING;

                    stmt->context->entry = def;
                    $$ = def;
                }
            | ALTER SESSION ENABLE_P OPTINFO_LOG
                {
                    alter_session_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_ALTER_SESSION;

                    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    def->action = ALTSES_ENABLE;
                    def->setable.enable = OG_TRUE;
                    def->setable.able_type = ABLE_OPTINFO;

                    stmt->context->entry = def;
                    $$ = def;
                }
        ;

opt_drop_tbsp:
            INCLUDING CONTENTS opt_drop_behavior
                {
                    $$ = $3 ? TABALESPACE_INCLUDE | TABALESPACE_CASCADE : TABALESPACE_INCLUDE;
                }
            | INCLUDING CONTENTS AND DATAFILES opt_drop_behavior
                {
                    $$ = $5 ? TABALESPACE_INCLUDE | TABALESPACE_DFS_AND | TABALESPACE_CASCADE : TABALESPACE_INCLUDE | TABALESPACE_DFS_AND;
                }
            | INCLUDING CONTENTS KEEP DATAFILES opt_drop_behavior
                {
                    $$ = $5 ? TABALESPACE_INCLUDE | TABALESPACE_CASCADE : TABALESPACE_INCLUDE;
            }
            | /* EMPTY */
                {
                    $$ = 0;
                }
        ;

opt_set_scope:
            /*
             * Native ALTER SYSTEM accepts scope values that may be scanned as
             * keywords, for example BOTH and MEMORY.
             */
            SCOPE '=' ColLabel
                {
                    if (cm_str_equal_ins($3, "memory")) {
                        $$ = CONFIG_SCOPE_MEMORY;
                    } else if (cm_str_equal_ins($3, "pfile")) {
                        $$ = CONFIG_SCOPE_DISK;
                    } else if (cm_str_equal_ins($3, "both")) {
                        $$ = CONFIG_SCOPE_BOTH;
                    } else {
                        parser_yyerror("invalid scope value");
                        $$ = CONFIG_SCOPE_BOTH;
                    }
                }
            | /* EMPTY */
                {
                    $$ = CONFIG_SCOPE_BOTH;
                }
        ;

opt_dump_to_file:
            TO SCONST
                {
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, $2);
                    text_t *text_ptr = NULL;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(text_t), (void **)&text_ptr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    text_ptr->str = tmp;
                    text_ptr->len = strlen(tmp);
                    $$ = text_ptr;
                }
            | /* EMPTY */
                {
                    $$ = NULL;
                }
        ;

opt_arch_set_type:
            GLOBAL
                {
                    $$ = ARCH_SET_TYPE_GLOBAL;
                }
            | LOCAL
                {
                    $$ = ARCH_SET_TYPE_LOCAL;
                }
            | /* EMPTY */
                {
                    $$ = ARCH_SET_TYPE_LOCAL;
                }
        ;

opt_ckpt_type:
            GLOBAL
                {
                    $$ = CKPT_TYPE_GLOBAL;
                }
            | LOCAL
                {
                    $$ = CKPT_TYPE_LOCAL;
                }
            | /* EMPTY */
                {
                    $$ = CKPT_TYPE_LOCAL;
                }
        ;

UserId:     ColId                                           { $$ = $1; }
        ;

opt_public:
            PUBLIC                                          { $$ = true; }
            | /* EMPTY */                                   { $$ = false; }
        ;

opt_force:
            FORCE                                           { $$ = true; }
            | /* EMPTY */                                   { $$ = false; }
        ;

truncate_option:
            PURGE                                           { $$ = TRUNC_PURGE_STORAGE; }
            | DROP STORAGE                                  { $$ = TRUNC_DROP_STORAGE; }
            | REUSE STORAGE                                 { $$ = TRUNC_REUSE_STORAGE; }
        ;

truncate_options:
            truncate_option                                 { $$ = $1; }
            | truncate_options truncate_option
                {
                    uint32 option = $1 | $2;
                    if ((option & TRUNC_REUSE_STORAGE) && (option & TRUNC_DROP_STORAGE)) {
                        parser_yyerror("unexpected text conflict");
                    }
                    $$ = option;
                }
        ;

opt_truncate_options:
            truncate_options                                { $$ = $1; }
            | /* EMPTY */                                   { $$ = 0; }

TruncateStmt: TRUNCATE TABLE_P any_name opt_truncate_options
                    {
                        knl_trunc_def_t *def = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        knl_dictionary_t dc;
                        dc.type = DICT_TYPE_TABLE;
                        stmt->context->type = OGSQL_TYPE_TRUNCATE_TABLE;

                        if (sql_alloc_mem(stmt->context, sizeof(knl_trunc_def_t), (void **)&def) != OG_SUCCESS) {
                            parser_yyerror("alloc mem failed");
                        }
                        def->owner = $3->owner;
                        def->name = $3->name;
                        if (def->owner.str == NULL) {
                            cm_str2text(stmt->session->curr_schema, &def->owner);
                        }
                        if (knl_open_dc_with_public(&stmt->session->knl_session, &def->owner, OG_TRUE, &def->name, &dc) != OG_SUCCESS) {
                            parser_yyerror("The table does not exist");
                        }
                        knl_close_dc(&dc);
                        def->option = $4;
                        $$ = def;
                    }
            ;

partition_or_subpartition:
            PARTITION                                       { $$ = true; }
            | SUBPARTITION                                  { $$ = false; }
        ;

FlashStmt:
            FLASHBACK TABLE_P any_name TO SCN a_expr
                {
                    knl_flashback_def_t *def = NULL;
                    sql_verifier_t verf = { 0 };
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->expr = $6;
                    verf.context = stmt->context;
                    verf.stmt = stmt;
                    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
                        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
                        SQL_EXCL_ROWNODEID;
                    if (sql_verify_expr(&verf, def->expr) != OG_SUCCESS) {
                        parser_yyerror("verify expr failed");
                    }
                    if (!OG_IS_WEAK_NUMERIC_TYPE(TREE_DATATYPE((expr_tree_t *)def->expr))) {
                        parser_yyerror("scn expr mismatch");
                    }
                    def->type = FLASHBACK_TO_SCN;
                    $$ = def;
                }
            | FLASHBACK TABLE_P any_name TO TIMESTAMP a_expr
                {
                    knl_flashback_def_t *def = NULL;
                    sql_verifier_t verf = { 0 };
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->expr = $6;
                    verf.context = stmt->context;
                    verf.stmt = stmt;
                    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
                        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
                        SQL_EXCL_ROWNODEID;
                    if (sql_verify_expr(&verf, def->expr) != OG_SUCCESS) {
                        parser_yyerror("verify expr failed");
                    }
                    if (!OG_IS_DATETIME_TYPE(TREE_DATATYPE((expr_tree_t *)def->expr))) {
                        parser_yyerror("timestamp expr mismatch");
                    }
                    def->type = FLASHBACK_TO_TIMESTAMP;
                    $$ = def;
                }
            | FLASHBACK TABLE_P any_name TO BEFORE DROP
                {
                    knl_flashback_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->type = FLASHBACK_DROP_TABLE;
                    $$ = def;
                }
            | FLASHBACK TABLE_P any_name TO BEFORE DROP RENAME TO ColId
                {
                    knl_flashback_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->ext_name.len = strlen($9);
                    def->ext_name.str = $9;
                    def->type = FLASHBACK_DROP_TABLE;
                    $$ = def;
                }
            | FLASHBACK TABLE_P any_name TO BEFORE TRUNCATE opt_force
                {
                    knl_flashback_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->force = $7;
                    def->type = FLASHBACK_TRUNCATE_TABLE;
                    $$ = def;
                }
            | FLASHBACK TABLE_P any_name partition_or_subpartition ColId TO BEFORE TRUNCATE opt_force
                {
                    knl_flashback_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_FLASHBACK_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->type = $4 ? FLASHBACK_TABLE_PART : FLASHBACK_TABLE_SUBPART;
                    def->ext_name.len = strlen($5);
                    def->ext_name.str = $5;
                    def->force = $9;
                    $$ = def;
                }
        ;

CommentStmt:
            COMMENT ON TABLE_P any_name IS SCONST
                {
                    knl_comment_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_COMMENT;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_comment_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->type = COMMENT_ON_TABLE;
                    def->owner = $4->owner;
                    def->name = $4->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if (strlen($6) != 0) {
                        if (strlen($6) > DDL_MAX_COMMENT_LEN) {
                            parser_yyerror("comment content cannot exceed 4000 bytes");
                        }
                        def->comment.str = $6;
                        def->comment.len = strlen($6);
                    } else {
                        def->comment.str = (g_instance->sql.enable_empty_string_null == OG_TRUE) ? NULL : "";
                    }
                    $$ = def;
                }
            | COMMENT ON COLUMN insert_column_item IS SCONST
                {
                    knl_comment_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_COMMENT;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_comment_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->type = COMMENT_ON_COLUMN;
                    def->owner = $4->owner;
                    def->name = $4->table;
                    def->column = $4->col_name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if (strlen($6) != 0) {
                        if (strlen($6) > DDL_MAX_COMMENT_LEN) {
                            parser_yyerror("comment content cannot exceed 4000 bytes");
                        }
                        def->comment.str = $6;
                        def->comment.len = strlen($6);
                    } else {
                        def->comment.str = (g_instance->sql.enable_empty_string_null == OG_TRUE) ? NULL : "";
                    }
                    $$ = def;
                }
        ;

AnalyzeStmt:
            ANALYZE TABLE_P any_name COMPUTE STATISTICS
                {
                    knl_analyze_tab_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_ANALYSE_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_tab_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    $$ = def;
                }
            | ANALYZE TABLE_P any_name COMPUTE STATISTICS FOR REPORT
                {
                    knl_analyze_tab_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_ANALYSE_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_tab_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->is_report = OG_TRUE;
                    $$ = def;
                }
            | ANALYZE TABLE_P any_name COMPUTE STATISTICS FOR REPORT SAMPLE ICONST
                {
                    knl_analyze_tab_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_ANALYSE_TABLE;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_tab_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->is_report = OG_TRUE;
                    if ($9 > MAX_SAMPLE_RATIO) {
                        parser_yyerror("the valid range of estimate_percent is [0,100]");
                    }
                    def->sample_ratio = $9;
                    def->sample_type = STATS_SPECIFIED_SAMPLE;
                    
                    $$ = def;
                }
            | ANALYZE INDEX_P any_name COMPUTE STATISTICS
                {
                    knl_analyze_index_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_ANALYZE_INDEX;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_index_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    $$ = def;
                }
            | ANALYZE INDEX_P any_name ESTIMATE STATISTICS ICONST
                {
                    knl_analyze_index_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_ANALYZE_INDEX;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_index_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->owner = $3->owner;
                    def->name = $3->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    def->sample_ratio = (double)$6 / 100;
                    $$ = def;
                }
        ;

database_name:
            ColId                           { $$ = $1; }
        ;

createdb_user_name:
            UserId
                {
                    createdb_user_token *user = NULL;
                    char *origin_name = og_yyget_extra(yyscanner)->core_yy_extra.origin_str;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_user_token), (void **)&user) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    user->name = $1;
                    user->display_name = origin_name != NULL ? origin_name : $1;
                    user->loc = @1.loc;
                    $$ = user;
                }
        ;

createdb_user_opt:
            USER createdb_user_name IDENTIFIED BY SCONST
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_USER_OPT;
                    opt->user.user_name = $2->name;
                    opt->user.display_name = $2->display_name;
                    opt->user.user_loc = $2->loc;
                    opt->user.password = $5;
                    $$ = opt;
                }
        ;

files:
            SCONST
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = NULL;
                    text_t *file_name = NULL;
                    text_t raw;
                    raw.str = $1;
                    raw.len = strlen($1);
                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create controlfile list failed.");
                    }
                    if (cm_galist_new(list, sizeof(text_t), (pointer_t *)&file_name) != OG_SUCCESS) {
                        parser_yyerror("new controlfile failed.");
                    }
                    if (sql_copy_file_name(stmt->context, (text_t *)&raw, file_name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    $$ = list;
                }
            | files ',' SCONST
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = $1;
                    text_t *file_name = NULL;
                    text_t raw;
                    raw.str = $3;
                    raw.len = strlen($3);
                    if (cm_galist_new(list, sizeof(text_t), (pointer_t *)&file_name) != OG_SUCCESS) {
                        parser_yyerror("new controlfile failed.");
                    }
                    if (sql_copy_file_name(stmt->context, (text_t *)&raw, file_name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    $$ = list;
                }
        ;

createdb_controlfile_opt:
            CONTROLFILE '(' files ')'
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_CONTROLFILE_OPT;
                    opt->list = $3;
                    $$ = opt;
                }
        ;

createdb_charset_opt:
            CHARACTER SET ColId
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_CHARSET_OPT;
                    opt->charset = $3;
                    $$ = opt;
                }
        ;

num_size:
        ICONST
            {
                $$ = $1;
            }
        | SIZE_B
            {
                int64 res = 0;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                $$ = res;
            }
        | SIZE_KB
            {
                int64 res = 0;
                int64 unit = 10;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
        | SIZE_MB
            {
                int64 res = 0;
                int64 unit = 20;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
        | SIZE_GB
            {
                int64 res = 0;
                int64 unit = 30;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
        | SIZE_TB
            {
                int64 res = 0;
                int64 unit = 40;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
        | SIZE_PB
            {
                int64 res = 0;
                int64 unit = 50;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
        | SIZE_EB
            {
                int64 res = 0;
                int64 unit = 60;
                if (strGetInt64($1, &res) != OG_SUCCESS) {
                    parser_yyerror("get int64 failed");
                }
                if (res > (OG_MAX_INT64 >> unit)) {
                    parser_yyerror("int64 overflow");
                }
                res = res << unit;
                $$ = res;
            }
    ;

opt_blocksize:
            BOLCKSIZE num_size                                  { $$ = $2; }
            | /* EMPTY */                                       { $$ = 0; }
        ;

logfile:
            SCONST SIZE num_size opt_blocksize
                {
                    knl_device_def_t *log_file = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_device_def_t), (void **)&log_file) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    const text_t name = { $1, strlen($1) };
                    if (sql_copy_file_name(stmt->context, (text_t *)&name, &log_file->name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    log_file->size = $3;
                    log_file->block_size = $4;
                    if (log_file->block_size != FILE_BLOCK_SIZE_512 && log_file->block_size != FILE_BLOCK_SIZE_4096) {
                        parser_yyerror("invalid block size");
                    }
                    $$ = log_file;
                }
        ;

logfiles:
            logfile
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create logfile list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert logfile failed.");
                    }
                    $$ = list;
                }
            | logfiles ',' logfile
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert logfile failed.");
                    }
                    $$ = list;
                }
        ;

opt_archivelog:
            ARCHIVELOG                                              { $$ = true; }
            | NOARCHIVELOG                                          { $$ = false; }
        ;

createdb_archivelog_opt:
            opt_archivelog
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_ARCHIVELOG_OPT;
                    opt->archivelog_enable = $1;
                    $$ = opt;
                }
        ;

opt_reuse:
            REUSE                                                   { $$ = true; }
            | /* EMPTY */                                           { $$ = false; }
        ;

next_size:
            NEXT num_size                                           { $$ = $2; }
            | /* EMPTY */                                           { $$ = 0; }
        ;

max_size:
            MAXSIZE num_size                                        { $$ = $2; }
            | MAXSIZE UNLIMITED                                     { $$ = 0; }
            | /* EMPTY */                                           { $$ = 0; }
        ;

datafile:
            SCONST SIZE num_size opt_reuse
                {
                    knl_device_def_t *dev_def = NULL;
                    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_device_def_t), (void **)&dev_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    const text_t name = { $1, strlen($1) };
                    if (sql_copy_file_name(stmt->context, (text_t *)&name, &dev_def->name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    dev_def->size = $3;
                    if (dev_def->size < OG_MIN_USER_DATAFILE_SIZE || dev_def->size > max_filesize) {
                        parser_yyerror("invalid datafile size.");
                    }
                    $$ = dev_def;
                }
            | SCONST SIZE num_size opt_reuse AUTOEXTEND OFF
                {
                    knl_device_def_t *dev_def = NULL;
                    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_device_def_t), (void **)&dev_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    const text_t name = { $1, strlen($1) };
                    if (sql_copy_file_name(stmt->context, (text_t *)&name, &dev_def->name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    dev_def->size = $3;
                    if (dev_def->size < OG_MIN_USER_DATAFILE_SIZE || dev_def->size > max_filesize) {
                        parser_yyerror("invalid datafile size.");
                    }
                    dev_def->autoextend.enabled = OG_FALSE;
                    $$ = dev_def;
                }
            | SCONST SIZE num_size opt_reuse AUTOEXTEND ON next_size max_size
                {
                    knl_device_def_t *dev_def = NULL;
                    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_device_def_t), (void **)&dev_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    const text_t name = { $1, strlen($1) };
                    if (sql_copy_file_name(stmt->context, (text_t *)&name, &dev_def->name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    dev_def->size = $3;
                    if (dev_def->size < OG_MIN_USER_DATAFILE_SIZE || dev_def->size > max_filesize) {
                        parser_yyerror("invalid datafile size.");
                    }
                    dev_def->autoextend.enabled = OG_TRUE;
                    dev_def->autoextend.nextsize = $7;
                    dev_def->autoextend.maxsize = $8;
                    if (dev_def->autoextend.nextsize < OG_MIN_AUTOEXTEND_SIZE) {
                        parser_yyerror("invalid datafile autoextend next size.");
                    }
                    if (dev_def->autoextend.maxsize < OG_MIN_AUTOEXTEND_SIZE) {
                        parser_yyerror("invalid datafile autoextend max size.");
                    }
                    $$ = dev_def;
                }
        ;

datafiles:
            datafile
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create datafile list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert datafile failed.");
                    }
                    $$ = list;
                }
            | datafiles ',' datafile
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert datafile failed.");
                    }
                    $$ = list;
                }
        ;

opt_all_in_memory:
            ALL IN_P MEMORY                                   { $$ = true; }
            | /* EMPTY */                                   { $$ = false; }
        ;

instance_node_opt:
            UNDO TABLESPACE DATAFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_INSTANCE_NODE_UNDO_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
            | LOGFILE '(' logfiles ')'
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_INSTANCE_NODE_LOGFILE_OPT;
                    opt->list = $3;
                    $$ = opt;
                }
            | TEMPORARY TABLESPACE TEMPFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_INSTANCE_NODE_TEMPORARY_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
            | NOLOGGING UNDO TABLESPACE TEMPFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_INSTANCE_NODE_NOLOGGING_OPT;
                    opt->space.datafiles = $5;
                    opt->space.in_memory = $6;
                    $$ = opt;
                }
        ;

instance_node_opts:
            instance_node_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
            | instance_node_opts instance_node_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
        ;

instance_node:
            NODE ICONST instance_node_opts    %prec UMINUS
                {
                    createdb_instance_node *node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_instance_node), (void **)&node) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed.");
                    }
                    node->id = $2;
                    node->loc = @2.loc;
                    node->opts = $3;
                    $$ = node;
                }
        ;

instance_nodes:
            instance_node
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert instance node failed.");
                    }
                    $$ = list;
                }
            | instance_nodes instance_node
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert instance node failed.");
                    }
                    $$ = list;
                }
        ;

createdb_instance_opt:
            INSTANCE instance_nodes
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_INSTANCE_OPT;
                    opt->list = $2;
                    $$ = opt;
                }
        ;

createdb_nologging_opt:
            NOLOGGING UNDO TABLESPACE TEMPFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_NOLOGGING_UNDO_OPT;
                    opt->space.datafiles = $5;
                    opt->space.in_memory = $6;
                    $$ = opt;
                }
            | NOLOGGING TABLESPACE TEMPFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_NOLOGGING_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
        ;

createdb_system_opt:
            SYSTEM_P TABLESPACE DATAFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_SYSTEM_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
        ;

createdb_sysaux_opt:
            SYSAUX TABLESPACE DATAFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_SYSAUX_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
        ;

createdb_default_opt:
            DEFAULT TABLESPACE DATAFILE datafiles opt_all_in_memory
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_DEFAULT_OPT;
                    opt->space.datafiles = $4;
                    opt->space.in_memory = $5;
                    $$ = opt;
                }
        ;

createdb_maxinstance_opt:
            MAXINSTANCES ICONST
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_MAXINSTANCE_OPT;
                    opt->max_instance = $2;
                    $$ = opt;
                }
        ;

createdb_compatibility_opt:
            WITH DBCOMPATIBILITY_P opt_equal SCONST
                {
                    char* compatibility = $4;
                    if (compatibility == NULL || strlen(compatibility) != 1) {
                        parser_yyerror("invalid compatibility value.");
                    }
                    cm_str_upper(compatibility);
                    if (compatibility[0] != 'A' && compatibility[0] != 'B' && compatibility[0] != 'C') {
                        parser_yyerror("invalid compatibility value.");
                    }
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_DBCOMPATIBILITY_OPT;
                    opt->dbcompatibility = compatibility[0];
                    $$ = opt;
                }
        ;

createdb_opt:
            createdb_user_opt                                           { $$ = $1; }
            | createdb_controlfile_opt                                  { $$ = $1; }
            | createdb_charset_opt                                      { $$ = $1; }
            | createdb_archivelog_opt                                   { $$ = $1; }
            | createdb_default_opt                                      { $$ = $1; }
            | createdb_nologging_opt                                    { $$ = $1; }
            | createdb_sysaux_opt                                       { $$ = $1; }
            | createdb_system_opt                                       { $$ = $1; }
            | createdb_instance_opt                                     { $$ = $1; }
            | createdb_maxinstance_opt                                  { $$ = $1; }
            | createdb_compatibility_opt                                { $$ = $1; }
        ;

createdb_opts:
            createdb_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
            | createdb_opts createdb_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
        ;

opt_createdb_opts:
            createdb_opts                                    { $$ = $1; }
            | /* EMPTY */                                    { $$ = NULL; }
        ;

plain_database_name:
            IDENT                                            { $$ = $1; }
        ;

CreatedbStmt:
            CREATE DATABASE CLUSTERED database_name opt_createdb_opts
                {
                    knl_database_def_t *db_def = NULL;
                    if (og_parse_create_database(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &db_def, $4, $5, OG_TRUE) != OG_SUCCESS) {
                        parser_abort_or_yyerror("parse create database failed");
                    }
                    $$ = db_def;
                }
            | CREATE DATABASE plain_database_name opt_createdb_opts
                {
                    knl_database_def_t *db_def = NULL;
                    if (og_parse_create_database(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &db_def, $3, $4, OG_FALSE) != OG_SUCCESS) {
                        parser_abort_or_yyerror("parse create database failed");
                    }
                    $$ = db_def;
                }
        ;

CreateUserStmt:
            CREATE USER user_name IDENTIFIED BY user_password opt_encrypted opt_user_options
                {
                    knl_user_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_user(stmt, &def, $3, $6, @6.loc, $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse create user failed");
                    }
                    $$ = def;
                }
        ;

AlterUserStmt:
            ALTER USER user_name alter_user_options
                {
                    knl_user_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_user(stmt, &def, $3, $4) != OG_SUCCESS) {
                        parser_yyerror("parse alter user failed");
                    }
                    $$ = def;
                }
        ;

CreateRoleStmt:
            CREATE ROLE role_name IDENTIFIED BY user_password opt_encrypted
                {
                    knl_role_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_role(stmt, &def, $3, $6, @6.loc, $7) != OG_SUCCESS) {
                        parser_yyerror("parse create role failed");
                    }
                    $$ = def;
                }
            | CREATE ROLE role_name opt_role_not_identified
                {
                    knl_role_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_role(stmt, &def, $3, NULL, @4.loc, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse create role failed");
                    }
                    $$ = def;
                }
        ;

CreateTenantStmt:
            CREATE TENANT tenant_name TABLESPACES '(' tablespace_name_list ')' opt_default_tablespace
                {
                    knl_tenant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_create_tenant(stmt, &def, $3, $6, $8) != OG_SUCCESS) {
                        parser_yyerror("parse create tenant failed");
                    }
                    $$ = def;
                }
        ;

AlterTenantStmt:
            ALTER TENANT tenant_name ADD_P TABLESPACES '(' tablespace_name_list ')'
                {
                    knl_tenant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_tenant(stmt, &def, $3, ALTER_TENANT_TYPE_ADD_SPACE, $7, NULL) != OG_SUCCESS) {
                        parser_yyerror("parse alter tenant failed");
                    }
                    $$ = def;
                }
            | ALTER TENANT tenant_name DEFAULT TABLESPACE tablespace_name
                {
                    knl_tenant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_tenant(stmt, &def, $3, ALTER_TENANT_TYPE_MODEIFY_DEFAULT, NULL, $6) !=
                        OG_SUCCESS) {
                        parser_yyerror("parse alter tenant failed");
                    }
                    $$ = def;
                }
        ;

alter_index_action:
 	        UNUSABLE
 	            {
 	                alter_index_action_t *alter_idx_act = NULL;
 	                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
 	                if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
 	                    parser_yyerror("alloc mem failed ");
 	                }
 	                alter_idx_act->type = ALINDEX_TYPE_UNUSABLE;
 	                $$ = alter_idx_act;
 	            }
 	        | COALESCE
 	            {
 	                alter_index_action_t *alter_idx_act = NULL;
 	                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
 	                if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
 	                    parser_yyerror("alloc mem failed ");
 	                }
 	                alter_idx_act->type = ALINDEX_TYPE_COALESCE;
 	                $$ = alter_idx_act;
 	            }
 	        | INITRANS ICONST
 	            {
 	                alter_index_action_t *alter_idx_act = NULL;
 	                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
 	                if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
 	                    parser_yyerror("alloc mem failed ");
 	                }
 	                alter_idx_act->type = ALINDEX_TYPE_INITRANS;
 	                alter_idx_act->idx_def.initrans = $2;
 	                $$ = alter_idx_act;
 	            }
 	        | RENAME TO any_name
 	            {
 	                alter_index_action_t *alter_idx_act = NULL;
 	                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
 	                if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
 	                    parser_yyerror("alloc mem failed ");
 	                }
 	                alter_idx_act->type = ALINDEX_TYPE_RENAME;
 	                alter_idx_act->user = $3->owner;
 	                alter_idx_act->idx_def.new_name = $3->name;
 	                $$ = alter_idx_act;
 	            }
            | REBUILD
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_REBUILD;
                    $$ = alter_idx_act;
                }
            | REBUILD PARTITION ColId
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_REBUILD_PART;
                    alter_idx_act->rebuild.part_name[0].str = $3;
                    alter_idx_act->rebuild.part_name[0].len = strlen($3);
                    $$ = alter_idx_act;
                }
            
            | REBUILD SUBPARTITION ColId
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_REBUILD_SUBPART;
                    alter_idx_act->rebuild.part_name[0].str = $3;
                    alter_idx_act->rebuild.part_name[0].len = strlen($3);
                    $$ = alter_idx_act;
                }
            
            | MODIFY_P PARTITION ColId UNUSABLE
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_MODIFY_PART;
                    alter_idx_act->mod_idxpart.part_name.str = $3;
                    alter_idx_act->mod_idxpart.part_name.len = strlen($3);
                    alter_idx_act->mod_idxpart.initrans = 0;
                    $$ = alter_idx_act;
                }
            | MODIFY_P PARTITION ColId COALESCE
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_MODIFY_PART;
                    alter_idx_act->mod_idxpart.part_name.str = $3;
                    alter_idx_act->mod_idxpart.part_name.len = strlen($3);
                    alter_idx_act->mod_idxpart.initrans = (uint32)(-1);
                    $$ = alter_idx_act;
                }
            | MODIFY_P PARTITION ColId INITRANS ICONST
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_MODIFY_PART;
                    alter_idx_act->mod_idxpart.part_name.str = $3;
                    alter_idx_act->mod_idxpart.part_name.len = strlen($3);
                    alter_idx_act->mod_idxpart.initrans = $5;
                    $$ = alter_idx_act;
                }
            | MODIFY_P SUBPARTITION ColId UNUSABLE
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_MODIFY_SUBPART;
                    alter_idx_act->mod_idxpart.part_name.str = $3;
                    alter_idx_act->mod_idxpart.part_name.len = strlen($3);
                    alter_idx_act->mod_idxpart.initrans = 0;
                    $$ = alter_idx_act;
                }
            | MODIFY_P SUBPARTITION ColId COALESCE
                {
                    alter_index_action_t *alter_idx_act = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(alter_index_action_t), (void **)&alter_idx_act) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed ");
                    }
                    alter_idx_act->type = ALINDEX_TYPE_MODIFY_SUBPART;
                    alter_idx_act->mod_idxpart.part_name.str = $3;
                    alter_idx_act->mod_idxpart.part_name.len = strlen($3);
                    alter_idx_act->mod_idxpart.initrans = (uint32)(-1);
                    $$ = alter_idx_act;
                }

 	             
 	    ;
 	 
AlterIndexStmt:
 	        ALTER INDEX_P any_name alter_index_action
 	            {
 	                knl_alindex_def_t *def = NULL;
 	                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
 	                text_t table;
 	                stmt->context->type = OGSQL_TYPE_ALTER_INDEX;
 	 
 	                if (sql_alloc_mem(stmt->context, sizeof(knl_alindex_def_t), (void **)&def) != OG_SUCCESS) {
 	                    parser_yyerror("alloc mem failed ");
 	                }
 	                def->user = $3->owner;
 	                def->name = $3->name;
 	                if (def->user.str == NULL) {
 	                    cm_str2text(stmt->session->curr_schema, &def->user);
 	                }
 	                if (knl_get_table_of_index(&stmt->session->knl_session, &def->user, &def->name, &table) != OG_SUCCESS) {
 	                    sql_check_user_priv(stmt, &def->user);
 	                    parser_yyerror("get_table_of_index failed ");
 	                }
 	                if (sql_regist_ddl_table(stmt, &def->user, &table)) {
 	                    parser_yyerror("regist_ddl_table failed ");
 	                }
 	 
 	                if (process_alter_index_action(stmt, $4, def) != OG_SUCCESS) {
 	                    parser_yyerror("process_alter_index_action failed ");
 	                }
 	                $$ = def;
 	            }
                       
 	    ;

/* Consume the remaining DDL tokens before the statement semantic action runs. */
ddl_passthrough_tail:
            {
                int tok = YYLEX;
                while (tok != YYEOF) {
                    if (tok == LEX_ERROR_TOKEN) {
                        parser_yyerror("lex error");
                    }
                    tok = YYLEX;
                }
                $$ = NULL;
            }
        ;

AlterTableStmt:
            ALTER TABLE_P ddl_passthrough_tail
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    status_t status = sql_parse_alter_table(stmt);
                    if (status == OG_SUCCESS) {
                        status = sql_verify_alter_table(stmt);
                    }
                    if (status != OG_SUCCESS) {
                        /* The native ALTER TABLE parser has already raised the precise error. */
                        YYABORT;
                    }
                    $$ = stmt->context->entry;
                }
        ;

AlterDatabaseStmt:
            ALTER DATABASE ddl_passthrough_tail
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_parse_alter_database_lead(stmt) != OG_SUCCESS) {
                        /* The native ALTER DATABASE parser has already raised the precise error. */
                        YYABORT;
                    }
                    $$ = stmt->context->entry;
                }
        ;

CreateTablespaceStmt:
            CREATE TEMPORARY TABLESPACE ddl_passthrough_tail
                {
                    OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create temporary lead ", "temporary tablespace");
                    YYABORT;
                    $$ = NULL;
                }
            | CREATE opt_undo TABLESPACE tablespace_name extents_clause DATAFILE datafiles opt_createts_opts
                {
                    knl_space_def_t *def = NULL;
                    uint32 size = $5;
                    if (size < OG_MIN_EXTENT_SIZE || size > OG_MAX_EXTENT_SIZE) {
                        parser_yyerror("invalid extent size.");
                    }
                    
                    if (og_parse_create_space(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &def, $2, $4, size,
                        $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse create tablespace failed.");
                    }
                    $$ = def;
                }
            | CREATE opt_undo TABLESPACE tablespace_name DATAFILE datafiles opt_createts_opts
                {
                    knl_space_def_t *def = NULL;

                    if (og_parse_create_space(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &def, $2, $4, 0,
                        $6, $7) != OG_SUCCESS) {
                        parser_yyerror("parse create tablespace failed.");
                    }
                    $$ = def;
                }
        ;

extents_clause:
            EXTENTS num_size                                        { $$ = $2; }
        ;

opt_undo:
            UNDO                                                    { $$ = true; }
            | /* EMPTY */                                           { $$ = false; }
        ;

opt_alter_ts_db:
            DB_P                                                      { $$ = true; }
            | /* EMPTY */                                           { $$ = false; }
        ;

AlterTablespaceStmt:
            ALTER TABLESPACE opt_alter_ts_db ColId alterts_opt opt_segments
                {
                    knl_altspace_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_alter_tablespace(stmt, &def, (bool32)$3, $4, $5, $6) != OG_SUCCESS) {
                        parser_yyerror("parse alter tablespace failed");
                    }
                    $$ = def;
                }
        ;

alterts_opt:
            ADD_P DATAFILE datafiles
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_ADD_DATAFILE_OPT;
                    opt->datafiles = $3;
                    $$ = opt;
                }
            | DROP DATAFILE files
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_DROP_DATAFILE_OPT;
                    opt->datafiles = $3;
                    $$ = opt;
                }
            | AUTOEXTEND OFF
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_AUTOEXTEND_OFF_OPT;
                    $$ = opt;
                }
            | AUTOEXTEND ON next_size max_size
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_AUTOEXTEND_ON_OPT;
                    opt->autoextend.next_size = $3;
                    opt->autoextend.max_size = $4;
                    if (opt->autoextend.next_size < OG_MIN_AUTOEXTEND_SIZE) {
                        parser_yyerror("invalid datafile autoextend next size.");
                    }
                    if (opt->autoextend.max_size < OG_MIN_AUTOEXTEND_SIZE) {
                        parser_yyerror("invalid datafile autoextend max size.");
                    }
                    $$ = opt;
                }
            | AUTOOFFLINE on_or_off
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_AUTOOFFLINE_OPT;
                    opt->on_off = $2;
                    $$ = opt;
                }
            | RENAME TO ColId
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_RENAME_OPT;
                    opt->new_name = $3;
                    $$ = opt;
                }
            | RENAME DATAFILE files TO files
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_RENAME_DATAFILE_OPT;
                    opt->rename_datafiles.old_files = $3;
                    opt->rename_datafiles.new_files = $5;
                    $$ = opt;
                }
            | OFFLINE DATAFILE files
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_OFFLINE_DATAFILE_OPT;
                    opt->datafiles = $3;
                    $$ = opt;
                }
            | AUTOPURGE on_or_off
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_AUTOPURGE_OPT;
                    opt->on_off = $2;
                    $$ = opt;
                }
            | SHRINK SPACE_P KEEP num_size
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    int64 max_size = (int64)OG_MAX_SPACE_FILES * g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_SHRINK_SPACE_OPT;
                    opt->size = $4;
                    if (opt->size < OG_MIN_USER_DATAFILE_SIZE || opt->size > max_size) {
                        parser_yyerror("invalid size for shrink space");
                    }
                    $$ = opt;
                }
            | PUNCH opt_punch_size
                {
                    alterts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(alterts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("Memory allocation failed for alterts_opt");
                    }
                    opt->type = ALTERTS_PUNCH_OPT;
                    opt->size = $2;
                    if (opt->size != OG_INVALID_INT64 && (opt->size < OG_MIN_USER_DATAFILE_SIZE ||
                        opt->size > OG_MAX_PUNCH_SIZE)) {
                        parser_yyerror("invalid size for punch");
                    }
                    $$ = opt;
                }
        ;

opt_punch_size:
            SIZE num_size                                           { $$ = $2; }
            | /* EMPTY */                                           { $$ = OG_INVALID_INT64; }
        ;

opt_segments:
            SEGMENTS BigintOnly                                     { $$ = $2; }
            | /* EMPTY */                                           { $$ = OG_INVALID_INT64; }
        ;

on_or_off:
            ON                                                      { $$ = true; }
            | OFF                                                   { $$ = false; }
        ;

CreateIndexStmt:
            CREATE opt_unique INDEX_P opt_if_not_exists any_name ON any_name '(' index_column_list ')' opt_createidx_opts
                {
                    knl_index_def_t *def = NULL;
                    if (og_parse_create_index(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &def, $5,
                        $7, $9, $11) != OG_SUCCESS) {
                        parser_yyerror("parse create index failed");
                    }
                    def->unique = $2;
                    if ($4) {
                        def->options |= CREATE_IF_NOT_EXISTS;
                    }
                    $$ = def;
                }
        ;

CreateIndexClusterStmt:
            CREATE INDEXCLUSTER '(' index_cluster_list ')'
                {
                    knl_indexes_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *index_list = $4;
                    knl_index_def_t *index_def = NULL;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_indexes_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->index_count = 0;
                    stmt->context->type = OGSQL_TYPE_CREATE_INDEXES;

                    for (uint32 i = 0; i < index_list->count; i++) {
                        if (def->index_count >= OG_MAX_INDEX_COUNT_PERSQL) {
                            parser_yyerror("create more than eight indexes in one SQL statement");
                        }
                        index_def = (knl_index_def_t*)cm_galist_get(index_list, i);
                        def->indexes_def[def->index_count] = *index_def;
                        def->index_count++;
                    }
                    $$ = def;
                }
        ;

index_cluster_list:
            index_cluster_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }

                    $$ = list;
                }
            | index_cluster_list ',' index_cluster_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }

                    $$ = list;
                }
        ;

index_cluster_item:
            opt_unique INDEX_P any_name ON any_name '(' index_column_list ')' opt_createidx_opts
                {
                    knl_index_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_index(stmt, &def, $3, $5, $7, $9) != OG_SUCCESS) {
                        parser_yyerror("parse create index failed");
                    }
                    
                    def->unique = $1;
                    $$ = def;
                }
        ;

CreateSequenceStmt:
            CREATE SEQUENCE any_name opt_createseq_opts
                {
                    knl_sequence_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_sequence(stmt, &def, $3, $4) != OG_SUCCESS) {
                        parser_yyerror("parse create sequence failed");
                    }
                    $$ = def;
                }
        ;

AlterSequenceStmt:
            ALTER SEQUENCE any_name opt_alterseq_opts
                {
                    knl_sequence_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_sequence(stmt, &def, $3, $4) != OG_SUCCESS) {
                        parser_yyerror("parse alter sequence failed");
                    }
                    $$ = def;
                }
        ;

opt_createseq_opts:
            createseq_opts                                  { $$ = $1; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

opt_alterseq_opts:
            alterseq_opts                                   { $$ = $1; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

createseq_opts:
            createseq_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create seq opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert seq opt failed.");
                    }
                    $$ = list;
                }
            | createseq_opts createseq_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert seq opt failed.");
                    }
                    $$ = list;
                }
        ;

alterseq_opts:
            alterseq_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create alter seq opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert alter seq opt failed.");
                    }
                    $$ = list;
                }
            | alterseq_opts alterseq_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert alter seq opt failed.");
                    }
                    $$ = list;
                }
        ;

alterseq_opt:
            createseq_opt                                    { $$ = $1; }
            | RESTART
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_RESTART_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
        ;

SignedIconst: ICONST                                { $$ = $1; }
            | '+' ICONST                            { $$ = + $2; }
            | '-' ICONST                            { $$ = - $2; }
        ;

BigintOnly:
            FCONST
                {
                    int64 res = 0;
                    if (strGetInt64($1, &res) != OG_SUCCESS) {
                        parser_yyerror("get int64 failed");
                    }
                    $$ = res;
                }
            | '+' FCONST
                {
                    int64 res = 0;
                    if (strGetInt64($2, &res) != OG_SUCCESS) {
                        parser_yyerror("get int64 failed");
                    }
                    $$ = + res;
                }
            | '-' FCONST
                {
                    int64 res = 0;
                    if (strGetInt64($2, &res) != OG_SUCCESS) {
                        parser_yyerror("get int64 failed");
                    }
                    $$ = - res;
                }
            | SignedIconst
                {
                    $$ = $1;
                }
        ;

createseq_opt:
            INCREMENT BY BigintOnly
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_INCREMENT_OPT;
                    opt->value = $3;
                    $$ = opt;
                }
            | MINVALUE BigintOnly
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_MINVALUE_OPT;
                    opt->value = $2;
                    $$ = opt;
                }
            | NOMINVALUE
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_NOMINVALUE_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | MAXVALUE BigintOnly
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_MAXVALUE_OPT;
                    opt->value = $2;
                    $$ = opt;
                }
            | NOMAXVALUE
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_NOMAXVALUE_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | START_WITH BigintOnly
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_START_OPT;
                    opt->value = $2;
                    $$ = opt;
                }
            | CACHE BigintOnly
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_CACHE_OPT;
                    opt->value = $2;
                    $$ = opt;
                }
            | NOCACHE
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_NOCACHE_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | CYCLE
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_CYCLE_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | NOCYCLE
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_NOCYCLE_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | ORDER
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_ORDER_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
            | NOORDER
                {
                    createseq_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createseq_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATESEQ_NOORDER_OPT;
                    opt->value = 0;
                    $$ = opt;
                }
        ;

view_column_list:
            ColId
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create view column list failed.");
                    }
                    cm_galist_insert(list, $1);
                    $$ = list;
                }
            | view_column_list ',' ColId
                {
                    galist_t *list = $1;
                    cm_galist_insert(list, $3);
                    $$ = list;
                }
        ;

CreateViewStmt:
            CREATE opt_or_replace opt_force VIEW any_name opt_view_column_list opt_with_read_only AS SelectStmt
                {
                    knl_view_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t src_sql;
                    src_sql.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf;
                    src_sql.len = og_yyget_extra(yyscanner)->core_yy_extra.scanbuflen;

                    if (og_parse_create_view(stmt, &def, $5, $6, $2, $3, $7, $9, &src_sql, @9.offset) != OG_SUCCESS) {
                        parser_yyerror("parse create view failed");
                    }
                    $$ = def;
                }
        ;

opt_with_read_only:
            WITH READ ONLY                   { $$ = OG_TRUE; }
            | /*EMPTY*/                      { $$ = OG_FALSE; }
        ;

opt_view_column_list:
            '(' view_column_list ')'                  { $$ = $2; }
            | /*EMPTY*/                                { $$ = NULL; }
        ;

CreateSynonymStmt:
            CREATE opt_or_replace opt_public SYNONYM any_name FOR any_name
                {
                    knl_synonym_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    uint32 flags = SYNONYM_IS_NULL;
                    
                    if ($2) {
                        flags |= SYNONYM_IS_REPLACE;
                    }
                    if ($3) {
                        flags |= SYNONYM_IS_PUBLIC;
                    }
                    
                    if (og_parse_create_synonym(stmt, &def, $5, $7, flags) != OG_SUCCESS) {
                        parser_yyerror("parse create synonym failed");
                    }
                    $$ = def;
                }
        ;

CreateProfileStmt:
            CREATE opt_or_replace PROFILE profile_name LIMIT profile_limit_list
                {
                    knl_profile_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_profile(stmt, &def, $4, $2, $6) != OG_SUCCESS) {
                        parser_yyerror("parse create profile failed");
                    }
                    $$ = def;
                }
        ;

AlterProfileStmt:
            ALTER PROFILE profile_name LIMIT profile_limit_list
                {
                    knl_profile_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_profile(stmt, &def, $3, $5) != OG_SUCCESS) {
                        parser_yyerror("parse alter profile failed");
                    }
                    $$ = def;
                }
        ;

profile_limit_list:
            profile_limit_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create profile limit list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert profile limit item failed.");
                    }
                    $$ = list;
                }
            | profile_limit_list profile_limit_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert profile limit item failed.");
                    }
                    $$ = list;
                }
        ;

profile_limit_item:
            profile_parameter profile_limit_value
                {
                    profile_limit_item_t *item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(profile_limit_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    item->param_type = $1;
                    item->value = $2;
                    $$ = item;
                }
        ;

profile_limit_value:
            DEFAULT
                {
                    profile_limit_value_t *val = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(profile_limit_value_t), (void **)&val) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    val->type = VALUE_DEFAULT;
                    $$ = val;
                }
            | a_expr
                {
                    profile_limit_value_t *val = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(profile_limit_value_t), (void **)&val) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_tree_t *expr = $1;
                    if (expr->root->type == EXPR_NODE_COLUMN &&
                        strcmp(expr->root->word.column.name.value.str, "UNLIMITED") == 0) {
                        val->type = VALUE_UNLIMITED;
                    } else {
                        val->type = VALUE_NORMAL;
                        val->expr = expr;
                    }
                    $$ = val;
                }
        ;

profile_parameter:
            FAILED_LOGIN_ATTEMPTS_P                                     { $$ = FAILED_LOGIN_ATTEMPTS; }
            | PASSWORD_LIFE_TIME_P                                      { $$ = PASSWORD_LIFE_TIME; }
            | PASSWORD_REUSE_TIME_P                                     { $$ = PASSWORD_REUSE_TIME; }
            | PASSWORD_REUSE_MAX_P                                      { $$ = PASSWORD_REUSE_MAX; }
            | PASSWORD_LOCK_TIME_P                                      { $$ = PASSWORD_LOCK_TIME; }
            | PASSWORD_GRACE_TIME_P                                     { $$ = PASSWORD_GRACE_TIME; }
            | SESSIONS_PER_USER_P                                       { $$ = SESSIONS_PER_USER; }
            | PASSWORD_MIN_LEN_P                                        { $$ = PASSWORD_MIN_LEN; }
        ;

/* -------------------------
 * GRANT
 * ------------------------- */
GrantStmt:
            GRANT sys_priv_list TO grantee_list opt_with_admin
                {
                    knl_grant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_grant(stmt, &def, PRIV_TYPE_SYS_PRIV, $2, OBJ_TYPE_INVALID, NULL, $4, $5) != OG_SUCCESS) {
                        parser_yyerror("parse grant failed");
                    }
                    $$ = def;
                }
            | GRANT obj_priv_list ON grant_objtype any_name TO grantee_list opt_with_grant
                {
                    knl_grant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_grant(stmt, &def, PRIV_TYPE_OBJ_PRIV, $2, $4, $5, $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse grant failed");
                    }
                    $$ = def;
                }
            | GRANT obj_priv_list ON any_name TO grantee_list opt_with_grant
                {
                    knl_grant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_grant(stmt, &def, PRIV_TYPE_OBJ_PRIV, $2, OBJ_TYPE_INVALID, $4, $6, $7) != OG_SUCCESS) {
                        parser_yyerror("parse grant failed");
                    }
                    $$ = def;
                }
            | GRANT directory_priv_spec any_name TO grantee_list opt_with_grant
                {
                    knl_grant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = NULL;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @2.offset;
                    priv_name.len = @3.offset - @2.offset;
                    cm_trim_text(&priv_name);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $2;
                    priv_def->priv_type = PRIV_TYPE_OBJ_PRIV;
                    priv_def->start_loc = @2.loc;

                    if (og_parse_grant(stmt, &def, PRIV_TYPE_OBJ_PRIV, list, OBJ_TYPE_DIRECTORY, $3, $5, $6) != OG_SUCCESS) {
                        parser_yyerror("parse grant failed");
                    }
                    $$ = def;
                }
            | GRANT user_priv_spec ON USER any_name TO grantee_list
                {
                    knl_grant_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = NULL;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @2.offset;
                    priv_name.len = @3.offset - @2.offset;
                    cm_trim_text(&priv_name);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $2;
                    priv_def->priv_type = PRIV_TYPE_USER_PRIV;
                    priv_def->start_loc = @2.loc;

                    if (og_parse_grant(stmt, &def, PRIV_TYPE_USER_PRIV, list, OBJ_TYPE_USER, $5, $7, false) != OG_SUCCESS) {
                        parser_yyerror("parse grant failed");
                    }
                    $$ = def;
                }
        ;

sys_priv_list:
            sys_priv_spec
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    knl_priv_def_t *priv_def = NULL;
                    uint32 rid;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @1.offset;
                    priv_name.len = yylloc.offset - @1.offset + ct_yyget_leng(yyscanner);
                    cm_trim_text(&priv_name);
                    priv_type_def priv_type;
                    uint32 priv_id;

                    if ($1 == ALL_PRIVILEGES) {
                        priv_type = PRIV_TYPE_ALL_PRIV;
                        priv_id = (uint32)$1;
                    } else if ($1 == OG_SYS_PRIVS_COUNT) {
                        priv_type = PRIV_TYPE_ROLE;
                        if (knl_get_role_id(&stmt->session->knl_session, &priv_name, &rid)) {
                            priv_id = rid;
                        } else {
                            parser_yyerror("invalid privilege or role name");
                        }
                    } else {
                        priv_type = PRIV_TYPE_SYS_PRIV;
                        priv_id = (uint32)$1;
                    }

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = priv_id;
                    priv_def->priv_type = priv_type;
                    priv_def->start_loc = @1.loc;
                    $$ = list;
                }
            | sys_priv_list ',' sys_priv_spec
                {
                    galist_t *list = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    knl_priv_def_t *priv_def = NULL;
                    uint32 rid;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @3.offset;
                    priv_name.len = yylloc.offset - @3.offset + ct_yyget_leng(yyscanner);
                    cm_trim_text(&priv_name);
                    priv_type_def priv_type;
                    uint32 priv_id;

                    if ($3 == ALL_PRIVILEGES) {
                        priv_type = PRIV_TYPE_ALL_PRIV;
                        priv_id = (uint32)$3;
                    } else if ($3 == OG_SYS_PRIVS_COUNT) {
                        priv_type = PRIV_TYPE_ROLE;
                        if (knl_get_role_id(&stmt->session->knl_session, &priv_name, &rid)) {
                            priv_id = rid;
                        }
                        parser_yyerror("invalid privilege or role name");
                    } else {
                        priv_type = PRIV_TYPE_SYS_PRIV;
                        priv_id = (uint32)$3;
                    }

                    if (sql_check_privs_duplicated(list, &priv_name, priv_type) != OG_SUCCESS) {
                        parser_yyerror("duplicate privilege listed");
                    }

                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = priv_id;
                    priv_def->priv_type = priv_type;
                    priv_def->start_loc = @3.loc;
                    $$ = list;
                }
        ;

obj_priv_list:
            obj_priv_spec
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @1.offset;
                    priv_name.len = yylloc.offset - @1.offset + ct_yyget_leng(yyscanner);
                    cm_trim_text(&priv_name);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $1;
                    priv_def->priv_type = PRIV_TYPE_OBJ_PRIV;
                    priv_def->start_loc = @1.loc;
                    $$ = list;
                }
            | obj_priv_list ',' obj_priv_spec
                {
                    galist_t *list = $1;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @3.offset;
                    priv_name.len = yylloc.offset - @3.offset + ct_yyget_leng(yyscanner);
                    cm_trim_text(&priv_name);

                    if (sql_check_privs_duplicated(list, &priv_name, $3) != OG_SUCCESS) {
                        parser_yyerror("duplicate privilege listed");
                    }

                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $3;
                    priv_def->priv_type = PRIV_TYPE_OBJ_PRIV;
                    priv_def->start_loc = @3.loc;
                    $$ = list;
                }
        ;

sys_priv_spec:
            ALL                                 { $$ = ALL_PRIVILEGES; }
            | ALL PRIVILEGES                    { $$ = ALL_PRIVILEGES; }
            | ALTER ANY INDEX_P                 { $$ = ALTER_ANY_INDEX; }
            | ALTER ANY MATERIALIZED VIEW       { $$ = ALTER_ANY_MATERIALIZED_VIEW; }
            | ALTER ANY PROCEDURE               { $$ = ALTER_ANY_PROCEDURE; }
            | ALTER ANY ROLE                    { $$ = ALTER_ANY_ROLE; }
            | ALTER ANY SEQUENCE                { $$ = ALTER_ANY_SEQUENCE; }
            | ALTER ANY TABLE_P                 { $$ = ALTER_ANY_TABLE; }
            | ALTER ANY TRIGGER                 { $$ = ALTER_ANY_TRIGGER; }
            | ALTER DATABASE                    { $$ = ALTER_DATABASE; }
            | ALTER DATABASE LINK               { $$ = ALTER_DATABASE_LINK; }
            | ALTER NODE                        { $$ = ALTER_NODE; }
            | ALTER PROFILE                     { $$ = ALTER_PROFILE; }
            | ALTER SESSION                     { $$ = ALTER_SESSION; }
            | ALTER SYSTEM_P                    { $$ = ALTER_SYSTEM; }
            | ALTER TABLESPACE                  { $$ = ALTER_TABLESPACE; }
            | ALTER TENANT                      { $$ = ALTER_TENANT; }
            | ALTER USER                        { $$ = ALTER_USER; }
            | ANALYZE ANY                       { $$ = ANALYZE_ANY; }
            | COMMENT ANY TABLE_P               { $$ = COMMENT_ANY_TABLE; }
            | CREATE ANY DIRECTORY              { $$ = CREATE_ANY_DIRECTORY; }
            | CREATE ANY DISTRIBUTE RULE        { $$ = CREATE_ANY_DISTRIBUTE_RULE; }
            | CREATE ANY INDEX_P                { $$ = CREATE_ANY_INDEX; }
            | CREATE ANY LIBRARY                { $$ = CREATE_ANY_LIBRARY; }
            | CREATE ANY MATERIALIZED VIEW      { $$ = CREATE_ANY_MATERIALIZED_VIEW; }
            | CREATE ANY PROCEDURE              { $$ = CREATE_ANY_PROCEDURE; }
            | CREATE ANY SEQUENCE               { $$ = CREATE_ANY_SEQUENCE; }
            | CREATE ANY SQL_P MAP              { $$ = CREATE_ANY_SQL_MAP; }
            | CREATE ANY SYNONYM                { $$ = CREATE_ANY_SYNONYM; }
            | CREATE ANY TABLE_P                { $$ = CREATE_ANY_TABLE; }
            | CREATE ANY TRIGGER                { $$ = CREATE_ANY_TRIGGER; }
            | CREATE ANY TYPE_P                 { $$ = CREATE_ANY_TYPE; }
            | CREATE ANY VIEW                   { $$ = CREATE_ANY_VIEW; }
            | CREATE CTRLFILE                   { $$ = CREATE_CTRLFILE; }
            | CREATE DATABASE                   { $$ = CREATE_DATABASE; }
            | CREATE DATABASE LINK              { $$ = CREATE_DATABASE_LINK; }
            | CREATE DISTRIBUTE RULE            { $$ = CREATE_DISTRIBUTE_RULE; }
            | CREATE LIBRARY                    { $$ = CREATE_LIBRARY; }
            | CREATE MATERIALIZED VIEW          { $$ = CREATE_MATERIALIZED_VIEW; }
            | CREATE NODE                       { $$ = CREATE_NODE; }
            | CREATE PROCEDURE                  { $$ = CREATE_PROCEDURE; }
            | CREATE PROFILE                    { $$ = CREATE_PROFILE; }
            | CREATE PUBLIC SYNONYM             { $$ = CREATE_PUBLIC_SYNONYM; }
            | CREATE ROLE                       { $$ = CREATE_ROLE; }
            | CREATE SEQUENCE                   { $$ = CREATE_SEQUENCE; }
            | CREATE SESSION                    { $$ = CREATE_SESSION; }
            | CREATE SYNONYM                    { $$ = CREATE_SYNONYM; }
            | CREATE TABLE_P                    { $$ = CREATE_TABLE; }
            | CREATE TABLESPACE                 { $$ = CREATE_TABLESPACE; }
            | CREATE TENANT                     { $$ = CREATE_TENANT; }
            | CREATE TRIGGER                    { $$ = CREATE_TRIGGER; }
            | CREATE TYPE_P                     { $$ = CREATE_TYPE; }
            | CREATE USER                       { $$ = CREATE_USER; }
            | CREATE VIEW                       { $$ = CREATE_VIEW; }
            | DELETE_P ANY TABLE_P              { $$ = DELETE_ANY_TABLE; }
            | DROP ANY DIRECTORY                { $$ = DROP_ANY_DIRECTORY; }
            | DROP ANY DISTRIBUTE RULE          { $$ = DROP_ANY_DISTRIBUTE_RULE; }
            | DROP ANY INDEX_P                    { $$ = DROP_ANY_INDEX; }
            | DROP ANY LIBRARY                  { $$ = DROP_ANY_LIBRARY; }
            | DROP ANY MATERIALIZED VIEW        { $$ = DROP_ANY_MATERIALIZED_VIEW; }
            | DROP ANY PROCEDURE                { $$ = DROP_ANY_PROCEDURE; }
            | DROP ANY ROLE                     { $$ = DROP_ANY_ROLE; }
            | DROP ANY SEQUENCE                 { $$ = DROP_ANY_SEQUENCE; }
            | DROP ANY SQL_P MAP                { $$ = DROP_ANY_SQL_MAP; }
            | DROP ANY SYNONYM                  { $$ = DROP_ANY_SYNONYM; }
            | DROP ANY TABLE_P                  { $$ = DROP_ANY_TABLE; }
            | DROP ANY TRIGGER                  { $$ = DROP_ANY_TRIGGER; }
            | DROP ANY TYPE_P                   { $$ = DROP_ANY_TYPE; }
            | DROP ANY VIEW                     { $$ = DROP_ANY_VIEW; }
            | DROP DATABASE LINK                { $$ = DROP_DATABASE_LINK; }
            | DROP NODE                         { $$ = DROP_NODE; }
            | DROP PROFILE                      { $$ = DROP_PROFILE; }
            | DROP PUBLIC SYNONYM               { $$ = DROP_PUBLIC_SYNONYM; }
            | DROP TABLESPACE                   { $$ = DROP_TABLESPACE; }
            | DROP TENANT                       { $$ = DROP_TENANT; }
            | DROP USER                         { $$ = DROP_USER; }
            | EXECUTE ANY LIBRARY               { $$ = EXECUTE_ANY_LIBRARY; }
            | EXECUTE ANY PROCEDURE             { $$ = EXECUTE_ANY_PROCEDURE; }
            | EXECUTE ANY TYPE_P                { $$ = EXECUTE_ANY_TYPE; }
            | EXEMPT ACCESS POLICY              { $$ = EXEMPT_ACCESS_POLICY; }
            | EXEMPT REDACTION POLICY           { $$ = EXEMPT_REDACTION_POLICY; }
            | FLASHBACK ANY TABLE_P             { $$ = FLASHBACK_ANY_TABLE; }
            | FLASHBACK ARCHIVE_P ADMINISTER    { $$ = FLASHBACK_ARCHIVE_ADMINISTER; }
            | FORCE ANY TRANSACTION             { $$ = FORCE_ANY_TRANSACTION; }
            | GLOBAL QUERY REWRITE              { $$ = GLOBAL_QUERY_REWRITE; }
            | GRANT ANY OBJECT_P PRIVILEGE      { $$ = GRANT_ANY_OBJECT_PRIVILEGE; }
            | GRANT ANY PRIVILEGE               { $$ = GRANT_ANY_PRIVILEGE; }
            | GRANT ANY ROLE                    { $$ = GRANT_ANY_ROLE; }
            | INHERIT ANY PRIVILEGES            { $$ = INHERIT_ANY_PRIVILEGES; }
            | INSERT ANY TABLE_P                { $$ = INSERT_ANY_TABLE; }
            | LOCK_P ANY TABLE_P                { $$ = LOCK_ANY_TABLE; }
            | MANAGE TABLESPACE                 { $$ = MANAGE_TABLESPACE; }
            | ON COMMIT REFRESH                 { $$ = ON_COMMIT_REFRESH; }
            | PURGE DBA_RECYCLEBIN              { $$ = PURGE_DBA_RECYCLEBIN; }
            | READ ANY TABLE_P                  { $$ = READ_ANY_TABLE; }
            | SELECT ANY DICTIONARY             { $$ = SELECT_ANY_DICTIONARY; }
            | SELECT ANY SEQUENCE               { $$ = SELECT_ANY_SEQUENCE; }
            | SELECT ANY TABLE_P                { $$ = SELECT_ANY_TABLE; }
            | UNDER ANY VIEW                    { $$ = UNDER_ANY_VIEW; }
            | UNLIMITED TABLESPACE              { $$ = UNLIMITED_TABLESPACE; }
            | UPDATE ANY TABLE_P                { $$ = UPDATE_ANY_TABLE; }
            | USE_P ANY TABLESPACE              { $$ = USE_ANY_TABLESPACE; }
            | SYSBACKUP_P                       { $$ = SYSBACKUP; }
            | SYSDBA_P                          { $$ = SYSDBA; }
            | SYSOPER_P                         { $$ = SYSOPER; }
            | ColId
                {
                    $$ = OG_SYS_PRIVS_COUNT;
                }
        ;

obj_priv_spec:
            ALTER                               { $$ = OG_PRIV_ALTER; }
            | DELETE_P                          { $$ = OG_PRIV_DELETE; }
            | EXECUTE_KEY                       { $$ = OG_PRIV_EXECUTE; }
            | INDEX_P                           { $$ = OG_PRIV_INDEX; }
            | INSERT                            { $$ = OG_PRIV_INSERT; }
            | READ_KEY                          { $$ = OG_PRIV_READ; }
            | REFERENCES                        { $$ = OG_PRIV_REFERENCES; }
            | SELECT                            { $$ = OG_PRIV_SELECT; }
            | UPDATE                            { $$ = OG_PRIV_UPDATE; }
        ;

directory_priv_spec:
            READ_ON_DIRECTORY                   { $$ = OG_PRIV_DIRE_READ; }
            | WRITE ON DIRECTORY                { $$ = OG_PRIV_DIRE_WRITE; }
            | EXECUTE_ON_DIRECTORY              { $$ = OG_PRIV_DIRE_EXECUTE; }
        ;


user_priv_spec:
            INHERIT PRIVILEGES                  { $$ = OG_PRIV_INHERIT_PRIVILEGES; }
        ;

/* -------------------------
 * REVOKE
 * ------------------------- */
RevokeStmt:
            REVOKE sys_priv_list FROM revokee_list
                {
                    knl_revoke_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_revoke(stmt, &def, PRIV_TYPE_SYS_PRIV, $2, OBJ_TYPE_INVALID, NULL, $4, false) != OG_SUCCESS) {
                        parser_yyerror("parse revoke failed");
                    }
                    $$ = def;
                }
            | REVOKE obj_priv_list ON grant_objtype any_name FROM revokee_list opt_revoke_cascade
                {
                    knl_revoke_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_revoke(stmt, &def, PRIV_TYPE_OBJ_PRIV, $2, $4, $5, $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse revoke failed");
                    }
                    $$ = def;
                }
            | REVOKE obj_priv_list ON any_name FROM revokee_list opt_revoke_cascade
                {
                    knl_revoke_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_revoke(stmt, &def, PRIV_TYPE_OBJ_PRIV, $2, OBJ_TYPE_INVALID, $4, $6, $7) != OG_SUCCESS) {
                        parser_yyerror("parse revoke failed");
                    }
                    $$ = def;
                }
            | REVOKE directory_priv_spec any_name FROM revokee_list opt_revoke_cascade
                {
                    knl_revoke_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = NULL;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @2.offset;
                    priv_name.len = @3.offset - @2.offset;
                    cm_trim_text(&priv_name);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $2;
                    priv_def->priv_type = PRIV_TYPE_OBJ_PRIV;
                    priv_def->start_loc = @2.loc;

                    if (og_parse_revoke(stmt, &def, PRIV_TYPE_OBJ_PRIV, list, OBJ_TYPE_DIRECTORY, $3, $5, $6) != OG_SUCCESS) {
                        parser_yyerror("parse revoke failed");
                    }
                    $$ = def;
                }
            | REVOKE user_priv_spec ON USER any_name FROM revokee_list opt_revoke_cascade
                {
                    knl_revoke_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    galist_t *list = NULL;
                    knl_priv_def_t *priv_def = NULL;
                    text_t priv_name;
                    priv_name.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @2.offset;
                    priv_name.len = @3.offset - @2.offset;
                    cm_trim_text(&priv_name);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create privilege list failed.");
                    }
                    if (cm_galist_new(list, sizeof(knl_priv_def_t), (pointer_t *)&priv_def) != OG_SUCCESS) {
                        parser_yyerror("new priv_def failed.");
                    }
                    if (sql_copy_name(stmt->context, &priv_name, &priv_def->priv_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed.");
                    }
                    priv_def->priv_id = $2;
                    priv_def->priv_type = PRIV_TYPE_USER_PRIV;
                    priv_def->start_loc = @2.loc;

                    if (og_parse_revoke(stmt, &def, PRIV_TYPE_USER_PRIV, list, OBJ_TYPE_USER, $5, $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse revoke failed");
                    }
                    $$ = def;
                }
        ;

revokee_list:
            ColId
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_temp_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create revokee list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert revokee list failed.");
                    }
                    $$ = list;
                }
            | revokee_list ',' ColId
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert revokee list failed.");
                    }
                    $$ = list;
                }
        ;

opt_revoke_cascade:
            CASCADE CONSTRAINTS                  { $$ = true; }
            | /* EMPTY */                        { $$ = false; }
        ;

/* -------------------------
 * PURGE
 * ------------------------- */
PurgeStmt:
            PURGE TABLE_P any_name opt_purge_partition
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    purge_type_t ptype = ($3 != NULL) ? PURGE_PART : PURGE_TABLE;
                    if (og_parse_purge(stmt, &def, ptype, $3, $4) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE TABLE_P SCONST
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_TABLE_OBJECT, NULL, $3) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE INDEX_P any_name
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_INDEX, $3, NULL) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE INDEX_P SCONST
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_INDEX_OBJECT, NULL, $3) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE PARTITION SCONST
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_PART_OBJECT, NULL, $3) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE TABLESPACE ColId
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_TABLESPACE, NULL, $3) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
            | PURGE RECYCLEBIN
                {
                    knl_purge_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_purge(stmt, &def, PURGE_RECYCLEBIN, NULL, NULL) != OG_SUCCESS) {
                        parser_yyerror("parse purge failed");
                    }
                    $$ = def;
                }
        ;

opt_purge_partition:
            PARTITION ColId                      { $$ = $2; }
            | /* EMPTY */                        { $$ = NULL; }
        ;

grantee_list:
            ColId
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_temp_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create grantee list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert grantee list failed.");
                    }
                    $$ = list;
                }
            | grantee_list ',' ColId
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert grantee list failed.");
                    }
                    $$ = list;
                }
        ;

opt_with_grant:
            WITH GRANT OPTION                   { $$ = true; }
            | /* EMPTY */                       { $$ = false; }
        ;

opt_with_admin:
            WITH ADMIN OPTION                   { $$ = true; }
            | /* EMPTY */                       { $$ = false; }
        ;

grant_objtype:
            TABLE_P         { $$ = OBJ_TYPE_TABLE; }
            | VIEW          { $$ = OBJ_TYPE_VIEW; }
            | SEQUENCE      { $$ = OBJ_TYPE_SEQUENCE; }
            | PACKAGE       { $$ = OBJ_TYPE_PACKAGE_SPEC; }
            | PROCEDURE     { $$ = OBJ_TYPE_PROCEDURE; }
            | FUNCTION      { $$ = OBJ_TYPE_FUNCTION; }
            | LIBRARY       { $$ = OBJ_TYPE_LIBRARY; }
        ;

CreateDirectoryStmt:
            CREATE opt_or_replace DIRECTORY ColId AS SCONST
                {
                    knl_directory_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_directory(stmt, &def, $4, $6, $2) != OG_SUCCESS) {
                        parser_yyerror("parse create directory failed");
                    }
                    $$ = def;
                }
        ;

CreateLibraryStmt:
            CREATE opt_or_replace LIBRARY any_name as_is SCONST
                {
                    pl_library_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_create_library(stmt, &def, $4, $6, $2) != OG_SUCCESS) {
                        parser_yyerror("parse create library failed");
                    }
                    $$ = def;
                }
        ;

as_is:
            AS
            | IS
        ;

CreateCtrlfileStmt:
            CREATE CTRLFILE opt_ctrlfile_opts
                {
                    knl_rebuild_ctrlfile_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_create_ctrlfile(stmt, &def, $3) != OG_SUCCESS) {
                        parser_yyerror("parse create ctrlfile failed");
                    }
                    $$ = def;
                }
        ;

opt_ctrlfile_opts:
            ctrlfile_opts                                 { $$ = $1; }
            | /* EMPTY */                                 { $$ = NULL; }
        ;

ctrlfile_opts:
            ctrlfile_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create ctrlfile opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert ctrlfile opt failed.");
                    }
                    $$ = list;
                }
            | ctrlfile_opts ctrlfile_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert ctrlfile opt failed.");
                    }
                    $$ = list;
                }
        ;

ctrlfile_opt:
            LOGFILE ctrlfile_file_list
                {
                    ctrlfile_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(ctrlfile_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CTRLFILE_LOGFILE_OPT;
                    opt->file_list = $2;
                    $$ = opt;
                }
            | DATAFILE ctrlfile_file_list
                {
                    ctrlfile_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(ctrlfile_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CTRLFILE_DATAFILE_OPT;
                    opt->file_list = $2;
                    $$ = opt;
                }
            | CHARSET charset_collate_name
                {
                    ctrlfile_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(ctrlfile_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CTRLFILE_CHARSET_OPT;
                    opt->charset = $2;
                    $$ = opt;
                }
            | ARCHIVELOG
                {
                    ctrlfile_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(ctrlfile_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CTRLFILE_ARCHIVELOG_OPT;
                    $$ = opt;
                }
            | NOARCHIVELOG
                {
                    ctrlfile_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(ctrlfile_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CTRLFILE_NOARCHIVELOG_OPT;
                    $$ = opt;
                }
        ;

ctrlfile_file_list:
            '(' ctrlfile_files ')'
                {
                    $$ = $2;
                }
        ;

ctrlfile_files:
            ctrlfile_file
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create ctrlfile list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert ctrlfile file failed.");
                    }
                    $$ = list;
                }
            | ctrlfile_files ',' ctrlfile_file
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert ctrlfile file failed.");
                    }
                    $$ = list;
                }
        ;

ctrlfile_file:
            SCONST
                {
                    knl_device_def_t *file = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_device_def_t), (void **)&file) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    const text_t name = { $1, strlen($1) };
                    if (sql_copy_file_name(stmt->context, (text_t *)&name, &file->name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed.");
                    }
                    $$ = file;
                }
        ;

/* create_table_prefix encodes bit 0 as TEMPORARY and bit 1 as GLOBAL. */
create_table_prefix:
            CREATE TABLE_P                                  { $$ = 0; }
            | CREATE TEMPORARY TABLE_P                      { $$ = 1; }
            | CREATE GLOBAL TABLE_P                         { $$ = 2; }
            | CREATE GLOBAL TEMPORARY TABLE_P               { $$ = 3; }
        ;

CreateTableStmt:
            create_table_prefix opt_if_not_exists any_name '(' OptTableElementList ')'
            opt_table_attrs opt_as_select
                {
                    knl_table_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    bool32 is_temp = ($1 & 1) != 0;
                    bool32 is_global = ($1 & 2) != 0;

                    if (is_global && !is_temp) {
                        parser_yyerror("TEMPORARY expected");
                    }
                    if (og_parse_create_table(stmt, &def, is_temp, is_global, $2, $3, $5, $7, $8, NULL) !=
                        OG_SUCCESS) {
                        parser_yyerror("parse create table failed");
                    }
                    $$ = def;
                }
            | create_table_prefix opt_if_not_exists any_name opt_table_attrs AS SelectStmt
                {
                    knl_table_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    bool32 is_temp = ($1 & 1) != 0;
                    bool32 is_global = ($1 & 2) != 0;

                    if (is_global && !is_temp) {
                        parser_yyerror("TEMPORARY expected");
                    }
                    if (og_parse_create_table(stmt, &def, is_temp, is_global, $2, $3, NULL, $4, $6, NULL) !=
                        OG_SUCCESS) {
                        parser_yyerror("parse create table failed");
                    }
                    $$ = def;
                }
            | create_table_prefix opt_if_not_exists any_name '(' OptTableElementList ')' external_table
                {
                    knl_table_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    bool32 is_temp = ($1 & 1) != 0;
                    bool32 is_global = ($1 & 2) != 0;

                    if (is_global && !is_temp) {
                        parser_yyerror("TEMPORARY expected");
                    }
                    if (og_parse_create_table(stmt, &def, is_temp, is_global, $2, $3, $5, NULL, NULL, $7) !=
                        OG_SUCCESS) {
                        parser_yyerror("parse create table failed");
                    }
                    $$ = def;
                }
        ;

external_table:
            ORGANIZATION EXTERNAL '(' TYPE_P LOADER_P DIRECTORY ColId LOCATION SCONST ')'
                {
                    knl_ext_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_organization(stmt, &def, $7, $9, NULL, NULL) != OG_SUCCESS) {
                        parser_yyerror("parse organizatioon failed");
                    }
                    $$ = def;
                }
            | ORGANIZATION EXTERNAL '(' TYPE_P LOADER_P DIRECTORY ColId ACCESS PARAMETERS
            '(' RECORDS DELIMITED BY opt_delimited FIELDS TERMINATED BY field_terminate ')'
            LOCATION SCONST ')'
                {
                    knl_ext_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (og_parse_organization(stmt, &def, $7, $21, $14, $18) != OG_SUCCESS) {
                        parser_yyerror("parse organizatioon failed");
                    }
                    $$ = def;
                }
        ;

opt_delimited:
            NEWLINE
                {
                    $$ = "\n";
                }
            | SCONST
                {
                    if (strlen($1) != 1) {
                        parser_yyerror("only single character is supported for records delimiter");
                    }
                    $$ = $1;
                }
        ;

field_terminate:
            SCONST
                {
                    if (strlen($1) != 1) {
                        parser_yyerror("only single character is supported for fields delimiter");
                    }
                    $$ = $1;
                }
        ;

OptTableElementList:
            TableElement
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create table column list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert table column item failed.");
                    }
                    $$ = list;
                }
            | OptTableElementList ',' TableElement
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert table column item failed.");
                    }
                    $$ = list;
                }
        ;

TableElement:
            columnDef
                {
                    parse_table_element_t *element = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parse_table_element_t), (void **)&element) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    element->is_constraint = OG_FALSE;
                    element->col = $1;
                    $$ = element;
                }
            | TableConstraint
                {
                    parse_table_element_t *element = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parse_table_element_t), (void **)&element) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    element->is_constraint = OG_TRUE;
                    element->cons = $1;
                    $$ = element;
                }
        ;

columnDef:
            ColId opt_column_type opt_column_attrs
                {
                    parse_column_t *col = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(parse_column_t), (void **)&col) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    col->col_name = $1;
                    col->type = $2;
                    col->column_attrs = $3;
                    $$ = col;
                }
        ;

opt_column_type:
            Typename                                 { $$ = $1; }
            | /* EMPTY */         %prec UMINUS       { $$ = NULL; }
        ;

opt_column_attrs:
            column_attrs                             { $$ = $1; }
            | /* EMPTY */                            { $$ = NULL; }
        ;

column_attrs:
            column_attr
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column attr list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert column attr failed.");
                    }
                    $$ = list;
                }
            | column_attrs column_attr
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert column attr failed.");
                    }
                    $$ = list;
                }
        ;

opt_column_on_update:
            ON UPDATE a_expr                            { $$ = $3; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

opt_equal:
            '='
            | /* EMPTY */
        ;

column_attr:
            DEFAULT a_expr opt_column_on_update
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_DEFAULT;
                    attr->default_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @2.offset;
                    attr->default_text.len = yylloc.offset - @2.offset;
                    attr->insert_expr = $2;
                    attr->update_expr = $3;
                    $$ = attr;
                }
            | COMMENT SCONST
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_COMMENT;
                    attr->comment = $2;
                    $$ = attr;
                }
            | AUTO_INCREMENT
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_AUTO_INCREMENT;
                    $$ = attr;
                }
            | COLLATE opt_equal charset_collate_name
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_COLLATE;
                    attr->collate = $3;
                    $$ = attr;
                }
            | column_attr_cons
                {
                    $$ = $1;
                }
            | CONSTRAINT ColId column_attr_cons
                {
                    column_attr_t *attr = $3;
                    attr->cons_name = $2;
                    $$ = attr;
                }
        ;
    
column_attr_cons:
            PRIMARY KEY
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_PRIMARY;
                    $$ = attr;
                }
            | UNIQUE
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_UNIQUE;
                    $$ = attr;
                }
            | REFERENCES any_name '(' table_column_list ')' opt_foreign_action
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_REFERENCES;
                    attr->ref = $2;
                    attr->ref_cols = $4;
                    attr->refactor = $6;
                    $$ = attr;
                }
            | CHECK '(' cond_tree_expr ')'
                {
                    column_attr_t *attr = NULL;
                    text_t check_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_CHECK;
                    check_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @3.offset;
                    check_text.len = @4.offset - @3.offset;
                    cm_trim_text(&check_text);
                    if (sql_copy_text(stmt->context, &check_text, &attr->check_text)) {
                        parser_yyerror("copy text failed");
                    }
                    attr->cond = $3;
                    $$ = attr;
                }
            | NOT NULL_P
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_NOT_NULL;
                    $$ = attr;
                }
            | NULL_P
                {
                    column_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(column_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = COL_ATTR_NULL;
                    $$ = attr;
                }
        ;

TableConstraint:
            CONSTRAINT ColId ConstraintElem
                {
                    // Constraint with name
                    parse_constraint_t *cons = $3;
                    cons->name = $2;
                    $$ = cons;
            }
            | ConstraintElem
                {
                    $$ = $1;
                }
        ;

opt_constraint_states:
            constraint_states                           { $$ = $1; }
            | /* EMPTY */                               { $$ = NULL; }
            /*
             * Keep USING INDEX as a dedicated tail here instead of a plain constraint_state item.
             * Otherwise PARALLEL/REVERSE can be parsed both as constraint states and as createidx_opts,
             * which introduces bison shift/reduce conflicts.
             */
            | constraint_states USING INDEX_P opt_createidx_opts
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_USING_INDEX;
                    state->index_opts = $4;

                    galist_t *list = $1;
                    if (cm_galist_insert(list, state) != OG_SUCCESS) {
                        parser_yyerror("insert constraint states list failed.");
                    }
                    $$ = list;
                }
            | USING INDEX_P opt_createidx_opts
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_USING_INDEX;
                    state->index_opts = $3;

                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create constraint states list failed.");
                    }
                    if (cm_galist_insert(list, state) != OG_SUCCESS) {
                        parser_yyerror("insert constraint states list failed.");
                    }
                    $$ = list;
                }
        ;

constraint_states:
            constraint_state
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create constraint states list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert constraint states list failed.");
                    }
                    $$ = list;
                }
            | constraint_states constraint_state
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert constraint states list failed.");
                    }
                    $$ = list;
                }
        ;

constraint_state:
            ENABLE_P
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_ENABLE;
                    $$ = state;
                }
            | DISABLE_P
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_DISABLE;
                    $$ = state;
                }
            | NOT DEFERRABLE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_NOT_DEFEREABLE;
                    $$ = state;
                }
            | DEFERRABLE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_DEFEREABLE;
                    $$ = state;
                }
            | INITIALLY IMMEDIATE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_INITIALLY_IMMEDIATE;
                    $$ = state;
                }
            | INITIALLY DEFERRED
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_INITIALLY_DEFERRED;
                    $$ = state;
                }
            | RELY
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_RELY;
                    $$ = state;
                }
            | NORELY
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_NO_RELY;
                    $$ = state;
                }
            | VALIDATE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_VALIDATE;
                    $$ = state;
                }
            | NOVALIDATE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_NO_VALIDATE;
                    $$ = state;
                }
            | PARALLEL ICONST
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_PARALLEL;
                    if ($2 <= 0 || $2 > OG_MAX_INDEX_PARALLELISM) {
                        parser_yyerror("parallelism must between 1 and 48. ");
                    }
                    state->parallelism = $2;
                    $$ = state;
                }
            | REVERSE
                {
                    constraint_state *state = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(constraint_state),
                        (void **)&state) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    state->type = CONS_STATE_REVERSE;
                    $$ = state;
                }
        ;

ConstraintElem:
            PRIMARY KEY '(' table_column_list ')' opt_constraint_states
                {
                    parse_constraint_t *cons = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(parse_constraint_t),
                        (void **)&cons) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cons->type = CONS_TYPE_PRIMARY;
                    cons->column_list = $4;
                    cons->state_opts = $6;
                    $$ = cons;
                }
            | UNIQUE '(' table_column_list ')' opt_constraint_states
                {
                    parse_constraint_t *cons = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(parse_constraint_t),
                        (void **)&cons) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cons->type = CONS_TYPE_UNIQUE;
                    cons->column_list = $3;
                    cons->state_opts = $5;
                    $$ = cons;
                }
            | FOREIGN_KEY '(' table_column_list ')' REFERENCES any_name '(' table_column_list ')' opt_foreign_action
                {
                    parse_constraint_t *cons = NULL;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(parse_constraint_t),
                        (void **)&cons) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cons->type = CONS_TYPE_REFERENCE;
                    cons->cols = $3;
                    cons->ref = $6;
                    cons->ref_cols = $8;
                    cons->refactor = $10;
                    $$ = cons;
                }
            | CHECK '(' cond_tree_expr ')'
                {
                    parse_constraint_t *cons = NULL;
                    text_t check_text;
                    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(parse_constraint_t),
                        (void **)&cons) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cons->type = CONS_TYPE_CHECK;
                    check_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @3.offset;
                    check_text.len = @4.offset - @3.offset;
                    cm_trim_text(&check_text);
                    if (sql_copy_text(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, &check_text, &cons->check_text)) {
                        parser_yyerror("copy text failed");
                    }
                    cons->cond = $3;
                    $$ = cons;
                }
        ;

opt_foreign_action:
            ON DELETE_P CASCADE                         { $$ = REF_DEL_NOT_ALLOWED | REF_DEL_CASCADE; }
            | ON DELETE_P SET NULL_P                    { $$ = REF_DEL_NOT_ALLOWED | REF_DEL_SET_NULL; }
            | /* EMPTY */                               { $$ = REF_DEL_NOT_ALLOWED; }
        ;

table_column_list:
            table_column
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column list failed");
                    }
                    cm_galist_insert(list, $1);
                    $$ = list;
                }
            | table_column_list ',' table_column
                {
                    galist_t *list = $1;
                    cm_galist_insert(list, $3);
                    $$ = list;
                }
        ;

table_column:
            ColId
                {
                    /* Create index column entry */
                    knl_index_col_def_t *col_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_index_col_def_t), (void **)&col_def) != OG_SUCCESS) {
                        parser_yyerror("alloc memory failed");
                    }
                    col_def->is_func = OG_FALSE;
                    col_def->func_expr = NULL;
                    col_def->func_text.len = 0;
                    col_def->name.str = $1;
                    col_def->name.len = strlen($1);
                    $$ = col_def;
                }
        ;

column_name_list:
            ColId
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column name list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert column name failed.");
                    }
                    $$ = list;
                }
            | column_name_list ',' ColId
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert column name failed.");
                    }
                    $$ = list;
                }
        ;

opt_table_attrs:
            table_attrs                              { $$ = $1; }
            | /* EMPTY */                            { $$ = NULL; }
        ;

table_attrs:
            table_attr
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create table attr list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert table attr failed.");
                    }
                    $$ = list;
                }
            | table_attrs table_attr
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert table attr failed.");
                    }
                    $$ = list;
                }
        ;

table_attr:
            TABLESPACE tablespace_name
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_TABLESPACE;
                    attr->str_value = $2;
                    $$ = attr;
                }
            | INITRANS ICONST
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_INITRANS;
                    if ($2 <= 0 || $2 > OG_MAX_TRANS) {
                        parser_yyerror("initrans must between 1 and 255.");
                    }
                    attr->int_value = $2;
                    $$ = attr;
                }
            | MAXTRANS ICONST
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_MAXTRANS;
                    if ($2 <= 0 || $2 > OG_MAX_TRANS) {
                        parser_yyerror("maxtrans must between 1 and 255.");
                    }
                    attr->int_value = $2;
                    $$ = attr;
                }
            | PCTFREE ICONST
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_PCTFREE;
                    if ($2 < 0 || $2 > 80) {
                        parser_yyerror("initrans must between 0 and 80.");
                    }
                    attr->int_value = $2;
                    $$ = attr;
                }
            | CRMODE row_or_page
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_CRMODE;
                    attr->int_value = $2;
                    $$ = attr;
                }
            | FORMAT csf_or_asf
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_FORMAT;
                    attr->bool_value = $2;
                    $$ = attr;
                }
            | SYSTEM_P ICONST
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_SYSTEM;
                    if ($2 <= 0 || $2 >= OG_EX_SYSID_END || ($2 >= OG_RESERVED_SYSID && $2 < OG_EX_SYSID_START)) {
                        parser_yyerror("system must between 1 and 64 or 1024 and 1536 ");
                    }
                    attr->int_value = $2;
                    $$ = attr;
                }
            | STORAGE '(' storage_opts ')'
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_STORAGE;
                    attr->storage_def = $3;
                    $$ = attr;
                }
            | LOB '(' column_name_list ')' STORE_P AS opt_seg_name opt_lob_store_params
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_LOB;
                    attr->lob_columns = $3;
                    attr->seg_name = $7;
                    attr->lob_store_params = $8;
                    $$ = attr;
                }
            | ON COMMIT delete_or_perserve ROWS
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_ON_COMMIT;
                    attr->int_value = $3;
                    $$ = attr;
                }
            | APPENDONLY on_or_off
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_APPENDONLY;
                    attr->bool_value = $2;
                    $$ = attr;
                }
            | table_partitioning_clause
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_PARTITION;
                    attr->partition = (parser_table_part*)$1;
                    $$ = attr;
                }
            | AUTO_INCREMENT opt_equal num_size
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_AUTO_INCREMENT;
                    attr->int64_value = $3;
                    $$ = attr;
                }
            | opt_default charset opt_equal charset_collate_name
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_CHARSET;
                    attr->str_value = $4;
                    $$ = attr;
                }
            | opt_default COLLATE opt_equal charset_collate_name
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_COLLATE;
                    attr->str_value = $4;
                    $$ = attr;
                }
            | CACHE
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_CACHE;
                    $$ = attr;
                }
            | NOCACHE
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_NO_CACHE;
                    $$ = attr;
                }
            | LOGGING
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_LOGGING;
                    $$ = attr;
                }
            | NOLOGGING
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_NO_LOGGING;
                    $$ = attr;
                }
            | COMPRESS opt_compress_for
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_COMPRESS;
                    attr->int_value = $2;
                    $$ = attr;
                }
            | NOCOMPRESS
                {
                    table_attr_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = TABLE_ATTR_NO_COMPRESS;
                    $$ = attr;
                }
        ;

table_partitioning_clause:
            range_partitioning_clause                       { $$ = $1; }
            | list_partitioning_clause                      { $$ = $1; }
            | hash_partitioning_clause                      { $$ = $1; }
        ;

range_partitioning_clause:
            PARTITION BY RANGE '(' column_name_list ')' opt_interval_partition_clause subpartitioning_clause
            opt_subpartitions_num '(' range_partition_list ')'
                {
                    parser_table_part *part = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_table_part), (void **)&part) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    part->part_type = PART_TYPE_RANGE;
                    part->column_list = $5;
                    part->interval = (parser_interval_part*)$7;
                    part->subpart = $8;

                    if ((part->subpart == NULL || part->subpart->part_type != PART_TYPE_HASH) && $9 != NULL) {
                        parser_yyerror("only hash partition can specify subpartitions");
                    }

                    part->subpart_store_in = $9;
                    part->partitions = $11;
                    $$ = part;
                }
        ;

range_partition_list:
            range_partition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | range_partition_list ',' range_partition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

range_partition_item:
            PARTITION ColId VALUES LESS THAN '(' range_partition_boundary_list ')' opt_part_options
            opt_subpartition_clause
                {
                    part_item_t *item = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @7.offset;
                    expr_text.len = @8.offset - @7.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &item->hiboundval) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    item->name = $2;
                    item->boundaries = $7;
                    item->opts = $9;
                    item->subpart_clause = (subpart_clause_t*)$10;
                    $$ = item;
                }
        ;

range_partition_boundary_list:
            a_expr
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | range_partition_boundary_list ',' a_expr
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

opt_subpartition_clause:
            subpartitions_num
                {
                    subpart_clause_t *subpart_clause = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(subpart_clause_t), (void **)&subpart_clause) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart_clause->is_store_in = OG_TRUE;
                    subpart_clause->subpart_store_in = $1;
                    $$ = subpart_clause;
                }
            | '(' range_subpartition_list ')'
                {
                    subpart_clause_t *subpart_clause = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(subpart_clause_t), (void **)&subpart_clause) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart_clause->is_store_in = OG_FALSE;
                    subpart_clause->subparts = $2;
                    $$ = subpart_clause;
                }
            | '(' list_subpartition_list ')'
                {
                    subpart_clause_t *subpart_clause = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(subpart_clause_t), (void **)&subpart_clause) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart_clause->is_store_in = OG_FALSE;
                    subpart_clause->subparts = $2;
                    $$ = subpart_clause;
                }
            | '(' hash_subpartition_list ')'
                {
                    subpart_clause_t *subpart_clause = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(subpart_clause_t), (void **)&subpart_clause) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart_clause->is_store_in = OG_FALSE;
                    subpart_clause->subparts = $2;
                    $$ = subpart_clause;
                }
            | /* EMPTY */
                {
                    $$ = NULL;
                }
        ;

range_subpartition_list:
            range_subpartition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | range_subpartition_list ',' range_subpartition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

range_subpartition_item:
            SUBPARTITION ColId VALUES LESS THAN '(' range_partition_boundary_list ')' opt_subpart_tablespace_option
                {
                    part_item_t *item = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @7.offset;
                    expr_text.len = @8.offset - @7.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &item->hiboundval) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    item->name = $2;
                    item->boundaries = $7;
                    item->tablespace = $9;
                    $$ = item;
                }
        ;

list_subpartition_list:
            list_subpartition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | list_subpartition_list ',' list_subpartition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

list_subpartition_item:
            SUBPARTITION ColId VALUES '(' listValueList ')' opt_subpart_tablespace_option
                {
                    part_item_t *item = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @5.offset;
                    expr_text.len = @6.offset - @5.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &item->hiboundval) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    item->name = $2;
                    item->boundaries = $5;
                    item->tablespace = $7;
                    $$ = item;
                }
        ;

hash_subpartition_list:
            hash_subpartition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | hash_subpartition_list ',' hash_subpartition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

hash_subpartition_item:
            SUBPARTITION ColId opt_subpart_tablespace_option
                {
                    part_item_t *item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    item->name = $2;
                    item->tablespace = $3;
                    $$ = item;
                }
        ;

list_partitioning_clause:
            PARTITION BY LIST '(' column_name_list ')' subpartitioning_clause
            opt_subpartitions_num '(' list_partition_list ')'
                {
                    parser_table_part *part = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_table_part), (void **)&part) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    part->part_type = PART_TYPE_LIST;
                    part->column_list = $5;
                    part->subpart = $7;

                    if ((part->subpart == NULL || part->subpart->part_type != PART_TYPE_HASH) && $8 != NULL) {
                        parser_yyerror("only hash partition can specify subpartitions");
                    }

                    part->subpart_store_in = $8;
                    part->partitions = $10;
                    $$ = part;
                }
        ;

list_partition_list:
            list_partition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | list_partition_list ',' list_partition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

list_partition_item:
            PARTITION ColId VALUES '(' listValueList ')' opt_part_options
            opt_subpartition_clause
                {
                    part_item_t *item = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @5.offset;
                    expr_text.len = @6.offset - @5.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &item->hiboundval) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    item->name = $2;
                    item->boundaries = $5;
                    item->opts = $7;
                    item->subpart_clause = $8;
                    $$ = item;
                }
        ;

listValueList:
            DEFAULT                                         { $$ = NULL; }
            | expr_or_implicit_row_list                     { $$ = $1; }
        ;

hash_partitioning_clause:
            PARTITION BY HASH '(' column_name_list ')' subpartitioning_clause
            partitions_num opt_subpartitions_num
                {
                    parser_table_part *part = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_table_part), (void **)&part) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    part->part_type = PART_TYPE_HASH;
                    part->column_list = $5;
                    part->subpart = (parser_table_subpart*)$7;
                    part->part_store_in = $8;

                    if ((part->subpart == NULL || part->subpart->part_type != PART_TYPE_HASH) && $9 != NULL) {
                        parser_yyerror("only hash partition can specify subpartitions");
                    }

                    part->subpart_store_in = $9;
                    $$ = part;
                }
            | PARTITION BY HASH '(' column_name_list ')' subpartitioning_clause
              opt_subpartitions_num '(' hash_partition_list ')'
                {
                    parser_table_part *part = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_table_part), (void **)&part) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    part->part_type = PART_TYPE_HASH;
                    part->column_list = $5;
                    part->subpart = (parser_table_subpart*)$7;

                    if ((part->subpart == NULL || part->subpart->part_type != PART_TYPE_HASH) && $8 != NULL) {
                        parser_yyerror("only hash partition can specify subpartitions");
                    }

                    part->subpart_store_in = $8;
                    part->partitions = $10;
                    $$ = part;
                }
        ;

hash_partition_list:
            hash_partition_item
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
            | hash_partition_list ',' hash_partition_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed.");
                    }
                    $$ = list;
                }
        ;

hash_partition_item:
            PARTITION ColId opt_part_options opt_subpartition_clause
                {
                    part_item_t *item = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_item_t), (void **)&item) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    item->name = $2;
                    item->opts = $3;
                    item->subpart_clause = $4;
                    $$ = item;
                }
        ;

opt_interval_partition_clause:
            INTERVAL '(' a_expr ')' opt_interval_tablespaceList
                {
                    parser_interval_part *interval = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_interval_part), (void **)&interval) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @3.offset;
                    expr_text.len = @4.offset - @3.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &interval->interval_text) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    interval->expr = $3;
                    interval->tablespaces = $5;
                    $$ = interval;
                }
            | /* EMPTY */                                       { $$ = NULL; }
        ;

opt_interval_tablespaceList:
            STORE_P IN_P  '(' tablespaceList ')'                { $$= $4; }
            | /* EMPTY */                                       { $$ = NULL; }
        ;

tablespaceList:
            tablespace
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create tablespace list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert tablespace failed.");
                    }
                    $$ = list;
                }
            | tablespaceList ',' tablespace
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert tablespace failed.");
                    }
                    $$ = list;
                }
        ;

tablespace:
            TABLESPACE tablespace_name                      { $$ = $2; }
        ;

subpartitioning_clause:
            SUBPARTITION BY partition_type '(' column_name_list ')'
                {
                    parser_table_subpart *subpart = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(parser_table_subpart), (void **)&subpart) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart->part_type = $3;
                    subpart->column_list = $5;
                    $$ = subpart;
                }
            | /* empty */                       { $$ = NULL; }
        ;

partition_type:
            RANGE                                           { $$ = PART_TYPE_RANGE; }
            | LIST                                          { $$ = PART_TYPE_LIST; }
            | HASH                                          { $$ = PART_TYPE_HASH; }
        ;

partitions_num:
            PARTITIONS ICONST opt_partition_store_in_clause
                {
                    part_store_in_clause *store_in = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_store_in_clause), (void **)&store_in) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    store_in->num = $2;
                    store_in->tablespaces = $3;
                    $$ = store_in;
                }
        ;

opt_partition_store_in_clause:
            STORE_P IN_P '(' tablespace_name_list ')'       { $$ = $4; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

subpartitions_num:
            SUBPARTITIONS ICONST opt_partition_store_in_clause
                {
                    part_store_in_clause *store_in = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(part_store_in_clause), (void **)&store_in) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    store_in->num = $2;
                    store_in->tablespaces = $3;
                    $$ = store_in;
                }
        ;

opt_subpartitions_num:
            subpartitions_num                               { $$ = $1; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

opt_seg_name:
            ColId                               { $$ = $1; }
            | /* EMPTY */   %prec UNBOUNDED     { $$ = NULL; }
        ;

opt_lob_store_params:
            '(' lob_store_params ')'                    { $$ = $2; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

lob_store_params:
            lob_store_param
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column name list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert column name failed.");
                    }
                    $$ = list;
                }
            | lob_store_params ',' lob_store_param
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert column name failed.");
                    }
                    $$ = list;
                }
        ;

lob_store_param:
            TABLESPACE tablespace_name
                {
                    lob_store_param_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = LOB_STORE_PARAM_TABLESPACE;
                    attr->str_value = $2;
                    $$ = attr;
                }
            | ENABLE_P STORAGE IN_P ROW
                {
                    lob_store_param_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = LOB_STORE_PARAM_STORAGE_IN_ROW;
                    attr->bool_value = OG_TRUE;
                    $$ = attr;
                }
            | DISABLE_P STORAGE IN_P ROW
                {
                    lob_store_param_t *attr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(table_attr_t), (void **)&attr) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    attr->type = LOB_STORE_PARAM_STORAGE_IN_ROW;
                    attr->bool_value = OG_FALSE;
                    $$ = attr;
                }
        ;

delete_or_perserve:
            DELETE_P                            { $$ = TABLE_TYPE_TRANS_TEMP; }
            | PRESERVE                          { $$ = TABLE_TYPE_SESSION_TEMP; }
        ;

charset:
            CHARACTER SET
            | CHARSET
        ;

opt_default:
            DEFAULT
            | /* EMPTY */
        ;

opt_as_select:
            AS SelectStmt                            { $$ = $2; }
            | /* EMPTY */                            { $$ = NULL; }
        ;

opt_unique:
            UNIQUE                                  { $$ = true; }
            | /* EMPTY */                           { $$ = false; }
        ;

opt_if_not_exists:
            IF_P NOT EXISTS                         { $$ = true; }
            | /* EMPTY */      %prec UMINUS         { $$ = false; }
        ;

index_column_list:
            index_column
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create column list failed");
                    }
                    cm_galist_insert(list, $1);
                    $$ = list;
                }
            | index_column_list ',' index_column
                {
                    galist_t *list = $1;
                    cm_galist_insert(list, $3);
                    $$ = list;
                }
        ;

index_column:
            ColId opt_asc_desc
                {
                    /* Create index column entry */
                    knl_index_col_def_t *col_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_index_col_def_t), (void **)&col_def) != OG_SUCCESS) {
                        parser_yyerror("alloc memory failed");
                    }
                    col_def->is_func = OG_FALSE;
                    col_def->func_expr = NULL;
                    col_def->func_text.len = 0;
                    col_def->name.str = $1;
                    col_def->name.len = strlen($1);
                    col_def->mode = $2;
                    $$ = col_def;
                }
            | func_expr_windowless opt_asc_desc
                {
                    /* Create index column entry */
                    knl_index_col_def_t *col_def = NULL;
                    text_t expr_text;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_index_col_def_t), (void **)&col_def) != OG_SUCCESS) {
                        parser_yyerror("alloc memory failed");
                    }
                    col_def->is_func = OG_TRUE;
                    col_def->func_expr = $1;
                    col_def->name.len = 0;

                    expr_text.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @1.offset;
                    expr_text.len = @2.offset == @1.offset ? yylloc.offset - @1.offset : @2.offset - @1.offset;
                    cm_trim_text(&expr_text);
                    if (sql_copy_text(stmt->context, &expr_text, &col_def->func_text) != OG_SUCCESS) {
                        parser_yyerror("copy text failed");
                    }
                    col_def->mode = $2;
                    $$ = col_def;
                }
        ;

func_expr_windowless:
            func_application                        { $$ = $1; }
            | func_expr_common_subexpr              { $$ = $1; }
            | case_expr                             { $$ = $1; }
        ;

createidx_opt:
            TABLESPACE tablespace_name
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_TABLESPACE;
                    opt->name = $2;
                    $$ = opt;
                }
            | INITRANS ICONST
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($2 <= 0 || $2 > OG_MAX_TRANS) {
                        parser_yyerror("initrans must between 1 and 255 ");
                    }
                    opt->type = CREATEIDX_OPT_INITRANS;
                    opt->size = $2;
                    $$ = opt;
                }
            | LOCAL opt_partition_index_def
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_LOCAL;
                    opt->list = $2;
                    $$ = opt;
                }
            | PCTFREE ICONST
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($2 > OG_PCT_FREE_MAX) {
                        parser_yyerror("pctfree must between 0 and 80 ");
                    }
                    opt->type = CREATEIDX_OPT_PCTFREE;
                    opt->size = $2;
                    $$ = opt;
                }
            | CRMODE row_or_page
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_CRMODE;
                    opt->cr_mode = (uint8)$2;
                    $$ = opt;
                }
            | ONLINE
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_ONLINE;
                    $$ = opt;
                }
            | PARALLEL ICONST
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($2 <= 0 || $2 > OG_MAX_INDEX_PARALLELISM) {
                        parser_yyerror("parallelism must between 1 and 48 ");
                    }
                    opt->type = CREATEIDX_OPT_PARALLEL;
                    opt->size = $2;
                    $$ = opt;
                }
            | REVERSE
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_REVERSE;
                    $$ = opt;
                }
            | NOLOGGING
                {
                    createidx_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEIDX_OPT_NOLOGGING;
                    $$ = opt;
                }
        ;

row_or_page:
            ROW                                 { $$ = CR_ROW; }
            | PAGE                              { $$ = CR_PAGE; }
        ;

opt_partition_index_def:
            '(' partition_index_list  ')'       { $$ = $2; }
            | /* EMPTY */                       {$$ = NULL;}
        ;

partition_index_list:
            partition_index_item
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create part_parse_info list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert part_parse_info list failed.");
                    }
                    $$ = list;
                }
            | partition_index_list ',' partition_index_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert part_parse_info list failed.");
                    }
                    $$ = list;
                }
        ;

partition_index_item:
            PARTITION ColId opt_part_options opt_subpartition_index_def
                {
                    index_partition_parse_info *part_parse_info = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_parse_info), (void **)&part_parse_info) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    part_parse_info->name = $2;
                    part_parse_info->opts = $3;
                    part_parse_info->subparts = $4;
                    $$ = part_parse_info;
                }
        ;

opt_part_options:
            part_options                                    { $$ = $1; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

part_options:
            part_option
                {
                    galist_t* list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create part option list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert part option list failed.");
                    }
                    $$ = list;
                }
            | part_options part_option
                {
                    galist_t* list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert part option list failed.");
                    }
                    $$ = list;
                }
        ;

part_option:
            TABLESPACE tablespace_name
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = INDEX_PARTITION_OPT_TABLESPACE;
                    opt->name = $2;
                    $$ = opt;
                }
            | INITRANS ICONST
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($2 <= 0 || $2 > OG_MAX_TRANS) {
                        parser_yyerror("initrans must between 1 and 255 ");
                    }
                    opt->type = INDEX_PARTITION_OPT_INITRANS;
                    opt->size = $2;
                    $$ = opt;
                }
            | PCTFREE ICONST
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if ($2 > OG_PCT_FREE_MAX) {
                        parser_yyerror("pctfree must between 0 and 80 ");
                    }
                    opt->type = INDEX_PARTITION_OPT_PCTFREE;
                    opt->size = $2;
                    $$ = opt;
                }
            | STORAGE '(' storage_opts ')'
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = INDEX_PARTITION_OPT_STORAGE;
                    opt->storage_def = $3;
                    $$ = opt;
                }
            | COMPRESS opt_compress_for
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = INDEX_PARTITION_OPT_COMPRESS;
                    opt->compress_type = $2;
                    $$ = opt;
                }
            | FORMAT csf_or_asf
                {
                    index_partition_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(index_partition_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = INDEX_PARTITION_OPT_FORMAT;
                    opt->csf = $2;
                    $$ = opt;
                }
        ;

storage_opts:
            storage_opt
                {
                    knl_storage_def_t *storage_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(knl_storage_def_t), (void **)&storage_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    switch ($1->type) {
                        case STORAGE_OPT_INITIAL:
                            storage_def->initial = $1->size;
                            break;
                        case STORAGE_OPT_NEXT:
                            storage_def->next = $1->size;
                            break;
                        case STORAGE_OPT_MAXSIZE:
                            storage_def->maxsize = $1->size;
                            break;
                        default:
                            break;
                    }
                    $$ = storage_def;
                }
            | storage_opts storage_opt
                {
                    knl_storage_def_t *storage_def = $1;
                    switch ($2->type) {
                        case STORAGE_OPT_INITIAL:
                            if (storage_def->initial > 0) {
                                parser_yyerror("duplicate storage option specification");
                            }
                            storage_def->initial = $2->size;
                            break;
                        case STORAGE_OPT_NEXT:
                            if (storage_def->next > 0) {
                                parser_yyerror("duplicate storage option specification");
                            }
                            storage_def->next = $2->size;
                            break;
                        case STORAGE_OPT_MAXSIZE:
                            if (storage_def->maxsize > 0) {
                                parser_yyerror("duplicate storage option specification");
                            }
                            storage_def->maxsize = $2->size;
                            break;
                        default:
                            break;
                    }
                    $$ = storage_def;
                }
        ;

storage_opt: 
            INITIAL_P num_size
                {
                    storage_opt_t *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(storage_opt_t), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = STORAGE_OPT_INITIAL;
                    opt->size = $2;
                    if (opt->size < OG_MIN_STORAGE_INITIAL || opt->size > OG_MAX_STORAGE_INITIAL) {
                        parser_yyerror("invalid initial size.");
                    }
                    $$ = opt;
                }
            | NEXT num_size
                {
                    storage_opt_t *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(storage_opt_t), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = STORAGE_OPT_NEXT;
                    opt->size = $2;
                    $$ = opt;
                }
            | MAXSIZE UNLIMITED
                {
                    storage_opt_t *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(storage_opt_t), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = STORAGE_OPT_MAXSIZE;
                    opt->size = OG_INVALID_INT64;
                    $$ = opt;
                }
            | MAXSIZE num_size
                {
                    storage_opt_t *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(storage_opt_t), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = STORAGE_OPT_MAXSIZE;
                    opt->size = $2;
                    if (opt->size < OG_MIN_STORAGE_MAXSIZE || opt->size > OG_MAX_STORAGE_MAXSIZE) {
                        parser_yyerror("invalid maxsize size.");
                    }
                    $$ = opt;
                }
        ;

opt_compress_for:
            FOR ALL OPERATIONS                      { $$ = COMPRESS_TYPE_ALL; }
            | FOR DIRECT_LOAD OPERATIONS            { $$ = COMPRESS_TYPE_DIRECT_LOAD; }
            | /* EMPTY */                           { $$ = COMPRESS_TYPE_GENERAL; }
        ;

csf_or_asf:
            CSF                                     { $$ = true; }
            | ASF                                   { $$ = false; }
        ;

opt_subpartition_index_def:
            '(' subpartition_index_list ')'                         { $$ = $2; }
            | /* EMPTY */                                           { $$ = NULL; }
        ;

subpartition_index_list:
            subpartition_index_item
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create subpartition list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert subpartition list failed.");
                    }
                    $$ = list;
                }
            | subpartition_index_list ',' subpartition_index_item
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert subpartition list failed.");
                    }
                    $$ = list;
                }
        ;

subpartition_index_item:
            SUBPARTITION ColId opt_subpart_tablespace_option
                {
                    knl_part_def_t *subpart_def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_part_def_t), (void **)&subpart_def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    subpart_def->name.str = $2;
                    subpart_def->name.len = strlen($2);
                    if ($3) {
                        subpart_def->space.str = $3;
                        subpart_def->space.len = strlen($3);
                    }
                    $$ = subpart_def;
                }
        ;

opt_subpart_tablespace_option:
            TABLESPACE tablespace_name                  { $$ = $2; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

opt_createidx_opts:
            createidx_opts                   { $$ = $1; }
            | /* EMPTY */                    { $$ = NULL; }
        ;

createidx_opts:
            createidx_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
            | createidx_opts createidx_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
        ;

createts_opt:
            ALL IN_P MEMORY
                {
                    createts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATETS_ALL_OPT;
                    $$ = opt;
                }
            | NOLOGGING
                {
                    createts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATETS_NOLOGGING_OPT;
                    $$ = opt;
                }
            | ENCRYPTION
                {
                    parser_yyerror("unsupport encrypt space");
                }
            | AUTOOFFLINE on_or_off
                {
                    createts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATETS_AUTOOFFLINE_OPT;
                    opt->val = $2;
                    $$ = opt;
                }
            | EXTENT AUTOALLOCATE
                {
                    createts_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(createts_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATETS_EXTENT_OPT;
                    $$ = opt;
                }
        ;

createts_opts:
            createts_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create opt list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
            | createts_opts createts_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert opt failed.");
                    }
                    $$ = list;
                }
        ;

opt_createts_opts:
            createts_opts                   { $$ = $1; }
            | /* EMPTY */                   { $$ = NULL; }
        ;

role_name:
            ColId                           { $$ = $1; }
        ;

tenant_name:
            ColId                           { $$ = $1; }
        ;

opt_role_not_identified:
            /* EMPTY */                     {}
            | NOT IDENTIFIED                {}
        ;

user_password:
            SCONST                          { $$ = $1; }
            | IDENT                         { $$ = og_yyget_extra(yyscanner)->core_yy_extra.origin_str ?
                                                   og_yyget_extra(yyscanner)->core_yy_extra.origin_str : $1; }
        ;

opt_encrypted:
            ENCRYPTED                       { $$ = true; }
            | /* EMPTY */                   { $$ = false; }
        ;

user_name:
            UserId                          { $$ = $1; }
        ;

opt_user_options:
            /* empty */                     { $$ = NULL; }
            | user_option_list              { $$ = $1; }
        ;

user_option_list:
            user_option
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create user option list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert user option failed.");
                    }
                    $$ = list;
                }
            | user_option_list user_option
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert user option failed.");
                    }
                    $$ = list;
                }
        ;

alter_user_options:
            alter_user_option
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create alter user option list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert alter user option failed.");
                    }
                    $$ = list;
                }
            | alter_user_options alter_user_option
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert alter user option failed.");
                    }
                    $$ = list;
                }
        ;

tablespace_name_list:
            tablespace_name
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (sql_create_temp_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create tablespace name list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed");
                    }
                    $$ = list;
                }
            | tablespace_name_list ',' tablespace_name
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed");
                    }

                    $$ = list;
                }
        ;

opt_default_tablespace:
            /* EMPTY */                                     { $$ = NULL; }
            | DEFAULT TABLESPACE tablespace_name            { $$ = $3; }
        ;

opt_alter_user_replace:
            REPLACE user_password                           { $$ = $2; }
            | /* EMPTY */                                   { $$ = NULL; }
        ;

user_option:
            DEFAULT TABLESPACE tablespace_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_DEFAULT_TABLESPACE;
                    option->value = $3;
                    $$ = option;
                }
            | TEMPORARY TABLESPACE tablespace_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_TEMPORARY_TABLESPACE;
                    option->value = $3;
                    $$ = option;
                }
            | PASSWORD EXPIRE
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_PASSWORD_EXPIRE;
                    $$ = option;
                }
            | ACCOUNT LOCK_P
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_ACCOUNT_LOCK;
                    $$ = option;
                }
            | ACCOUNT UNLOCK
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_ACCOUNT_UNLOCK;
                    $$ = option;
                }
            | PROFILE profile_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    if (strcmp($2, "DEFAULT") == 0) {
                        option->type = USER_OPTION_PROFILE_DEFAULT;
                    } else {
                        option->type = USER_OPTION_PROFILE;
                        option->value = $2;
                    }
                    $$ = option;
                }
            | PERMANENT
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc user option failed");
                    }
                    option->type = USER_OPTION_PERMANENT;
                    $$ = option;
                }
        ;

alter_user_option:
            IDENTIFIED BY user_password opt_alter_user_replace
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_IDENTIFIED;
                    option->value = $3;
                    option->old_value = $4;
                    option->loc = @3.loc;
                    $$ = option;
                }
            | DEFAULT TABLESPACE tablespace_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_DEFAULT_TABLESPACE;
                    option->value = $3;
                    $$ = option;
                }
            | TEMPORARY TABLESPACE tablespace_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_TEMPORARY_TABLESPACE;
                    option->value = $3;
                    $$ = option;
                }
            | PASSWORD EXPIRE
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_PASSWORD_EXPIRE;
                    $$ = option;
                }
            | ACCOUNT LOCK_P
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_ACCOUNT_LOCK;
                    $$ = option;
                }
            | ACCOUNT UNLOCK
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    option->type = USER_OPTION_ACCOUNT_UNLOCK;
                    $$ = option;
                }
            | PROFILE profile_name
                {
                    user_option_t *option = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(user_option_t), (void **)&option) != OG_SUCCESS) {
                        parser_yyerror("alloc alter user option failed");
                    }
                    if (strcmp($2, "DEFAULT") == 0) {
                        option->type = USER_OPTION_PROFILE_DEFAULT;
                    } else {
                        option->type = USER_OPTION_PROFILE;
                        option->value = $2;
                    }
                    $$ = option;
                }
        ;

profile_name:
            ColId                           { $$ = $1; }
            | DEFAULT                       { $$ = "DEFAULT"; }
        ;

tablespace_name:
            ColId                           { $$ = $1; }
        ;

arg_class:  IN_P                                { $$ = PLV_DIR_IN; }
            | OUT_P                             { $$ = PLV_DIR_OUT; }
            | IN_P OUT_P                      { $$ = PLV_DIR_INOUT; }
        ;

func_arg_with_default:
            func_arg
                {
                    $$ = $1;
                }
            | func_arg DEFAULT a_expr
                {
                    func_parameter *param = (func_parameter*)$1;
                    param->def_expr = $3;
                    $$ = param;
                }
            | func_arg COLON_EQUALS a_expr
                {
                    func_parameter *param = (func_parameter*)$1;
                    param->def_expr = $3;
                    $$ = param;
                }
        ;

attrs:      '.' ColId
                {
                    galist_t *list = NULL;
                    text_t *text = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_new(list, sizeof(text_t), (pointer_t *)&text) != OG_SUCCESS) {
                        parser_yyerror("init element failed.");
                    }

                    cm_str2text($2, text);
                    $$ = list;
                }
            | attrs '.' ColId
                {
                    galist_t *list = $1;
                    text_t *text = NULL;
                    if (cm_galist_new(list, sizeof(text_t), (pointer_t *)&text) != OG_SUCCESS) {
                        parser_yyerror("init element failed.");
                    }

                    cm_str2text($3, text);
                    $$ = list;
                }
        ;

func_type:
            Typename                                { $$ = $1; }
            | type_function_name attrs '%' ROWTYPE_P
                {
                    type_word_t *type;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(type_word_t), (void **)&type) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    type->str = $1;
                    type->typemode = $2;
                    type->loc = @1.loc;
                    type->pl_rowtype = OG_TRUE;
                    $$ = type;
                }
            | type_function_name '%' ROWTYPE_P
                {
                    type_word_t *type;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(type_word_t), (void **)&type) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    type->str = $1;
                    type->loc = @1.loc;
                    type->pl_rowtype = OG_TRUE;
                    $$ = type;
                }
            | type_function_name attrs '%' TYPE_P
                {
                    type_word_t *type;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(type_word_t), (void **)&type) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    type->str = $1;
                    type->typemode = $2;
                    type->loc = @1.loc;
                    type->pl_type = OG_TRUE;
                    $$ = type;
                }
            | type_function_name '%' TYPE_P
                {
                    type_word_t *type;
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
                        sizeof(type_word_t), (void **)&type) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    type->str = $1;
                    type->loc = @1.loc;
                    type->pl_type = OG_TRUE;
                    $$ = type;
                }
        ;

func_arg:
            ColId func_type
                {
                    func_parameter *param = NULL;
                    if (pl_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_context, sizeof(func_parameter), (void**)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    param->name = $1;
                    param->drct = PLV_DIR_IN;
                    param->type = $2;
                    $$ = param;
                }
            | ColId arg_class func_type
                {
                    func_parameter *param = NULL;
                    if (pl_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_context, sizeof(func_parameter), (void**)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    param->name = $1;
                    param->drct = $2;
                    param->type = $3;
                    $$ = param;
                }
        ;

func_args_with_defaults_list:
            func_arg_with_default
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (sql_create_temp_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed.");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert list failed");
                    }
                    $$ = list;
                }
            | func_args_with_defaults_list ',' func_arg_with_default
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                        parser_yyerror("insert list failed");
                    }
                    $$ = list;
                }
        ;

func_args_with_defaults:
            '(' func_args_with_defaults_list ')'        { $$ = $2; }
            | '(' ')'                                   { $$ = NULL; }
        ;

proc_args:
            func_args_with_defaults                     { $$ = $1; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

opt_authid:
            AUTHID CURRENT_USER                         {}
            | /* EMPTY */                               {}
        ;

opt_package_body:
            BODY_P                                      { $$ = true; }
            | /* EMPTY */       %prec UMINUS            { $$ = false; }
        ;

opt_type_body:
            BODY_P                                      { $$ = true; }
            | /* EMPTY */       %prec UMINUS            { $$ = false; }
        ;

opt_type_force:
            FORCE                                       { $$ = true; }
            | /* EMPTY */                               { $$ = false; }
        ;

pl_as_is_body:
            as_is subprogram_body                       { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
        ;

pl_type_body:
            as_is subprogram_body                       { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
            | UNDER subprogram_body                     { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
        ;

pl_trigger_body:
            BEFORE subprogram_body                      { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
            | AFTER subprogram_body                     { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
            | INSTEAD subprogram_body                   { $$ = pl_prepend_body_start(yyscanner, $2, @1.offset, @1.loc); }
        ;

compileFunctionSource:
            proc_args RETURN Typename as_is subprogram_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (stmt->pl_context == NULL) {
                        parser_yyerror("syntax error");
                    }

                    if (pl_bison_compile_function_source(stmt, $1, $3, $5) != OG_SUCCESS) {
                        parser_yyerror("compile function failed");
                    }

                    $$ = NULL;
                }
        ;

compileProcedureSource:
            func_args_with_defaults opt_authid as_is subprogram_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (stmt->pl_context == NULL) {
                        parser_yyerror("syntax error");
                    }

                    if (pl_bison_compile_procedure_source(stmt, $1, $4) != OG_SUCCESS) {
                        parser_yyerror("compile procedure failed");
                    }

                    $$ = NULL;
                }
            | AUTHID CURRENT_USER as_is subprogram_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (stmt->pl_context == NULL) {
                        parser_yyerror("syntax error");
                    }

                    if (pl_bison_compile_procedure_source(stmt, NULL, $4) != OG_SUCCESS) {
                        parser_yyerror("compile procedure failed");
                    }

                    $$ = NULL;
                }
        ;

compileStoredBodySource:
            as_is subprogram_body
                {
                    if (pl_compile_stored_body_source(yyscanner, $2, @1.offset, @1.loc, OG_TRUE) != OG_SUCCESS) {
                        parser_yyerror("compile stored PL source failed");
                    }

                    $$ = NULL;
                }
            | UNDER subprogram_body
                {
                    if (pl_compile_stored_body_source(yyscanner, $2, @1.offset, @1.loc, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("compile stored PL source failed");
                    }

                    $$ = NULL;
                }
            | BEFORE subprogram_body
                {
                    if (pl_compile_stored_body_source(yyscanner, $2, @1.offset, @1.loc, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("compile stored PL source failed");
                    }

                    $$ = NULL;
                }
            | AFTER subprogram_body
                {
                    if (pl_compile_stored_body_source(yyscanner, $2, @1.offset, @1.loc, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("compile stored PL source failed");
                    }

                    $$ = NULL;
                }
            | INSTEAD subprogram_body
                {
                    if (pl_compile_stored_body_source(yyscanner, $2, @1.offset, @1.loc, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("compile stored PL source failed");
                    }

                    $$ = NULL;
                }
        ;

CreateProcedureStmt:
            CREATE opt_or_replace PROCEDURE {
                if (pl_init_compiler(og_yyget_extra(yyscanner)->core_yy_extra.stmt) != OG_SUCCESS) {
                    parser_yyerror("init pl compiler failed");
                }
            } opt_if_not_exists any_name proc_args opt_authid as_is subprogram_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t storage_source;
                    storage_source.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @7.offset;
                    storage_source.len = yylloc.offset - @7.offset;

                    if (pl_bison_parse_create_procedure(stmt, $2, $5, $6, $7, $10, &storage_source) != OG_SUCCESS) {
                        parser_yyerror("parse create procedure failed");
                    }

                    $$ = NULL;
                }
        ;

CreateFunctionStmt:
            CREATE opt_or_replace FUNCTION {
                if (pl_init_compiler(og_yyget_extra(yyscanner)->core_yy_extra.stmt) != OG_SUCCESS) {
                    parser_yyerror("init pl compiler failed");
                }
            } opt_if_not_exists any_name proc_args RETURN Typename
            as_is subprogram_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t storage_source;
                    storage_source.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @7.offset;
                    storage_source.len = yylloc.offset - @7.offset;

                    if (pl_bison_parse_create_function(stmt, $2, $5, $6, $7, $9, $11, &storage_source) != OG_SUCCESS) {
                        parser_yyerror("parse create function failed");
                    }

                    $$ = NULL;
                }
        ;

CreatePackageStmt:
            CREATE opt_or_replace PACKAGE opt_package_body opt_if_not_exists any_name pl_as_is_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t storage_source;
                    storage_source.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @7.offset;
                    storage_source.len = yylloc.offset - @7.offset;

                    if (pl_bison_parse_create_package(stmt, $2, $4, $5, $6, $7, &storage_source) != OG_SUCCESS) {
                        parser_yyerror("parse create package failed");
                    }

                    $$ = NULL;
                }
        ;

CreateTypeStmt:
            CREATE opt_or_replace TYPE_P opt_type_body opt_if_not_exists any_name opt_type_force pl_type_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t storage_source;
                    storage_source.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @8.offset;
                    storage_source.len = yylloc.offset - @8.offset;

                    if (pl_bison_parse_create_type(stmt, $2, $4, $5, $6, $7, $8, &storage_source) != OG_SUCCESS) {
                        parser_yyerror("parse create type failed");
                    }

                    $$ = NULL;
                }
        ;

CreateTriggerStmt:
            CREATE opt_or_replace TRIGGER opt_if_not_exists any_name pl_trigger_body
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t storage_source;
                    storage_source.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + @6.offset;
                    storage_source.len = yylloc.offset - @6.offset;

                    if (pl_bison_parse_create_trigger(stmt, $2, $4, $5, $6, &storage_source) != OG_SUCCESS) {
                        parser_yyerror("parse create trigger failed");
                    }

                    $$ = NULL;
                }
        ;

AlterTriggerStmt:
            ALTER TRIGGER any_name alter_trigger_enable
                {
                    knl_alttrig_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    if (og_parse_alter_trigger(stmt, &def, $3, $4) != OG_SUCCESS) {
                        parser_yyerror("parse alter trigger failed");
                    }
                    $$ = def;
                }
        ;

alter_trigger_enable:
            ENABLE_P                                        { $$ = true; }
            | DISABLE_P                                     { $$ = false; }
        ;

AlterFunctionStmt:
            ALTER FUNCTION ddl_passthrough_tail
                {
                    OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "alter function");
                    YYABORT;
                    $$ = NULL;
                }
        ;

subprogram_body: {
                sql_text_t *body_src = NULL;
                int	tok = YYLEX;
                int proc_b = yylloc.offset;
                int proc_e = yylloc.offset;
                source_location_t proc_loc = yylloc.loc;
                sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                if (sql_stack_alloc(stmt, sizeof(sql_text_t), (void**)&body_src) != OG_SUCCESS) {
                    parser_yyerror("alloc mem failed");
                }

                while (tok != YYEOF) {
                    if (tok == '/') {
                        proc_e = yylloc.offset;
                    }
                    tok = YYLEX;
                }

                body_src->value.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + proc_b;
                body_src->value.len = proc_e - proc_b;
                body_src->loc = proc_loc;
                body_src->implicit = OG_FALSE;
                $$ = (text_t *)body_src;
            }
        ;

XID: 
            SCONST
                {
                    text_t xid_src;
                    cm_str2text($1, &xid_src);
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_parse_gtid(stmt, &xid_src) != OG_SUCCESS) {
                        parser_yyerror("invalid XID");
                    }
                    $$ = stmt->context->entry;
                }
        ;

LTID: 
            SCONST
                {
                    knl_xid_t *xid = NULL;
                    text_t ltid_src;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    cm_str2text($1, &ltid_src);
                    if (sql_alloc_mem(stmt->context, sizeof(knl_xid_t), (void **)&xid) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (sql_parse_ltid(&ltid_src, xid) != OG_SUCCESS) {
         ///////////////////               cm_try_set_error_loc(word->text.loc);
                        parser_yyerror("invalid LTID");
                    }
                    $$ = xid;
                }
        ;

opt_transaction:
            TRANSACTION                                 {}
            | /*EMPTY*/                                 {}
        ;

opt_backup_opts:
            backup_opts                                   { $$ = $1; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

backup_opts:
            backup_opt
                {
                    galist_t *list = NULL;
                    if (sql_create_temp_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("insert backup opt failed");
                    }
                    $$ = list;
                }
            | backup_opts backup_opt
                {
                    galist_t *list = $1;
                    if (cm_galist_insert(list, $2) != OG_SUCCESS) {
                        parser_yyerror("insert backup opt failed");
                    }
                    $$ = list;
                }
        ;

opt_compress_level:
            LEVEL ICONST                                { $$ = $2; }
            | /* EMPTY */                               { $$ = Z_BEST_SPEED; }

compress_algo:
            LZ4                                         { $$ = COMPRESS_LZ4; }
            | ZLIB                                      { $$ = COMPRESS_ZLIB; }
            | ZSTD                                      { $$ = COMPRESS_ZSTD; }
            | /* EMPTY */                               { $$ = COMPRESS_ZSTD; }

backup_opt:
            /*
             * Keep bison aligned with the native parser, which fetches FORMAT
             * using the string path parser.
             */
            FORMAT SCONST
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_FORMAT_OPT;
                    opt->loc = @2.loc;
                    opt->dest_format = $2;
                    $$ = opt;
                }
            | AS compress_algo COMPRESSED BACKUPSET opt_compress_level
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_AS_OPT;
                    opt->compress_algo = $2;
                    opt->compress_level = $5;
                    opt->loc = @5.loc;
                    $$ = opt;
                }
            | TAG SCONST
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_TAG_OPT;
                    opt->loc = @2.loc;
                    opt->tag = $2;
                    $$ = opt;
                }
            | BUFFER_P SIZE num_size
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_BUFFER_OPT;
                    opt->size = $3;
                    opt->loc = @3.loc;
                    $$ = opt;
                }
            | FULL
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_FULL_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | INCREMENTAL LEVEL ICONST
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_INCREMENTAL_OPT;
                    opt->incremental_level = $3;
                    opt->loc = @3.loc;
                    $$ = opt;
                }
            | INCREMENTAL
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_INCREMENTAL_NO_LEVEL_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | COMPRESS compress_algo opt_compress_level
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_COMPRESS_OPT;
                    opt->compress_algo = $2;
                    opt->compress_level = $3;
                    opt->loc = @3.loc;
                    $$ = opt;
                }
            | PARALLELISM ICONST
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_PARALLELISM_OPT;
                    opt->parallelism = $2;
                    opt->loc = @2.loc;
                    $$ = opt;
                }
            | SECTION THRESHOLD num_size
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_SECTION_OPT;
                    opt->size = $3;
                    opt->loc = @3.loc;
                    $$ = opt;
                }
            | EXCLUDE FOR TABLESPACE tablespace_name_list
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_EXCLUDE_OPT;
                    opt->space_list = $4;
                    opt->loc = @4.loc;
                    $$ = opt;
                }
            | PASSWORD user_password
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_PASSWORD_OPT;
                    opt->passwd = $2;
                    opt->loc = @2.loc;
                    $$ = opt;
                }
            | COPY OF_P TABLESPACE tablespace_name_list
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_COPY_OPT;
                    opt->space_list = $4;
                    opt->loc = @4.loc;
                    $$ = opt;
                }
            | PREPARE
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_PREPARE_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | FINISH SCN BigintOnly
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_FINISH_OPT;
                    opt->scn = $3;
                    opt->loc = @3.loc;
                    $$ = opt;
                }
            | CUMULATIVE
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_CUMULATIVE_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | SKIP BADBLOCK
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_SKIP_BADBLOCK_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | DISCONNECT FROM SESSION
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_DISCONNET_OPT;
                    opt->loc = @1.loc;
                    $$ = opt;
                }
            | TABLESPACE tablespace_name
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_TABLESPACE_OPT;
                    opt->loc = @2.loc;
                    opt->space_name = $2;
                    $$ = opt;
                }
            | REPAIR TYPE_P IDENT
                {
                    backup_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_stack_alloc(stmt, sizeof(backup_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = BACKUP_REPAIR_OPT;
                    opt->loc = @3.loc;
                    opt->repair_type = $3;
                    $$ = opt;
                }
        ;

TransactionStmt:
            PREPARE TRANSACTION XID
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_COMMIT_PHASE1;

                    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
                        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "prepare transaction on coordinator");
                        YYABORT;
                    }
                    $$ = $3;
                }
            | COMMIT opt_transaction
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_COMMIT;

                    $$ = NULL;
                }
            | COMMIT PREPARED XID
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_COMMIT_PHASE2;
                    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
                        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "commit prepared on coordinator");
                        YYABORT;
                    }
                    $$ = $3;
                }
            | COMMIT FORCE LTID
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_COMMIT;

                    $$ = $3;
                }
            | ROLLBACK opt_transaction
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_ROLLBACK;
                    $$ = NULL;
                }
            | ROLLBACK opt_transaction TO IDENT
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_ROLLBACK_TO;
                    
                    text_t *name = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    text_t src;
                    cm_str2text($4, &src);

                    if (sql_copy_object_name(stmt->context, WORD_TYPE_VARIANT, &src, name) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }
                    $$ = name;
                }
            | ROLLBACK opt_transaction TO SAVEPOINT IDENT
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_ROLLBACK_TO;
                    
                    text_t *name = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    text_t src;
                    cm_str2text($5, &src);

                    if (sql_copy_object_name(stmt->context, WORD_TYPE_VARIANT, &src, name) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }
                    $$ = name;
                }
            | ROLLBACK PREPARED XID
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    stmt->session->sql_audit.audit_type = SQL_AUDIT_DML;
                    stmt->context->type = OGSQL_TYPE_ROLLBACK_PHASE2;

                    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
                        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "rollback prepared on coordinator");
                        YYABORT;
                    }
                    $$ = $3;
                }
            | SAVEPOINT IDENT
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SAVEPOINT;

                    text_t *name = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    text_t src;
                    cm_str2text($2, &src);

                    if (sql_copy_object_name(stmt->context, WORD_TYPE_VARIANT, &src, name) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }
                    $$ = name;
                }
            | RELEASE SAVEPOINT IDENT
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RELEASE_SAVEPOINT;

                    text_t *name = NULL;
                    if (sql_alloc_mem(stmt->context, sizeof(text_t), (void **)&name) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }

                    text_t src;
                    cm_str2text($3, &src);

                    if (sql_copy_object_name(stmt->context, WORD_TYPE_VARIANT, &src, name) != OG_SUCCESS) {
                        parser_yyerror("copy object name failed");
                    }
                    $$ = name;
                }
            | SET TRANSACTION ISOLATION LEVEL SERIALIZABLE
                {
                    isolation_level_t *isolevel = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SET_TRANS;

                    if (sql_alloc_mem(stmt->context, sizeof(isolation_level_t), (void **)&isolevel) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    *isolevel = ISOLATION_SERIALIZABLE;
                    $$ = isolevel;
                }
            | SET TRANSACTION ISOLATION LEVEL READ COMMITTED
                {
                    isolation_level_t *isolevel = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SET_TRANS;

                    if (sql_alloc_mem(stmt->context, sizeof(isolation_level_t), (void **)&isolevel) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    *isolevel = ISOLATION_READ_COMMITTED;
                    $$ = isolevel;
                }
            | SET TRANSACTION ISOLATION LEVEL CURRENT_P COMMITTED
                {
                    isolation_level_t *isolevel = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SET_TRANS;

                    if (sql_alloc_mem(stmt->context, sizeof(isolation_level_t), (void **)&isolevel) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    *isolevel = ISOLATION_CURR_COMMITTED;
                    $$ = isolevel;
                }
            | BACKUP_P ARCHIVELOG ALL opt_backup_opts
                {
                    knl_backup_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BACKUP;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->finish_scn = OG_INVALID_ID64;
                    
                    if (sql_create_list(stmt, &param->exclude_spcs) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (sql_create_list(stmt, &param->target_info.target_list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    param->target_info.target = TARGET_ARCHIVE;
                    param->type = BACKUP_MODE_ARCHIVELOG;
                    param->target_info.backup_arch_mode = ARCHIVELOG_ALL;
                    if (og_parse_backup_archivelog(stmt, param, $4) != OG_SUCCESS) {
                        parser_yyerror("parse backup archivelog failed");
                    }
                    if (sql_check_backup_param(stmt, param) != OG_SUCCESS) {
                        parser_yyerror("parse check backup param failed");
                    }
                    $$ = param;
                }
            | BACKUP_P ARCHIVELOG FROM ASN ICONST opt_backup_opts
                {
                    knl_backup_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BACKUP;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->finish_scn = OG_INVALID_ID64;
                    
                    if (sql_create_list(stmt, &param->exclude_spcs) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (sql_create_list(stmt, &param->target_info.target_list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    param->target_info.target = TARGET_ARCHIVE;
                    param->type = BACKUP_MODE_ARCHIVELOG;
                    param->target_info.backup_arch_mode = ARCHIVELOG_FROM;
                    param->target_info.backup_begin_asn = $5;

                    if (og_parse_backup_archivelog(stmt, param, $6) != OG_SUCCESS) {
                        parser_yyerror("parse backup archivelog failed");
                    }
                    if (sql_check_backup_param(stmt, param) != OG_SUCCESS) {
                        parser_yyerror("parse check backup param failed");
                    }
                    $$ = param;
                }
            | BACKUP_P CANCEL CURRENT_P PROCESS
                {
                    knl_backup_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BACKUP;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->finish_scn = OG_INVALID_ID64;
                    param->type = BACKUP_MODE_INVALID;
                    if (sql_create_list(stmt, &param->exclude_spcs) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (sql_create_list(stmt, &param->target_info.target_list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    param->force_cancel = OG_TRUE;
                    $$ = param;
                }
            | BACKUP_P DATABASE opt_backup_opts
                {
                    knl_backup_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BACKUP;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->finish_scn = OG_INVALID_ID64;
                    param->type = BACKUP_MODE_INVALID;
                    if (sql_create_list(stmt, &param->exclude_spcs) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (sql_create_list(stmt, &param->target_info.target_list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (og_parse_backup_database(stmt, param, $3) != OG_SUCCESS) {
                        parser_yyerror("parse backup database failed");
                    }
                    if (sql_check_backup_param(stmt, param) != OG_SUCCESS) {
                        parser_yyerror("parse check backup param failed");
                    }
                    $$ = param;
                }
            | RESTORE DATABASE FROM SCONST opt_backup_opts
                {
                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    if (sql_parse_restore_from_bison(stmt, $4, @4.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }

                    if (og_parse_restore(stmt, param, $5) != OG_SUCCESS) {
                        parser_yyerror("parse restore failed");
                    }
                    $$ = param;
                }
            | RESTORE BLOCKRECOVER DATAFILE ICONST PAGE ICONST FROM SCONST
                {
                    if (!IS_CTRST_INSTANCE) {
                        parser_yyerror("BLOCKRECOVER is not supported in non-CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    if (sql_parse_restore_blockrecover_bison(stmt, $4, $6, param) != OG_SUCCESS) {
                        parser_yyerror("parse restore blockrecover failed");
                    }

                    if (sql_parse_restore_from_bison(stmt, $8, @8.loc, param, OG_TRUE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    $$ = param;
                }
            | RESTORE BLOCKRECOVER DATAFILE ICONST PAGE ICONST FROM SCONST UNTIL LFN BigintOnly
                {
                    if (!IS_CTRST_INSTANCE) {
                        parser_yyerror("BLOCKRECOVER is not supported in non-CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    if (sql_parse_restore_blockrecover_bison(stmt, $4, $6, param) != OG_SUCCESS) {
                        parser_yyerror("parse restore blockrecover failed");
                    }

                    if (sql_parse_restore_from_bison(stmt, $8, @8.loc, param, OG_TRUE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    param->lfn = $11;
                    $$ = param;
                }
            | RESTORE FILERECOVER FILENAME SCONST FROM SCONST 
                {
                    if (IS_CTRST_INSTANCE) {
                        parser_yyerror("filerecover is not supported in CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->file_type = RESTORE_DATAFILE;
                    text_t file_name;
                    cm_str2text($4, &file_name);
                    if (sql_copy_file_name(stmt->context, &file_name, &param->file_repair_name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed");
                    }
                    param->file_repair = OG_INVALID_FILEID;

                    if (sql_parse_restore_from_bison(stmt, $6, @6.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    param->buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;
                    $$ = param;
                }
            | RESTORE FILERECOVER FILEID ICONST FROM SCONST backup_opt
                {
                    if (IS_CTRST_INSTANCE) {
                        parser_yyerror("filerecover is not supported in CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_DATAFILE;
                    if ($4 >= INVALID_FILE_ID) {
                        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "fileid value should be in [%u, %u]", (uint32)0,
                            (uint32)(INVALID_FILE_ID - 1));
                        YYABORT;
                    }
                    param->file_repair = $4;

                    if (sql_parse_restore_from_bison(stmt, $6, @6.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    if ($7->type != BACKUP_BUFFER_OPT) {
                        parser_yyerror("buffer expected but unknown restore option");
                    }
                    if (og_parse_backup_buffer(stmt, &param->buffer_size, $7) != OG_SUCCESS) {
                        YYABORT;
                    }
                    $$ = param;
                }
            | RESTORE FILERECOVER FILEID ICONST FROM SCONST 
                {
                    if (IS_CTRST_INSTANCE) {
                        parser_yyerror("filerecover is not supported in CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->file_type = RESTORE_DATAFILE;
                    if ($4 >= INVALID_FILE_ID) {
                        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "fileid value should be in [%u, %u]", (uint32)0,
                            (uint32)(INVALID_FILE_ID - 1));
                        YYABORT;
                    }
                    param->file_repair = $4;

                    if (sql_parse_restore_from_bison(stmt, $6, @6.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    param->buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;
                    $$ = param;
                }
            | RESTORE FILERECOVER FILENAME SCONST FROM SCONST backup_opt
                {
                    if (IS_CTRST_INSTANCE) {
                        parser_yyerror("filerecover is not supported in CTRST instance");
                    }

                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_DATAFILE;
                    text_t file_name;
                    cm_str2text($4, &file_name);
                    if (sql_copy_file_name(stmt->context, &file_name, &param->file_repair_name) != OG_SUCCESS) {
                        parser_yyerror("copy file name failed");
                    }
                    param->file_repair = OG_INVALID_FILEID;

                    if (sql_parse_restore_from_bison(stmt, $6, @6.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    if ($7->type != BACKUP_BUFFER_OPT) {
                        parser_yyerror("buffer expected but unknown restore option");
                    }
                    if (og_parse_backup_buffer(stmt, &param->buffer_size, $7) != OG_SUCCESS) {
                        YYABORT;
                    }
                    $$ = param;
                }
            | RESTORE ARCHIVELOG FROM SCONST
                {
                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_ARCHFILE;

                    if (sql_parse_restore_from_bison(stmt, $4, @4.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    param->buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;
                    $$ = param;
                }
            | RESTORE ARCHIVELOG FROM SCONST backup_opt
                {
                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_ARCHFILE;

                    if (sql_parse_restore_from_bison(stmt, $4, @4.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    if ($5->type != BACKUP_BUFFER_OPT) {
                        parser_yyerror("buffer expected but unknown restore option");
                    }
                    if (og_parse_backup_buffer(stmt, &param->buffer_size, $5) != OG_SUCCESS) {
                        YYABORT;
                    }
                    $$ = param;
                }
            | RESTORE FLUSHPAGE FROM SCONST opt_backup_opts
                {
                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_FLUSHPAGE;

                    if (sql_parse_restore_from_bison(stmt, $4, @4.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    if (og_parse_restore(stmt, param, $5) != OG_SUCCESS) {
                        parser_yyerror("parse restore failed");
                    }
                    $$ = param;
                }
            | RESTORE COPYCTRL TO SCONST opt_backup_opts
                {
                    knl_restore_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RESTORE;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    
                    param->file_type = RESTORE_COPYCTRL;

                    if (sql_parse_restore_from_bison(stmt, $4, @4.loc, param, OG_FALSE) != OG_SUCCESS) {
                        parser_yyerror("parse restore from failed");
                    }
                    if (og_parse_restore(stmt, param, $5) != OG_SUCCESS) {
                        parser_yyerror("parse restore failed");
                    }
                    $$ = param;
                }
        ;

RecoverStmt:
            RECOVER DATABASE
                {
                    knl_recover_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RECOVER;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_recover_t), 0, sizeof(knl_recover_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->time.tv_sec = (long)OG_INVALID_INT64;
                    param->time.tv_usec = 0;
                    param->action = RECOVER_NORMAL;
                    $$ = param;
                }
            | RECOVER DATABASE UNTIL TIME SCONST
                {
                    knl_recover_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t fmt_text;
                    date_t date;

                    stmt->context->type = OGSQL_TYPE_RECOVER;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_recover_t), 0, sizeof(knl_recover_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->time.tv_sec = (long)OG_INVALID_INT64;
                    param->time.tv_usec = 0;

                    sql_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
                    text_t until_time;
                    cm_str2text($5, &until_time);
                    if (cm_text2date(&until_time, &fmt_text, &date) != OG_SUCCESS) {
                        parser_yyerror("invalid date format");
                    }

                    cm_date2timeval(date, &param->time);
                    param->action = RECOVER_UNTIL_TIME;
                    $$ = param;
                }
            | RECOVER DATABASE UNTIL SCN BigintOnly
                {
                    knl_recover_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RECOVER;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_recover_t), 0, sizeof(knl_recover_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->time.tv_sec = (long)OG_INVALID_INT64;
                    param->time.tv_usec = 0;
                    param->scn = $5;
                    param->action = RECOVER_UNTIL_SCN;
                    $$ = param;
                }
            | RECOVER DATABASE UNTIL CANCEL
                {
                    knl_recover_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_RECOVER;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_recover_t), 0, sizeof(knl_recover_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }
                    param->time.tv_sec = (long)OG_INVALID_INT64;
                    param->time.tv_usec = 0;
                    param->action = RECOVER_UNTIL_CANCEL;
                    $$ = param;
                }
        ;

OgracStmt:
            OGRAC RECOVER ICONST START ICONST COUNT ICONST
                {
                    knl_ograc_recover_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_OGRAC;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_ograc_recover_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_ograc_recover_t), 0, sizeof(knl_ograc_recover_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->full = $3;
                    if (param->full > 1) {
                        parser_yyerror("recover mode should be 1(if recover) or 0(if analysis)");
                    }

                    param->start = $5;
                    if (param->start >= OG_MAX_INSTANCES) {
                        parser_yyerror("start node id should be in [0, OG_MAX_INSTANCES - 1]");
                    }

                    param->count = $7;
                    if (param->count > OG_MAX_INSTANCES) {
                        parser_yyerror("node count should be less or equal than OG_MAX_INSTANCES");
                    }

                    $$ = param;
                }
        ;

ShutdownStmt:
            SHUTDOWN
                {
                    shutdown_context_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SHUTDOWN;

                    if (sql_alloc_mem(stmt->context, sizeof(shutdown_context_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(shutdown_context_t), 0, sizeof(shutdown_context_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->mode = SHUTDOWN_MODE_NORMAL;

                    $$ = param;
                }
            | SHUTDOWN IMMEDIATE
                {
                    shutdown_context_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SHUTDOWN;

                    if (sql_alloc_mem(stmt->context, sizeof(shutdown_context_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(shutdown_context_t), 0, sizeof(shutdown_context_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->mode = SHUTDOWN_MODE_IMMEDIATE;

                    $$ = param;
                }
            | SHUTDOWN ABORT_P
                {
                    shutdown_context_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SHUTDOWN;

                    if (sql_alloc_mem(stmt->context, sizeof(shutdown_context_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(shutdown_context_t), 0, sizeof(shutdown_context_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->mode = SHUTDOWN_MODE_ABORT;

                    $$ = param;
                }
        ;

BuildStmt:
            BUILD DATABASE opt_backup_opts
                {
                    knl_build_def_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BUILD;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_build_def_t), 0, sizeof(knl_build_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->build_type = BUILD_AUTO;

                    if (og_parse_build(stmt, param, $3) != OG_SUCCESS) {
                        parser_yyerror("parse build database failed");
                    }

                    $$ = param;
                }
            | BUILD CASCADED STANDBY DATABASE opt_backup_opts
                {
                    knl_build_def_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BUILD;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_build_def_t), 0, sizeof(knl_build_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->build_type = BUILD_CASCADED_STANDBY;

                    if (og_parse_build(stmt, param, $5) != OG_SUCCESS) {
                        parser_yyerror("parse build database failed");
                    }

                    $$ = param;
                }
            | BUILD STANDBY DATABASE opt_backup_opts
                {
                    knl_build_def_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BUILD;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_build_def_t), 0, sizeof(knl_build_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->build_type = BUILD_STANDBY;

                    if (og_parse_build(stmt, param, $4) != OG_SUCCESS) {
                        parser_yyerror("parse build database failed");
                    }

                    $$ = param;
                }
            | BUILD REPAIR DATABASE opt_backup_opts
                {
                    knl_build_def_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_BUILD;

                    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_build_def_t), 0, sizeof(knl_build_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->build_type = BUILD_AUTO;
                    param->param_ctrl.is_repair = OG_TRUE;

                    if (og_parse_build(stmt, param, $4) != OG_SUCCESS) {
                        parser_yyerror("parse build database failed");
                    }

                    $$ = param;
                }
        ;

RepairStmt:
            REPAIR_PAGE
                {
                    og_yyget_extra(yyscanner)->core_yy_extra.stmt->context->type = OGSQL_TYPE_REPAIR_PAGE;
                    $$ = NULL;
                }
            | REPAIR_COPYCTRL
                {
                    og_yyget_extra(yyscanner)->core_yy_extra.stmt->context->type = OGSQL_TYPE_REPAIR_COPYCTRL;
                    $$ = NULL;
                }
        ;

CheckPointStmt:
            CHECKPOINT
                {
                    parser_yyerror("not support checkpoint");
                    og_yyget_extra(yyscanner)->core_yy_extra.stmt->context->type = OGSQL_TYPE_CHECKPOINT;
                    $$ = NULL;
                }
        ;

ValidateStmt:
            VALIDATE DATAFILE ICONST PAGE ICONST
                {
                    knl_validate_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_VALIDATE;

                    if ($3 >= INVALID_FILE_ID) {
                        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile value should be in [%u, %u]", (uint32)0,
                            (uint32)(INVALID_FILE_ID - 1));
                        YYABORT;
                    }

                    if ($5 == 0) {
                        parser_yyerror("page value should not be 0");
                    }

                    if (sql_alloc_mem(stmt->context, sizeof(knl_validate_t), (void **)&param) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(param, sizeof(knl_validate_t), 0, sizeof(knl_validate_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    param->validate_type = VALIDATE_DATAFILE_PAGE;
                    param->page_id.file = $3;
                    param->page_id.page = $5;

                    $$ = param;
                }
            | VALIDATE BACKUPSET ICONST
                {
                    knl_validate_t *param = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_VALIDATE;
                    OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "validate backupset not supported");
                    YYABORT;
                    $$ = param;
                }
        ;

SyncPointStmt:
            SYNCPOINT RESET
                {
#ifdef DB_DEBUG_VERSION
                    syncpoint_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SYNCPOINT;

                    if (sql_alloc_mem(stmt->context, sizeof(syncpoint_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(def, sizeof(syncpoint_def_t), 0, sizeof(syncpoint_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    $$ = def;
#else
                    parser_yyerror("syncpoint not supported");
                    $$ = NULL;
                    YYABORT;
#endif
                }
            | SYNCPOINT IDENT
                {
#ifdef DB_DEBUG_VERSION
                    syncpoint_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_SYNCPOINT;

                    if (sql_alloc_mem(stmt->context, sizeof(syncpoint_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    if (memset_s(def, sizeof(syncpoint_def_t), 0, sizeof(syncpoint_def_t)) != EOK) {
                        parser_yyerror("memset failed");
                    }

                    text_t syncpoint_name;
                    cm_str2text($2, &syncpoint_name);
                    if (sql_copy_object_name(stmt->context, WORD_TYPE_VARIANT, &syncpoint_name,
                        &def->syncpoint_name) != OG_SUCCESS) {
                        parser_yyerror("copy name failed");
                    }

                    $$ = def;
#else
                    parser_yyerror("syncpoint not supported");
                    $$ = NULL;
                    YYABORT;
#endif
                }
        ;

LockTableStmt:
            LOCK_P TABLE_P any_name_list opt_lock_table_in lock_mode MODE opt_wait_time
                {
                    lock_tables_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

                    stmt->context->type = OGSQL_TYPE_LOCK_TABLE;

                    if (sql_alloc_mem(stmt->context, sizeof(lock_tables_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    cm_galist_init(&def->tables, stmt->context, sql_alloc_mem);

                    if (sql_parse_table_defs_bison(stmt, def, $3) != OG_SUCCESS) {
                        parser_yyerror("parse create lock table failed");
                    }
                    def->lock_mode = $5;
                    def->wait_time = $7;
                    if (def->wait_time == 0) {
                        def->wait_mode = WAIT_MODE_NO_WAIT;
                    } else {
                        def->wait_mode = WAIT_MODE_WAIT;
                    }
                    $$ = def;
                }
        ;

opt_lock_table_in:
            IN_P
            | /* EMPTY */
        ;

lock_mode:
            SHARE
                {
                    $$ = LOCK_MODE_SHARE;
                }
            | EXCLUSIVE
                {
                    $$ = LOCK_MODE_EXCLUSIVE;
                }
        ;

any_name_list:
            any_name
                {
                    lock_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(lock_table_t), (void **)&table) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    table->name = $1->name;
                    table->schema = $1->owner;
                    
                    galist_t *list = NULL;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create list failed");
                    }
                    if (cm_galist_insert(list, table) != OG_SUCCESS) {
                        parser_yyerror("insert any_name opt failed");
                    }
                    $$ = list;
                }
            | any_name_list ',' any_name
                {
                    lock_table_t *table = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(lock_table_t), (void **)&table) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    table->name = $3->name;
                    table->schema = $3->owner;

                    if (cm_galist_insert($1, table) != OG_SUCCESS) {
                        parser_yyerror("insert any_name opt failed");
                    }
                    $$ = $1;
                }
        ;

opt_wait_time:
            NOWAIT
                {
                    $$ = 0;
                }
            | WAIT ICONST
                {
                    if ($2 < 0) {
                        OG_SRC_THROW_ERROR_EX(@2.loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid WAIT interval");
                        YYABORT;
                    }
                    $$ = $2;
                }
            | /*EMPTY*/
                {
                    $$ = OG_INVALID_ID32;
                }
        ;

debug_mode_value:
            IDENT
                {
                    $$ = $1;
                }
            | SCONST
                {
                    $$ = $1;
                }
        ;

altsession_set_key:
            IDENT
                {
                    $$ = $1;
                }
            | CURRENT_SCHEMA
                {
                    $$ = "current_schema";
                }
            | TENANT
                {
                    $$ = "tenant";
                }
        ;

altsession_set_value:
            alter_param_value
                {
                    $$ = $1;
                }
        ;

alter_param_value:
            ColLabel
                {
                    $$ = $1;
                }
            | SCONST
                {
                    $$ = $1;
                }
            | FCONST
                {
                    $$ = $1;
                }
            | FCONST_F
                {
                    $$ = $1;
                }
            | FCONST_D
                {
                    $$ = $1;
                }
            | SignedIconst
                {
                    char tmp_buf[OG_MAX_INT64_STRLEN + 1] = { 0 };
                    if (snprintf_s(tmp_buf, sizeof(tmp_buf), OG_MAX_INT64_STRLEN, PRINT_FMT_BIGINT, $1) < 0) {
                        parser_yyerror("format alter parameter value failed");
                    }
                    char *tmp = NULL;
                    BISON_MEM_STRDUP(tmp, tmp_buf);
                    $$ = tmp;
                }
        ;

unreserved_keyword:
              ABORT_P
            | ABSENT
            | ABSOLUTE_P
            | ACCESS
            | ACCOUNT
            | ACTION
            | ADD_P
            | ADMIN
            | AFTER
            | AGGREGATE
            | ALGORITHM
            | ALSO
            | ALWAYS
            | APP
            | APPEND
            | APPENDONLY
            | APPLY
            | ARCHIVE_P
            | ARCHIVE_SET
            | ARCHIVELOG
            | ASF
            | ASN
            | ASOF_P
            | ASSERTION
            | ASSIGNMENT
            | AT
            | ATTRIBUTE
            | AUDIT
            | AUTOEXTEND
            | AUTOMAPPED
            | AUTOOFFLINE
            | AUTOPURGE
            | AUTO_INCREMENT
            | AUTOALLOCATE
            | BACKUP_P
            | BACKUPSET
            | BACKWARD
            | BADBLOCK
            | BARRIER
            | BEFORE
            | BEGIN_P
            | BEGIN_NON_ANOYBLOCK
            | BLANKS
            | BLOB_P
            | BLOCKCHAIN
            | BLOCKRECOVER
            | BOLCKSIZE
            | BODY_P
            | BUFFER_P
            | BUILD
            | BY
            | BYTE_P
            | CACHE
            | CALL
            | CALLED
            | CANCEL
            | CANCELABLE
            | CASCADE
            | CASCADED
            | CATALOG_P
            | CATALOG_NAME
            | CHAIN
            | CHANGE
            | CHARACTERISTICS
            | CHARACTERSET
            | CHARSET
            | CHECKPOINT
            | CLASS
            | CLASS_ORIGIN
            | CLEAN
            | CLIENT
            | CLIENT_MASTER_KEY
            | CLIENT_MASTER_KEYS
            | CLOB
            | CLOSE
            | CLUSTER_P
            | CLUSTERED
            | COLUMN_ENCRYPTION_KEY
            | COLUMN_ENCRYPTION_KEYS
            | COLUMN_NAME
            | COLUMNS
            | COMMENT
            | COMMENTS
            | COMMIT
            | COMMITTED
            | COMPATIBLE_ILLEGAL_CHARS
            | COMPLETE
            | COMPILE
            | COMPLETION
            | COMPRESS
            | COMPRESSED
            | COMPUTE
            | CONDITION
            | CONDITIONAL
            | CONFIGURATION
            | CONFIG
            | CONNECT
            | CONNECTION
            | CONSISTENT
            | COUNT
            | CONSTANT
            | CONSTRAINT_CATALOG
            | CONSTRAINT_NAME
            | CONSTRAINT_SCHEMA
            | CONSTRAINTS
            | CONSTRUCTOR
            | CONTENT_P
            | CONTENTS
            | CONTINUE_P
            | CONTROLFILE
            | CONTVIEW
            | CONVERSION_P
            | COORDINATOR
            | COORDINATORS
            | COPY
            | COPYCTRL
            | COST
            | CSV
            | CTRLFILE
            | CUBE
            | CUMULATIVE
            | CURRENT_P
            | CURRENT_DATE
            | CURRENT_TIMESTAMP
            | CURSOR
            | CURSOR_NAME
            | CYCLE
            | DATA_P
            | DATABASE
            | DATAFILE
            | DATAFILES
            | DATANODE
            | DATANODES
            | DATATYPE_CL
            | DATE_FORMAT_P
            | DAY_HOUR_P
            | DAY_MINUTE_P
            | DAY_P
            | DAY_SECOND_P
            | DBA_RECYCLEBIN
            | DEBUG
            | DBCOMPATIBILITY_P
            | DEALLOCATE
            | DECLARE
            | DEFAULTS
            | DEFERRED
            | DEFINER
            | DELIMITED
            | DELIMITER
            | DELIMITERS
            | DELTA
            | DENSE_RANK
            | DETERMINISTIC
            | DIAGNOSTICS
            | DICTIONARY
            | DIRECT
            | DIRECT_LOAD
            | DIRECTORY
            | DISABLE_P
            | DISCARD
            | DISCONNECT
            | DISTRIBUTE
            | DISTRIBUTION
            | DOCUMENT_P
            | DOMAIN_P
            | DOUBLE_P
            | DROP
            | DUMP
            | DUMPFILE
            | DUPLICATE
            | EACH
            | ELASTIC
            | EMPTY
            | ENABLE_P
            | ENCLOSED
            | ENCODING
            | ENCRYPTED       
            | ENCRYPTED_VALUE
            | ENCRYPTION
            | ENCRYPTION_TYPE
            | ENDS
            | ENTRY
            | ENFORCED
            | ENUM_P
            | EOL
            | ERROR_P
            | ERRORS
            | ESCAPE
            | ESCAPED
            | ESCAPING
            | ESTIMATE
            | EXEMPT
            | EVENT
            | EVENTS
            | EVERY
            | EXCHANGE
            | EXCLUDE
            | EXCLUDING
            | EXCLUSIVE
            | EXECUTE
            | EXPIRE
            | EXPIRED_P
            | EXPLAIN
            | EXTENSION
            | EXTENT
            | EXTENTS
            | EXTERNAL
            | FAILED_LOGIN_ATTEMPTS_P
            | FAMILY
            | FAST
            | FEATURES             // DB4AI
            | FENCED
            | FIELDS
            | FILEHEADER_P
            | FILEID
            | FILENAME
            | FILERECOVER
            | FILLER
            | FILL_MISSING_FIELDS
            | FILTER
            | FINAL
            | FINISH
            | FIRST_P
            | FIXED_P
            | FLASHBACK
            | FLUSH
            | FLUSHPAGE
            | FOLLOWING
            | FOLLOWS_P
            | FORCE
            | FORMAT
            | FORMATTER
            | FORWARD
            | FUNCTION
            | FUNCTIONS
            | GENERATED
            | GET
            | GLOBAL
            | GRANTED
            | HANDLER
            | HASH
            | HEADER_P
            | HOLD
            | HOUR_MINUTE_P
            | HOUR_P
            | HOUR_SECOND_P
            | IDENTIFIED
            | IDENTITY_P
            | IGNORE_EXTRA_DATA
            | IMMEDIATE
            | IMMUTABLE
            | IMPLICIT_P
            | INCLUDE
            | INCLUDING
            | INCREMENT
            | INCREMENTAL
            | INDEXES
            | INDEXCLUSTER
            | INFILE
            | INFINITE_P
            | INHERIT
            | INHERITS
            | INITIAL_P
            | INITRANS
            | INLINE_P
            | INPUT_P
            | INSENSITIVE
            | INSTANCE
            | INSTEAD
            | INTERNAL
            | INTERACTIVE
            | INVISIBLE
            | INVOKER
            | IP
            | ISNULL
            | ISOLATION
            | JSON_TABLE_P
            | JSONB
            | JSONB_TABLE_P
            | KEEP
            | KEY
            | KEY_PATH
            | KEY_STORE
            | KILL
            | LABEL
            | LANGUAGE
            | LARGE_P
            | LAST_P
            | LATERAL_P
            | LC_COLLATE_P
            | LC_CTYPE_P
            | LEAKPROOF
            | LINES
            | LINK
            | LIST
            | LISTEN
            | LOAD
            | LOADER_P
            | LOB
            | LSNR_ADDR
            | LOCAL
            | LOCALTIMESTAMP
            | LOCATION
            | LOCK_P
            | LOCKED
            | LOG_P
            | LOGFILE
            | LOGGING
            | SWITCH
            | LOGIN_ANY
            | LOGIN_FAILURE
            | LOGIN_SUCCESS
            | LOGOUT
            | LZ4
            | LOOP
            | MAP
            | MAPPING
            | MASKING
            | MASTER
            | MATCH
            | MATCHED
            | MATERIALIZED
            | MAXEXTENTS
            | MAXINSTANCES
            | MAXSIZE
            | MAXTRANS
            | MAXVALUE
            | MEMBER
            | MEMORY
            | MERGE
            | MESSAGE_TEXT
            | METHOD
            | MINEXTENTS
            | MINUTE_P
            | MINUTE_SECOND_P
            | MINVALUE
            | MODE
            | MODEL      // DB4AI
            | MONTH_P
            | MOVE
            | MOVEMENT
            | MYSQL_ERRNO
            | NAME_P
            | NAMES
            | NAN_P
            | NEWLINE
            | NEXT
            | NO
            | NOARCHIVELOG
            | NOCACHE
            | NOCOMPRESS
            | NODE
            | NOLOGGING
            | NOMAXVALUE
            | NOMINVALUE
            | NOORDER
            | NORELY
            | NOTHING
            | NOTIFY
            | NOVALIDATE
            | NOWAIT
            | NULLCOLS
            | NULLS_P
            | NUMSTR
            | OBJECT_P
            | OF_P
            | OFF
            | OGRAC
            | OFFLINE
            | OIDS
            | OPERATIONS
            | OPERATOR
            | OPTIMIZATION
            | OPTINFO_LOG
            | OPTION
            | OPTIONALLY
            | OPTIONS
            | OVER
            | ORDINALITY
            | ORGANIZATION
            | OUTFILE
            | OWNED
            | OWNER
            | PACKAGE
            | PACKAGES
            | PAGE
            | PARALLEL
            | PARALLELISM
            | PARALLEL_ENABLE
            | PARAMETERS
            | PARSER
            | PARTIAL
            | PARTITION
            | PARTITIONS
            | PASSING
            | PASSWORD
            | PASSWORD_GRACE_TIME_P
            | PASSWORD_LIFE_TIME_P
            | PASSWORD_LOCK_TIME_P
            | PASSWORD_MIN_LEN_P
            | PASSWORD_REUSE_MAX_P
            | PASSWORD_REUSE_TIME_P
            | PATH
            | PCTFREE
            | PBL
            | PER_P
            | PERCENT
            | PERM
            | PERMANENT
            | PIPELINED
            | PIVOT
            | PLAN
            | PLANS
            | POLICY
            | POOL
            | PRECEDES_P
            | PRECEDING
            | PREDICT   // DB4AI
            | PREFERRED
            | PREFIX
            | PREPARE
            | PREPARED
            | PRESERVE
            | PRIORER
            | PRIVATE
            | PRIVILEGE
            | PRIVILEGES
            | PROCEDURAL
            | PROCESS
            | PROFILE
            | PUBLIC
            | PUBLICATION
            | PUBLISH
            | PUNCH
            | PURGE
            | QUERY
            | QUOTE
            | RANDOMIZED
            | RANGE
            | RATIO
            | RAW                  {    $$ = "raw";}
            | READ
            | REASSIGN
            | REBUILD
            | RECHECK
            | RECORDS
            | RECOVER
            | RECURSIVE
            | RECYCLE
            | REDISANYVALUE
            | REF
            | REFRESH
            | RELOAD
            | REGEXP
            | REGEXP_LIKE %prec UMINUS
            | REINDEX
            | RELATIVE_P
            | RELEASE
            | RELOPTIONS
            | RELY
            | REMOTE_P
            | REMOVE
            | RENAME
            | REPAIR
            | REPAIR_COPYCTRL
            | REPAIR_PAGE
            | REPEAT
            | REPEATABLE
            | REPLACE
            | REPLICA
            | REPLICATION_P
            | REPORT
            | RESET
            | RESIZE
            | RESOURCE
            | RESPECT_P
            | RESTART
            | RESTRICT
            | RESULT
            | RESTORE
            | RETURN
            | RETURNED_SQLSTATE
            | RETURNS
            | REUSE
            | REVERSE
            | REVOKE
            | ROLE
            | ROLES
            | ROLLBACK
            | ROLLUP
            | ROTATE
            | ROTATION
            | ROW_COUNT
            | ROWS
            | ROWTYPE_P
            | RULE
            | SAMPLE
            | SAVEPOINT
            | SCHEDULE
            | SCHEMA
            | SCHEMA_NAME
            | SCN
            | SCROLL
            | SEARCH
            | SECOND_P
            | SECTION
            | SECURITY
            | SEGMENTS
            | SELF
            | SEPARATOR_P
            | SEQUENCE
            | SEQUENCES
            | SERIALIZABLE
            | SERVER_P
            | SESSION
            | SESSIONS_PER_USER_P
            | SET
            | SETS
            | SHARE
            | SHIPPABLE
            | SHOW
            | SCOPE
            | SHUTDOWN
            | SIBLINGS
            | SIGNED
            | SIMPLE
            | SIZE
            | SKIP
            | SLAVE
            | SLICE
            | SMALLDATETIME_FORMAT_P
            | SQLPOOL
            | SNAPSHOT
            | SOURCE_P
            | SPACE_P
            | SPECIFICATION
            | SPILL
            | SPLIT
            | SQL_P
            | SQL_CALC_FOUND_ROWS
            | STABLE
            | STACKED_P
            | STANDBY
            | STANDALONE_P
            | START
            | STARTING
            | STARTS
            | STATEMENT
            | STATEMENT_ID
            | STATIC_P
            | STATISTICS
            | STDIN
            | STDOUT
            | STOP
            | STORAGE
            | STORE_P
            | STORED
            | STRATIFY
            | STREAM
            | STRICT_P
            | STRIP_P
            | SUBCLASS_ORIGIN
            | SUBPARTITION
            | SUBPARTITIONS
            | SUBSCRIPTION
            | SYNCPOINT
            | SYNONYM
            | SYSID
            | SYS_REFCURSOR                    { $$ = "refcursor"; }
            | SYSAUX
            | SYSTEM_P
            | TABLE_NAME
            | TABLES
            | TABLESPACE
            | TABLESPACES
            | TAG
            | TARGET
            | TEMP
            | TEMPFILE
            | TEMPLATE
            | TEMPORARY
            | TENANT
            | TERMINATED
            | TEXT_P
            | THAN
            | THRESHOLD
            | TIES
            | TIMESTAMP_FORMAT_P
            | TIMEZONE_HOUR_P
            | TIMEZONE_MINUTE_P
            | TIME_FORMAT_P
            | TRANSACTION
            | TRANSFORM
            | TRIGGER
            | TRIGGERS
            | TRUNCATE
            | TRUSTED
            | TSFIELD
            | TSTAG
            | TSTIME 
            | TYPE_P
            | TYPES_P
            | UNBOUNDED
            | UNCOMMITTED
            | UNCONDITIONAL
            | UNDER
            | UNDO
            | UNENCRYPTED
            | UNKNOWN
            | UNLIMITED
            | UNLISTEN
            | UNLOCK
            | UNLOGGED
            | UNPIVOT
            | UNSIGNED
            | UNTIL
            | UNUSABLE
            | USE_P
            | USEEOF
            | VACUUM
            | VALID
            | VALIDATE
            | VALIDATION
            | VALIDATOR
            | VALUE_P
            | VARIABLES
            | VARRAY
            | VARYING
            | VCGROUP
            | VERSION_P
            | VISIBLE
            | VOLATILE
            | WAIT
            | WARNINGS
            | WEAK
            | WHILE_P
            | WHITESPACE_P
            | WITHIN
            | WITHOUT
            | WORK
            | WORKLOAD
            | WRAPPER
            | WRITE
            | XML_P
            | YEAR_MONTH_P
            | YEAR_P
            | YES_P
            | ZLIB
            | ZSTD
            | ZONE
            | BETWEEN
            | BINARY_DOUBLE_INF
            | BINARY_DOUBLE_NAN
            | BIT
            | BUCKETCNT
            | BYTEAWITHOUTORDER
            | BYTEAWITHOUTORDERWITHEQUAL
            | COALESCE
            | DATE_P
            | DEC
            | DECODE
            | GREATEST
            | GROUPING_P
            | INOUT_P
            | INTERVAL
            | LEAST
            | NATIONAL
            | NONE
            | NTH_VALUE_P
            | NULLIF
            | NVL
            | OVERLAY
            | POSITION
            | PRECISION
            | ROW
            | SETOF
            | SMALLDATETIME
            | TIME
            | TIMESTAMPDIFF
            | TIMEOUT
            | TREAT
            | XMLATTRIBUTES
            | XMLCONCAT
            | XMLELEMENT
            | XMLEXISTS
            | XMLFOREST
            | XMLPARSE
            | XMLPI
            | XMLROOT
            | XMLSERIALIZE
            | AUTHORIZATION
            | BINARY
            | COLLATION
            | COMPACT
            | CONCURRENTLY
            | CROSS
            | CSF
            | CSN
            | CURRENT_SCHEMA
            | DELTAMERGE
            | FREEZE
            | FULL
            | HDFSDIRECTORY
            | IGNORE
            | ILIKE
            | INNER_P
            | JOIN
            | LEFT
            | LFN
            | LIKE
            | NATURAL
            | NOTNULL
            | OUTER_P
            | OVERLAPS
            | RECYCLEBIN
            | RIGHT
            | SIMILAR
            | TABLESAMPLE
            | TIMECAPSULE
            | VERBOSE
        ;

col_name_keyword:
            BIGINT
            | BINARY_BIGINT
            | BINARY_DOUBLE
            | BINARY_FLOAT
            | BINARY_INTEGER
            | BOOLEAN_P
            | BPCHAR
            | CAST
            | CHARACTER
            | CONVERT_P
            | FLOAT_P
            | IF_P
            | INT_P
            | JSON
            | JSON_ARRAY
            | JSON_EXISTS
            | JSON_MERGEPATCH
            | JSON_OBJECT
            | JSON_QUERY
            | JSON_SET
            | JSON_VALUE
            | JSONB_EXISTS
            | JSONB_MERGEPATCH
            | JSONB_QUERY
            | JSONB_SET
            | JSONB_VALUE
            | NCHAR
            | NUMERIC
            | NVARCHAR
            | NVARCHAR2
            | REAL
            | SUBSTR
            | SUBSTRING
            | TIMESTAMP
            | TINYINT
            | TRIM
            | LNNVL
            | GROUP_CONCAT
            | EXTRACT
            | PRIMARY       %prec UMINUS
            | UNIQUE
            | FOREIGN
            | OUT_P
        ;


/* Reserved keyword --- these keywords are usable only as a ColLabel.
 *
 * Keywords appear here if they could not be distinguished from variable,
 * type, or function names in some contexts.  Don't put things here unless
 * forced to.
 */
reserved_keyword:
              ALL
            | ANALYSE
            | ANALYZE
            | ALTER
            | AND
            | ANY
            | ARRAY
            | AS
            | ASC
            | ASYMMETRIC
            | AUTHID
            | BOTH
            | BUCKETS
            | CASE
            | CHECK
            | COLLATE
            | COLUMN
            | CONSTRAINT
            | CREATE
            | CRMODE
            | CURRENT_CATALOG
            | CURRENT_ROLE
            | CURRENT_TIME
            | CURRENT_USER
            | DB_P
            | DEFAULT
            | DEFERRABLE
            | DELETE_P
            | DESC
            | DISTINCT
            | DO
            | ELSE
            | END_P
            | EXCEPT
            | EXCLUDED
            | FALSE_P
            | FETCH
            | FOR
            | FROM
            | GRANT
            | GROUP_P
            | GROUPPARENT
            | HAVING
            | HBA
            | IMCSTORED
            | IN_P
            | INDEX_P
            | INIT
            | INITIALLY
            | INSERT
            | INTERSECT_P
            | INTO
            | IS
            | LEADING
            | LESS
            | LEVEL
            | LIMIT
            | LOCALTIME
            | MINUS_P
            | MODIFY_P
            | NOCYCLE
            | NOT
            | NULL_P
            | OFFSET
            | ON
            | ONLINE
            | ONLY
            | OR
            | ORDER
            | PERFORMANCE
            | PLACING
            | PROCEDURE
            | REFERENCES
            | REJECT_P
            | RETURNING
            | ROWID
            | ROWNUM
            | ROWSCN
            | SHAREDPOOL
            | SHARE_MEMORY
            | SELECT
            | SESSION_USER
            | SHRINK
            | SOME
            | SYMMETRIC
            | SYSBACKUP_P
            | SYSDBA_P
            | SYSOPER_P
            | SYSDATE
            | TABLE_P
            | THEN
            | TO
            | TRAILING
            | TRUE_P
            | UNIMCSTORED
            | UNION
            | USER
            | USING
            | VARIADIC
            | VERIFY
            | WHEN
            | WHERE
            | WINDOW
            | WITH
            | VALUES
            | DECIMAL_P
            | EXISTS
            | VARCHAR
            | VARCHAR2
            | INTEGER
            | NUMBER_P
            | CHAR_P
            | PRIOR
            | UPDATE
            | VIEW
            | LIBRARY
        ;

/* Please note that the following line will be replaced with the contents of given file name even if with starting with a comment */
/*$$include "gram-dialect-rule.y"*/

%%

static void
base_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner, const char *msg)
{
    scanner_yyerror(msg, yyscanner);
}

/*$$exclude in dialect begin*/

/* parser_init()
 * Initialize to parse one query string
 */
void
parser_init(base_yy_extra_type *yyext)
{
    yyext->parsetree = NULL;        /* in case grammar forgets to set it */
    //yyext->core_yy_extra.query_string_locationlist = NIL;
    yyext->core_yy_extra.paren_depth = 0;
}

/*$$exclude in dialect end*/

static status_t column_list_to_column_pairs(sql_stmt_t *stmt, galist_t *colname_list, galist_t **pairs)
{
    OG_RETURN_IFERR(sql_create_list(stmt, pairs));

    column_value_pair_t *pair = NULL;
    column_parse_info *column = NULL;
    for (uint32 i = 0; i < colname_list->count; i++) {
        column = (column_parse_info*)cm_galist_get(colname_list, i);
        OG_RETURN_IFERR(cm_galist_new(*pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
        pair->column_name.value = column->col_name;
    }
    return OG_SUCCESS;
}

static status_t make_type_word(core_yyscan_t yyscanner, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc)
{
    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,
        sizeof(type_word_t), (void **)type) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*type)->str = str;
    (*type)->typemode = typemode;
    (*type)->loc = loc;
    return OG_SUCCESS;
}

static status_t make_type_modifiers(core_yyscan_t yyscanner, galist_t **list, int val, source_location_t loc)
{
    expr_tree_t *expr = NULL;
    if (sql_create_int_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
        &expr, val, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_create_list(og_yyget_extra(yyscanner)->core_yy_extra.stmt, list) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_galist_insert(*list, expr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool check_in_rows_match(galist_t *rows, uint32 cols, expr_tree_t **expr)
{
    expr_tree_t *head = (expr_tree_t*)cm_galist_get(rows, 0);
    expr_tree_t *tail = NULL;

    /* return true if (a, b) in ((select 1)) */
    if (rows->count == 1 && head->next == NULL && head->root->type == EXPR_NODE_SELECT) {
        *expr = head;
        return true;
    }

    for (uint32 i = 0; i < rows->count; i++) {
        expr_tree_t *curr = (expr_tree_t*)cm_galist_get(rows, i);
        expr_tree_t *tmp = curr;
        uint32 count = 1;

        /* check each row if matched left side of in/not in */
        while (tmp->next != NULL) {
            count++;
            tmp = tmp->next;
        }
        if (count != cols) {
            return false;
        }

        if (tail == NULL) {
            tail = tmp;
        } else {
            tail->next = curr;
        }
    }

    *expr = head;
    return true;
}

static void fix_type_for_select_node(expr_tree_t *expr, select_type_t type)
{
    while (expr != NULL) {
        if (expr->root->type == EXPR_NODE_SELECT) {
            ((sql_select_t*)expr->root->value.v_obj.ptr)->type = type;
        }
        expr = expr->next;
    }
}

static status_t convert_expr_tree_to_galist(sql_stmt_t *stmt, expr_tree_t *expr, galist_t **list)
{
    if (sql_create_list(stmt, list) != OG_SUCCESS) {
        return OG_ERROR;
    }
    expr_tree_t *tmp = expr;
    while (tmp != NULL) {
        cm_galist_insert(*list, tmp);
        tmp = expr->next;
        expr->next = NULL;
        expr = tmp;
    }
    return OG_SUCCESS;
}

static status_t attach_pending_subselects_to_query(sql_query_t *query, sql_array_t *pending)
{
    if (pending->count == 0) {
        return OG_SUCCESS;
    }

    /*
     * The bison parser reduces subselect expressions before the owning query is
     * built.  Attach them here so correlated subqueries can resolve parent
     * table aliases during verification.
     */
    for (uint32 i = 0; i < pending->count; i++) {
        sql_select_t *subselect = (sql_select_t *)sql_array_get(pending, i);
        if (subselect->parent == NULL) {
            subselect->parent = query;
        }
    }

    OG_RETURN_IFERR(sql_array_concat(&query->ssa, pending));
    sql_array_reset(pending);
    return OG_SUCCESS;
}

static status_t sql_parse_table_cast_type(sql_stmt_t *stmt, expr_tree_t **expr, char *name, source_location_t loc)
{
    expr_tree_t *arg = NULL;
    if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)expr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    arg = *expr;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg->root) != OG_SUCCESS) {
        return OG_ERROR;
    }
    arg->root->value.type = OG_TYPE_TYPMODE;
    arg->root->type = EXPR_NODE_CONST;
    arg->loc = loc;
    arg->root->exec_default = OG_TRUE;
    arg->root->word.func.name.value.str = name;
    arg->root->word.func.name.value.len = strlen(name);
    return OG_SUCCESS;
}

static inline int32 compare_int64_text(const char *str1, uint32 len1, const char *str2, uint32 len2)
{
    const text_t text1 = { (char *)str1, len1 };
    const text_t text2 = { (char *)str2, len2 };
    return cm_compare_text(&text1, &text2);
}

static status_t strGetInt64(const char *str, int64 *value)
{
    size_t len = strlen(str) - 1;

    OG_RETVALUE_IFTRUE((len > OG_MAX_INT64_PREC), OG_ERROR);

    if (len == OG_MAX_INT64_PREC) {
        int32 cmp_ret = compare_int64_text(str, len, g_pos_bigint_ceil.str, g_pos_bigint_ceil.len);
        if (cmp_ret > 0) {
            return OG_ERROR;
        } else if (cmp_ret == 0) {
            *value = OG_MAX_INT64;
            return OG_SUCCESS;
        }
    }

    *value = 0;
    for (uint32 i = 0; i < len; ++i) {
        *value = (*value) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(str[i]);
    }
    return OG_SUCCESS;
}

static interval_unit_t get_interval_unit(interval_unit_order_t order)
{
    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };
    if (order < (sizeof(itvl_uints) / sizeof(interval_unit_t))) {
        return itvl_uints[order];
    } else {
        return IU_NONE;
    }
}

static char* ds_unit_to_str(interval_unit_order_t order)
{
    switch (order) {
        case IUO_DAY:
            return "DAY";
        case IUO_HOUR:
            return "HOUR";
        case IUO_MINUTE:
            return "MINUTE";
        default:
            return "UNKNOWN";
    }
}

static interval_unit_t generate_interval_unit(interval_unit_order_t from, interval_unit_order_t to)
{
    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };
    const uint32 itvl_uints_size = sizeof(itvl_uints) / sizeof(interval_unit_t);
    if (from >= itvl_uints_size || to >= itvl_uints_size) {
        return IU_NONE;
    }

    interval_unit_t itvl_fmt = IU_NONE;
    for (uint32 i = from + 1; i <= to; ++i) {
        itvl_fmt |= itvl_uints[i];
    }
    return itvl_fmt;
}

static text_t *pl_prepend_body_start(core_yyscan_t yyscanner, text_t *body, int start_offset, source_location_t loc)
{
    sql_text_t *body_src = (sql_text_t *)body;
    char *start = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + start_offset;
    char *end = body_src->value.str + body_src->value.len;

    body_src->value.str = start;
    body_src->value.len = (uint32)(end - start);
    body_src->loc = loc;
    return (text_t *)body_src;
}

static status_t pl_compile_stored_body_source(core_yyscan_t yyscanner, text_t *body, int start_offset,
    source_location_t loc, bool32 has_program_body)
{
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    text_t program_body;
    text_t *program_body_ptr = NULL;
    text_t *stored_body = NULL;

    if (stmt->pl_context == NULL) {
        return OG_ERROR;
    }

    if (has_program_body) {
        program_body = *body;
        program_body_ptr = &program_body;
    }
    stored_body = pl_prepend_body_start(yyscanner, body, start_offset, loc);
    return pl_bison_compile_stored_body_source(stmt, program_body_ptr, stored_body);
}

static status_t process_alter_index_action(sql_stmt_t *stmt, alter_index_action_t *alter_idx_act, knl_alindex_def_t *def)
 	{
	    def->type = alter_idx_act->type;

        switch (alter_idx_act->type) {
            case ALINDEX_TYPE_UNUSABLE:
            case ALINDEX_TYPE_COALESCE:
                break;

            case ALINDEX_TYPE_INITRANS:
                if (alter_idx_act->idx_def.initrans <= 0 || alter_idx_act->idx_def.initrans > OG_MAX_TRANS) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d", "initrans", OG_MAX_TRANS);
                    return OG_ERROR;
                }
                def->idx_def.initrans = alter_idx_act->idx_def.initrans;
                break;

            case ALINDEX_TYPE_RENAME:
                if (alter_idx_act->user.str != NULL && cm_compare_text(&alter_idx_act->user, &def->user) != 0) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s expected", T2S(&def->user));
                    return OG_ERROR;
                }
                def->idx_def.new_name = alter_idx_act->idx_def.new_name;
                break;

            case ALINDEX_TYPE_REBUILD:
                break;

            case ALINDEX_TYPE_REBUILD_PART:
                def->rebuild.specified_parts = 1;
                def->rebuild.part_name[0] = alter_idx_act->rebuild.part_name[0];
                break;

            case ALINDEX_TYPE_REBUILD_SUBPART:
                def->rebuild.specified_parts = 1;
                def->rebuild.part_name[0] = alter_idx_act->rebuild.part_name[0];
                break;

            case ALINDEX_TYPE_MODIFY_PART:
                def->mod_idxpart.part_name = alter_idx_act->mod_idxpart.part_name;
            
                if (alter_idx_act->mod_idxpart.initrans == (uint32)(-1)) {
                    def->mod_idxpart.type = MODIFY_IDXPART_COALESCE;
                } else if (alter_idx_act->mod_idxpart.initrans > 0) {
                    if (alter_idx_act->mod_idxpart.initrans > OG_MAX_TRANS) {
                        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "initrans must between 1 and %d", OG_MAX_TRANS);
                        return OG_ERROR;
                    }
                    def->mod_idxpart.type = MODIFY_IDXPART_INITRANS;
                    def->mod_idxpart.initrans = alter_idx_act->mod_idxpart.initrans;
                } else {
                    def->mod_idxpart.type = MODIFY_IDXPART_UNUSABLE;
                }
                break;

            case ALINDEX_TYPE_MODIFY_SUBPART:
                def->mod_idxpart.part_name = alter_idx_act->mod_idxpart.part_name;
            
                if (alter_idx_act->mod_idxpart.initrans == (uint32)(-1)) {
                    def->mod_idxpart.type = MODIFY_IDXSUBPART_COALESCE;
                } else {
                    def->mod_idxpart.type = MODIFY_IDXSUBPART_UNUSABLE;
                }
                break;

            default:
                return OG_ERROR;
        }
        return OG_SUCCESS;
 	}

/*
 * Must undefine this stuff before including scan.c, since it has different
 * definitions for these macros.
 */
#undef yyerror
#undef yylval
#undef yylloc
#undef yylex

#define SCANINC

/* Please note that the following line will be replaced with the contents of given file name even if with starting with a comment */
/*$$include "gram-dialect-epilogue.y.c"*/

#ifdef SCANINC
#include "scan.inc"
#endif
