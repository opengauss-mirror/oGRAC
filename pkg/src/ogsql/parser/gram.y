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

#define BISON_MEM_STRDUP(dest, src)                                             \
do {                                                                            \
    size_t len = strlen(src) + 1;                                               \
    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,   \
        len, (void **)&dest) != OG_SUCCESS) {                                   \
        parser_yyerror("alloc mem failed ");                                    \
    }                                                                           \
    errno_t ret = memcpy_s(dest, len, src, len - 1);                            \
    knl_securec_check(ret);                                                     \
    dest[len - 1] = '\0';                                                       \
} while (0)

#define parser_errposition(pos)  scanner_errposition(pos, yyscanner)

static digitext_t g_pos_bigint_ceil = { "9223372036854775807",  19 };

static void base_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner,
                         const char *msg);
static status_t column_list_to_column_pairs(sql_stmt_t *stmt, galist_t *colname_list, galist_t **pairs);
static status_t make_type_word(core_yyscan_t yyscanner, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc);
static status_t make_type_modifiers(core_yyscan_t yyscanner, galist_t **list, int val, source_location_t loc);
static bool check_in_rows_match(galist_t *rows, uint32 cols, expr_tree_t **expr);
static void fix_type_for_select_node(expr_tree_t *expr, select_type_t type);
static status_t convert_expr_tree_to_galist(sql_stmt_t *stmt, expr_tree_t *expr, galist_t **list);
static status_t sql_parse_table_cast_type(sql_stmt_t *stmt, expr_tree_t **expr, char *name, source_location_t loc);
static status_t strGetInt64(const char *str, int64 *value);

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
    knl_drop_tablespace_dfs_option_t drop_tbsp_opt;
    createdb_opt        *db_opt;
    knl_device_def_t    *dev_def;
    createdb_instance_node *inode;
    user_option_t       *user_opt;
}

%type <res>    stmtblock stmtmulti InsertStmt SelectStmt simple_select DeleteStmt select_with_parens select_no_parens UpdateStmt select_clause MergeStmt DropStmt merge_insert merge_when_insert_clause ReplaceStmt TruncateStmt FlashStmt CommentStmt AnalyzeStmt CreatedbStmt CreateUserStmt CreateRoleStmt CreateTenantStmt
%type <list>   ctext_expr_list ctext_row indirection opt_indirection values_clause insert_column_list when_expr_clause_list when_cond_clause_list func_name within_group_clause sort_clause opt_sort_clause sortby_list opt_partition_clause expr_list target_list opt_target_list opt_type_modifiers opt_float opt_array_bounds
%type <list>   all_insert_into_list set_clause_list set_clause multiple_set_clause return_clause delete_target_list expr_list_with_select_rows json_column_list siblings_clause with_clause cte_list pivot_in_list pivot_clause_list select_pivot_clause unpivot_in_list expr_or_implicit_row_list cube_clause rollup_clause
%type <list>   group_sets_item group_sets_list grouping_sets_clause group_by_cartesian_item group_by_list group_clause locked_rels_list columnref_list opt_siblings_clause replace_set_clause_list
%type <expr>   ctext_expr a_expr b_expr c_expr AexprConst indirection_el columnref case_default case_expr func_application func_expr func_arg_expr func_arg_list func_expr_common_subexpr substr_list multi_expr_list expr_or_implicit_row
%type <table>  insert_target qualified_name relation_expr table_func json_table
%type <case_pair> when_expr_clause when_cond_clause
%type <column> insert_column_item
%type <boolean> opt_ignore opt_varying opt_charbyte sub_type format_json json_table_on_error_or_null jsonb_table opt_found_rows opt_distinct unpivot_include_or_exclude_nulls opt_nocycle opt_all opt_all_distinct opt_if_exists opt_drop_behavior opt_cascade opt_purge opt_temporary opt_public opt_force partition_or_subpartition opt_archivelog opt_reuse opt_all_in_memory opt_encrypted
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
%type <type_word> GenericType Typename SimpleTypename Numeric NoSignedInteger Character CharacterWithLength CharacterWithoutLength ConstDatetime ConstInterval JsonType
%type <timezone_type> opt_timezone
%type <trim_list> trim_list
%type <extract_list> extract_list
%type <expr> expr_with_select expr_list_with_select expr_list_with_select_row implicit_row opt_escape expr_list_with_paren
%type <join_node> using_clause from_list table_ref joined_table from_clause
%type <join_type> join_type
%type <rs_column> json_column
%type <json_func_att_id> format_json_attr json_column_on_error
%type <withas_factor> common_table_expr
%type <expr_alias> pivot_in_item_list pivot_in_item pivot_in_list_element
%type <pivot_item> pivot_clause
%type <expr_alias_as> unpivot_in_list_element
%type <swcb> start_with_clause
%type <for_update> for_locking_clause
%type <rowmark_type> opt_nowait_or_skip
%type <merge_when> merge_when_list
%type <name_owner> any_name
%type <drop_tbsp_opt> opt_drop_tbsp
%type <db_opt> createdb_user_opt createdb_controlfile_opt createdb_charset_opt instance_node_opt createdb_instance_opt createdb_nologging_opt createdb_system_opt createdb_sysaux_opt createdb_default_opt createdb_maxinstance_opt createdb_opt createdb_archivelog_opt
%type <list> controlfiles logfiles instance_node_opts instance_nodes createdb_opts datafiles opt_user_options user_option_list tablespace_name_list
%type <ival64> num_size opt_blocksize next_size max_size
%type <dev_def> logfile datafile
%type <inode> instance_node
%type <str>  profile_name tablespace_name user_name role_name tenant_name opt_default_tablespace
%type <user_opt> user_option

%type <keyword> unreserved_keyword
%type <keyword> col_name_keyword reserved_keyword
%type <str> ColId type_function_name alias_without_as param_name all_Op qual_all_Op MathOp hint_string character character_national charset_collate_name opt_separator substr_func extract_arg alias_clause json_table_column_error ColLabel UserId database_name user_password
%type <ival>    opt_asc_desc opt_nulls_order opt_charset opt_collate opt_wait opt_truncate_options truncate_option truncate_options
%type <sortby>  sortby
%type <limit_item> opt_limit limit_clause offset_clause select_limit

%token <str>    IDENT FCONST SCONST Op CmpOp COMMENTSTRING SET_USER_IDENT SET_IDENT UNDERSCORE_CHARSET FCONST_F FCONST_D
%token <ival>   ICONST PARAM

%token            LEX_ERROR_TOKEN
%token            TYPECAST ORA_JOINOP DOT_DOT COLON_EQUALS PARA_EQUALS SET_IDENT_SESSION SET_IDENT_GLOBAL NULLS_FIRST NULLS_LAST
%token <str>      SIZE_B SIZE_KB SIZE_MB SIZE_GB SIZE_TB SIZE_PB SIZE_EB

%token <keyword> ABORT_P ABSOLUTE_P ACCESS ACCOUNT ACTION ADD_P ADMIN AFTER
    AGGREGATE ALGORITHM ALL ALSO ALTER ALWAYS ANALYSE ANALYZE AND ANY APP APPEND APPLY ARCHIVE_P ARCHIVELOG ARRAY AS ASC ASOF_P
        ASSERTION ASSIGNMENT ASYMMETRIC AT ATTRIBUTE AUDIT AUTHID AUTHORIZATION AUTOEXTEND AUTOMAPPED AUTO_INCREMENT

    BACKWARD BARRIER BEFORE BEGIN_NON_ANOYBLOCK BEGIN_P BETWEEN BIGINT BINARY BINARY_DOUBLE BINARY_DOUBLE_INF BINARY_DOUBLE_NAN BINARY_FLOAT BINARY_INTEGER BIT BLANKS
    BLOB_P BLOCKCHAIN BOLCKSIZE BODY_P BOGUS BOOLEAN_P BOTH BPCHAR BUCKETCNT BUCKETS BUILD BY BYTE_P BYTEAWITHOUTORDER BYTEAWITHOUTORDERWITHEQUAL

    CACHE CALL CALLED CANCELABLE CASCADE CASCADED CASE CAST CATALOG_P CATALOG_NAME CHAIN CHANGE CHAR_P
    CHARACTER CHARACTERISTICS CHARACTERSET CHARSET CHECK CHECKPOINT CLASS CLASS_ORIGIN CLEAN CLIENT CLIENT_MASTER_KEY CLIENT_MASTER_KEYS CLOB CLOSE
    CLUSTER_P CLUSTERED COALESCE COLLATE COLLATION COLUMN COLUMN_ENCRYPTION_KEY COLUMN_ENCRYPTION_KEYS COLUMN_NAME COLUMNS COMMENT COMMENTS COMMIT
    COMMITTED COMPACT COMPATIBLE_ILLEGAL_CHARS COMPILE COMPLETE COMPLETION COMPRESS COMPUTE CONCURRENTLY CONDITION CONFIGURATION CONNECTION CONSISTENT CONSTANT CONSTRAINT CONSTRAINT_CATALOG CONSTRAINT_NAME CONSTRAINT_SCHEMA CONSTRAINTS
    CONTENT_P CONTENTS CONTINUE_P CONTROLFILE CONTVIEW CONVERSION_P CONVERT_P CONNECT COORDINATOR COORDINATORS COPY COST CREATE
    CROSS CSN CSV CUBE CURRENT_P
    CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA
    CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR CURSOR_NAME CYCLE
    SHRINK USE_P

    DATA_P DATABASE DATAFILE DATAFILES DATANODE DATANODES DATATYPE_CL DATE_P DATE_FORMAT_P DAY_P DAY_HOUR_P DAY_MINUTE_P DAY_SECOND_P DBCOMPATIBILITY_P DEALLOCATE DEC DECIMAL_P DECLARE DECODE DEFAULT DEFAULTS
    DEFERRABLE DEFERRED DEFINER DELETE_P DELIMITER DELIMITERS DELTA DELTAMERGE DENSE_RANK DESC DETERMINISTIC
/* PGXC_BEGIN */
    DIAGNOSTICS DICTIONARY DIRECT DIRECTORY DISABLE_P DISCARD DISTINCT DISTRIBUTE DISTRIBUTION DO DOCUMENT_P DOMAIN_P DOUBLE_P
/* PGXC_END */
    DROP DUPLICATE DISCONNECT DUMPFILE

    EACH ELASTIC ELSE EMPTY ENABLE_P ENCLOSED ENCODING ENCRYPTED ENCRYPTED_VALUE ENCRYPTION ENCRYPTION_TYPE END_P ENDS ENFORCED ENUM_P ERROR_P ERRORS ESCAPE EOL ESCAPING ESTIMATE EVENT EVENTS EVERY EXCEPT EXCHANGE
    EXCLUDE EXCLUDED EXCLUDING EXCLUSIVE EXECUTE EXISTS EXPIRE EXPIRED_P EXPLAIN
    EXTENSION EXTERNAL EXTRACT ESCAPED

    FALSE_P FAMILY FAST FENCED FETCH FIELDS FILEHEADER_P FILL_MISSING_FIELDS FILLER FILTER FIRST_P FIXED_P FLASHBACK FLOAT_P FOLLOWING FOLLOWS_P FOR FORCE FOREIGN FORMAT FORMATTER FORWARD
    FEATURES // DB4AI
    FREEZE FROM FULL FUNCTION FUNCTIONS

    GENERATED GET GLOBAL GRANT GRANTED GREATEST GROUP_P GROUP_CONCAT GROUPING_P GROUPPARENT

    HANDLER HAVING HDFSDIRECTORY HEADER_P HOLD HOUR_P HOUR_MINUTE_P HOUR_SECOND_P

    IDENTIFIED IDENTITY_P IF_P IGNORE IGNORE_EXTRA_DATA ILIKE IMMEDIATE IMMUTABLE IMPLICIT_P IN_P INCLUDE IMCSTORED
    INCLUDING INCREMENT INCREMENTAL INDEX_P INDEXES INFILE INFINITE_P INHERIT INHERITS INITIAL_P INITIALLY INITRANS INLINE_P

    INNER_P INOUT_P INPUT_P INSENSITIVE INSERT INSTANCE INSTEAD INT_P INTEGER INTERNAL
    INTERSECT_P INTERVAL INTO INVISIBLE INVOKER IP IS ISNULL ISOLATION

    JOIN JSON JSON_EXISTS JSON_TABLE_P JSONB JSONB_TABLE_P

    KEEP KEY KILL KEY_PATH KEY_STORE

    LABEL LANGUAGE LARGE_P LAST_P LATERAL_P LC_COLLATE_P LC_CTYPE_P LEADING LEAKPROOF LIBRARY LINES
    LEAST LESS LEFT LEVEL LIKE LIMIT LIST LISTEN LNNVL LOAD LOCAL LOCALTIME LOCALTIMESTAMP
    LOCATION LOCK_P LOCKED LOG_P LOGFILE LOGGING LOGIN_ANY LOGIN_FAILURE LOGIN_SUCCESS LOGOUT LOOP
    MAPPING MASKING MASTER MATCH MATERIALIZED MATCHED MAXEXTENTS MAXINSTANCES MAXSIZE MAXTRANS MAXVALUE MERGE MESSAGE_TEXT METHOD MINUS_P MINUTE_P MINUTE_SECOND_P MINVALUE MINEXTENTS MODE
    MODEL MODIFY_P MONTH_P MOVE MOVEMENT MYSQL_ERRNO
    // DB4AI
    NAME_P NAMES NAN_P NATIONAL NATURAL NCHAR NEXT NO NOARCHIVELOG NOCOMPRESS NOCYCLE NODE NOLOGGING NOMAXVALUE NOMINVALUE NONE
    NOT NOTHING NOTIFY NOTNULL NOVALIDATE NOWAIT NTH_VALUE_P NULL_P NULLCOLS NULLIF NULLS_P NUMBER_P NUMERIC NUMSTR NVARCHAR NVARCHAR2 NVL

    OBJECT_P OF OFF OFFSET OIDS ON ONLY OPERATOR OPTIMIZATION OPTION OPTIONALLY OPTIONS OR
    ORDER OUT_P OUTER_P OVER OVERLAPS OVERLAY OWNED OWNER ORDINALITY OUTFILE

    PACKAGE PACKAGES PARALLEL_ENABLE PARSER PARTIAL PARTITION PARTITIONS PASSING PASSWORD PATH PCTFREE PER_P PERCENT PERFORMANCE PERM PERMANENT PLACING PLAN PLANS POLICY POSITION
    PIPELINED PIVOT
/* PGXC_BEGIN */
    POOL PRECEDING PRECISION
/* PGXC_END */
    PREDICT  // DB4AI
/* PGXC_BEGIN */
    PREFERRED PREFIX PRESERVE PREPARE PREPARED PRIMARY
/* PGXC_END */
    PRECEDES_P PRIVATE PRIOR PRIORER PRIVILEGES PRIVILEGE PROCEDURAL PROCEDURE PROFILE PUBLIC PUBLICATION PUBLISH PURGE

    QUERY QUOTE

    RANDOMIZED RANGE RATIO RAW READ REAL REASSIGN REBUILD RECHECK RECURSIVE RECYCLEBIN REDISANYVALUE REF REFERENCES REFRESH REGEXP REGEXP_LIKE REINDEX REJECT_P
    RELATIVE_P RELEASE RELOPTIONS REMOTE_P REMOVE RENAME REPEAT REPEATABLE REPLACE REPLICA REPORT
    RESET RESIZE RESOURCE RESPECT_P RESTART RESTRICT RETURN RETURNED_SQLSTATE RETURNING RETURNS REUSE REVOKE RIGHT ROLE ROLES ROLLBACK ROLLUP ROTATE
    ROTATION ROW ROW_COUNT ROWNUM ROWS ROWTYPE_P RULE

    SAMPLE SAVEPOINT SCHEDULE SCHEMA SCHEMA_NAME SCN SCROLL SEARCH SECOND_P SECURITY SELECT SEPARATOR_P SEQUENCE SEQUENCES SHARE_MEMORY
    SERIALIZABLE SERVER_P SESSION SESSION_USER SET SETS SETOF SHARE SHIPPABLE SHOW SHUTDOWN SIBLINGS SIGNED
    SIMILAR SIMPLE SIZE SKIP SLAVE SLICE SMALLDATETIME SMALLDATETIME_FORMAT_P SMALLINT SNAPSHOT SOME SOURCE_P SPACE_P SPECIFICATION SPILL SPLIT STABLE STACKED_P STANDALONE_P START STARTS STARTWITH
    STATEMENT STATEMENT_ID STATISTICS STDIN STDOUT STORAGE STORE_P STORED STRATIFY STREAM STRICT_P STRIP_P SUBCLASS_ORIGIN SUBPARTITION SUBPARTITIONS SUBSCRIPTION SUBSTR SUBSTRING
    SYMMETRIC SYNONYM SYSDATE SYSID SYSTEM_P SYS_REFCURSOR SYSAUX STARTING SQL_P

    SQL_CALC_FOUND_ROWS

    TABLE_P TABLE_NAME TABLES TABLESAMPLE TABLESPACE TABLESPACES TARGET TEMP TEMPFILE TEMPLATE TEMPORARY TENANT TERMINATED TEXT_P THAN THEN TIME TIME_FORMAT_P TIES TIMECAPSULE TIMESTAMP TIMESTAMP_FORMAT_P TIMESTAMPDIFF TIMEZONE_HOUR_P TIMEZONE_MINUTE_P TINYINT
    TO TRAILING TRANSACTION TRANSFORM TREAT TRIGGER TRIM TRUE_P
    TRUNCATE TRUSTED TSFIELD TSTAG TSTIME TYPE_P TYPES_P

    UNBOUNDED UNCOMMITTED UNENCRYPTED UNION UNIQUE UNKNOWN UNLIMITED UNLISTEN UNLOCK UNLOGGED UNPIVOT UNIMCSTORED
    UNTIL UNUSABLE UPDATE USEEOF USER USING

    VACUUM VALID VALIDATE VALIDATION VALIDATOR VALUE_P VALUES VARCHAR VARCHAR2 VARIABLES VARIADIC VARRAY VARYING VCGROUP
    VERBOSE VERIFY VERSION_P VIEW VISIBLE VOLATILE

    WAIT WARNINGS WEAK WHEN WHERE WHILE_P WHITESPACE_P WINDOW WITH WITHIN WITHOUT WORK WORKLOAD WRAPPER WRITE

    XML_P XMLATTRIBUTES XMLCONCAT XMLELEMENT XMLEXISTS XMLFOREST XMLPARSE
    XMLPI XMLROOT XMLSERIALIZE

    YEAR_P YEAR_MONTH_P YES_P

    ZONE

%token <keyword> CONSTRUCTOR FINAL MAP MEMBER MEMORY RESULT SELF STATIC_P UNDER UNDO

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
        PARTITION_FOR SUBPARTITION_FOR ORDER_SIBLINGS

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
             SEPARATOR_P
%left        Op OPERATOR        /* multi-character ops and user-defined operators */
%left        '+' '-'
%left        '*' '/' '%'
%left        '^'
/* Unary Operators */
%left        AT                /* sets precedence for AT TIME ZONE, AT LOCAL */
%left        COLLATE
%right        UMINUS
%left        '[' ']'
%left        '(' ')'
%left        TYPECAST
%left        '.'
/*
 * These might seem to be low-precedence, but actually they are not part
 * of the arithmetic hierarchy at all in their use as JOIN operators.
 * We make them high-precedence to support their use as function names.
 * They wouldn't be given a precedence at all, were it not that we need
 * left-associativity among the JOIN rules themselves.
 */
%left        JOIN CROSS LEFT FULL RIGHT INNER_P NATURAL
%nonassoc    ON RETURN SQL_CALC_FOUND_ROWS BODY_P IF_P NOLOGGING IGNORE    /* handle table_ref JOIN table_ref JOIN table_ref ON join_qual  */

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
        | /*EMPTY*/ { $$ = NULL; }
    ;

opt_into:
        INTO                            {}
        | /*EMPTY*/                     {}

opt_ignore:
        IGNORE                                  {  $$ = true; }
        | /*EMPTY*/         %prec UMINUS        {  $$ = false; }
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
                    if (cm_galist_insert(cte_list, $3) != OG_SUCCESS) {
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
                        cm_galist_insert(select_ctx->withass, factor->subquery_ctx);
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
                        cm_galist_insert(select_ctx->withass, factor->subquery_ctx);
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
                        cm_galist_insert(select_ctx->withass, factor->subquery_ctx);
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
                        cm_galist_insert(select_ctx->withass, factor->subquery_ctx);
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
            OF columnref_list                        { $$ = $2; }
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
                if (og_yyget_extra(yyscanner)->core_yy_extra.ssa.count > 0) {
                    sql_create_array(stmt->context, &select_ctx->first_query->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                    sql_array_concat(&select_ctx->first_query->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
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
        | select_with_parens %prec UMINUS
            {
                expr_tree_t *expr = NULL;
                sql_select_t *select_ctx = $1;
                if (sql_create_select_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, select_ctx,
                    &og_yyget_extra(yyscanner)->core_yy_extra.ssa, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init select expr failed");
                }
                $$ = expr;
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
                    sql_create_array(stmt->context, &delete_ctx->query->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                    sql_array_concat(&delete_ctx->query->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
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
                    sql_create_array(stmt->context, &delete_ctx->query->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                    sql_array_concat(&delete_ctx->query->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
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

/* TODO: select from table list(sql_array_t) */
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

json_table_on_error_or_null:
            ERROR_P                                 { $$ = true; }
            | NULL_P                                { $$ = false; }
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

json_column_on_error:
            EMPTY ARRAY ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_ARRAY_ON_ERROR;
            }
            | EMPTY OBJECT_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_OBJECT_ON_ERROR;
            }
            | EMPTY ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_EMPTY_ON_EMPTY;
            }
            | ERROR_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_ERROR_ON_ERROR;
            }
            | FALSE_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_FALSE_ON_ERROR;
            }
            | NULL_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_NULL_ON_ERROR;
            }
            | TRUE_P ON ERROR_P
            {
                $$ = JSON_FUNC_ATT_TRUE_ON_ERROR;
            }
            | /* EMPTY */
            {
                $$ = JSON_FUNC_ATT_INVALID;
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
            | insert_column_item CLOB json_table_column_error PATH SCONST json_column_on_error
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
            | insert_column_item JSONB json_table_column_error PATH SCONST json_column_on_error
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
            | insert_column_item VARCHAR2 json_table_column_error PATH SCONST json_column_on_error
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
            | insert_column_item VARCHAR2 '(' ICONST ')' json_table_column_error PATH SCONST json_column_on_error
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

json_table: jsonb_table '(' expr_with_select format_json ',' SCONST json_table_on_error_or_null ON ERROR_P COLUMNS '(' json_column_list ')' ')'
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

                cm_galist_copy(&table->json_table_info->columns, $12);
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

join_type:	FULL join_outer                         { $$ = JOIN_TYPE_FULL; }
            | LEFT join_outer                       { $$ = JOIN_TYPE_LEFT; }
            | RIGHT join_outer                      { $$ = KEY_WORD_RIGHT; }
        ;

join_outer: OUTER_P
            | /*EMPTY*/
        ;

joined_table:
            '(' joined_table ')'
                {
                    $$ = $2;
                }
            | table_ref CROSS JOIN table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_CROSS, NULL, NULL, $1, $4, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref join_type JOIN table_ref ON cond_tree_expr
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, $2, NULL, $6, $1, $4, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref INNER_P JOIN table_ref
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, $1, $4, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref JOIN table_ref ON cond_tree_expr
                {
                    sql_join_node_t *join_node = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, $5, $1, $3, &join_node) != OG_SUCCESS) {
                        parser_yyerror("create join node failed.");
                    }
                    $$ = join_node;
                }
            | table_ref JOIN table_ref
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
a_expr:    c_expr    { $$ = $1; }
        ;

/*
 * Restricted expressions
 *
 * b_expr is a subset of the complete expression syntax defined by a_expr.
 *
 * Presently, AND, NOT, IS, and IN are the a_expr keywords that would
 * cause trouble in the places where b_expr is used.  For simplicity, we
 * just eliminate all the boolean-keyword-operator productions from b_expr.
 */
b_expr:    c_expr { $$ = $1; }
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

qual_all_Op:
            all_Op { $$ = $1; }
        ;

all_Op:     Op          { $$ = $1; }
            | CmpOp     { $$ = $1; }
            | MathOp    { $$ = $1; }
        ;

MathOp:     '+'                 { $$ = "+"; }
            | '-'               { $$ = "-"; }
            | '*'               { $$ = "*"; }
            | '/'               { $$ = "/"; }
            | '%'               { $$ = "%"; }
            | '^'               { $$ = "^"; }
            | '<'               { $$ = "<"; }
            | '>'               { $$ = ">"; }
            | '='               { $$ = "="; }
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

columnref:  ColId
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_columnref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("init columnref expr failed");
                    }
                    $$ = expr;
                }
            | ColId indirection
                {
                    expr_tree_t *expr = NULL;
                    if (sql_create_columnref_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &expr, $1, $2, @1.loc) != OG_SUCCESS) {
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
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(int), (void **)&ival) != OG_SUCCESS) {
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
                    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt, sizeof(int), (void **)&ival) != OG_SUCCESS) {
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

character_national: NCHAR               { $$ = "nchar"; }
            | NVARCHAR                  { $$ = "nvarchar"; }
            | NVARCHAR2                 { $$ = "nvarchar2"; }
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
                | /*EMPTY*/ { $$ = 0;}
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
                    char *tmp = strdup($1);
                    cm_str_upper(tmp);
                    $$ = tmp;
                }
            | col_name_keyword
                {
                    char *tmp = strdup($1);
                    cm_str_upper(tmp);
                    $$ = tmp;
                }
        ;

/* Type/function identifier --- names that can be type or function names.
 */
type_function_name:    IDENT                        { $$ = $1; }
                       | unreserved_keyword         { $$ = strdup($1); }
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
            | SCONST
            {
                expr_tree_t *expr = NULL;
                if (sql_create_string_const_expr(og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, @1.loc) != OG_SUCCESS) {
                    parser_yyerror("init const expr failed");
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
                    sql_create_array(stmt->context, &update_context->query->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS);
                    sql_array_concat(&update_context->query->ssa, &og_yyget_extra(yyscanner)->core_yy_extra.ssa);
                    sql_array_reset(&og_yyget_extra(yyscanner)->core_yy_extra.ssa);
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
            | /* EMPTY */                       { $$ = NULL; }
        ;

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
            | DROP INDEX_P opt_if_exists any_name ON any_name
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
                    def->ex_owner = $6->owner;
                    def->ex_name = $6->name;
                    if (def->owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->owner);
                    }
                    if (def->ex_owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->ex_owner);
                    }
                    if (cm_compare_text_ins(&def->owner, &def->ex_owner) != 0) {
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
                    knl_drop_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_TABLESPACE;
                    if ($3->owner.str != NULL) {
                        parser_yyerror("incorrect tablespace name");
                    }
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    def->name = $3->name;
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
                    knl_drop_def_t *def = NULL;
                    text_t user;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    stmt->context->type = OGSQL_TYPE_DROP_USER;
                    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != OG_SUCCESS) {
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
            | ANALYZE INDEX_P any_name ON any_name COMPUTE STATISTICS
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
                    def->table_owner = $5->owner;
                    def->table_name = $5->name;
                    if (def->table_owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->table_owner);
                    }
                    $$ = def;
                }
            | ANALYZE INDEX_P any_name ON any_name ESTIMATE STATISTICS ICONST
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
                    def->table_owner = $5->owner;
                    def->table_name = $5->name;
                    if (def->table_owner.str == NULL) {
                        cm_str2text(stmt->session->curr_schema, &def->table_owner);
                    }
                    def->sample_ratio = (double)$8 / 100;
                    $$ = def;
                }
        ;

database_name:
            ColId                           { $$ = $1; }
        ;

createdb_user_opt:
            USER UserId IDENTIFIED BY SCONST
                {
                    createdb_opt *opt = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(createdb_opt), (void **)&opt) != OG_SUCCESS) {
                        parser_yyerror("alloc mem failed");
                    }
                    opt->type = CREATEDB_USER_OPT;
                    opt->user.user_name = $2;
                    opt->user.password = $5;
                    $$ = opt;
                }
        ;

controlfiles:
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
            | controlfiles ',' SCONST
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
            CONTROLFILE '(' controlfiles ')'
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

CreatedbStmt:
            CREATE DATABASE CLUSTERED database_name createdb_opts
                {
                    knl_database_def_t *db_def = NULL;
                    if (og_parse_create_database(og_yyget_extra(yyscanner)->core_yy_extra.stmt,
                        &db_def, $4, $5) != OG_SUCCESS) {
                        parser_yyerror("parse create database failed");
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

tablespace_name_list:
            tablespace_name
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t *space_name = NULL;
                    text_t raw;
                    cm_str2text($1, &raw);

                    if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                        parser_yyerror("create tablespace name list failed.");
                    }
                    if (cm_galist_new(list, sizeof(text_t), (void **)&space_name) != OG_SUCCESS) {
                        parser_yyerror("alloc space name failed");
                    }
                    if (sql_copy_name(stmt->context, (text_t *)&raw, space_name) != OG_SUCCESS) {
                        parser_yyerror("copy space name failed");
                    }
                    $$ = list;
                }
            | tablespace_name_list ',' tablespace_name
                {
                    galist_t *list = $1;
                    text_t *space_name = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    text_t raw;
                    cm_str2text($3, &raw);

                    if (sql_find_space_in_list(list, &raw)) {
                        parser_yyerror("tablespace is already exists");
                    }

                    if (cm_galist_new(list, sizeof(text_t), (void **)&space_name) != OG_SUCCESS) {
                        parser_yyerror("alloc space name failed");
                    }
                    if (sql_copy_name(stmt->context, (text_t *)&raw, space_name) != OG_SUCCESS) {
                        parser_yyerror("copy space name failed");
                    }
                    if (list->count >= OG_MAX_SPACES) {
                        parser_yyerror("exclude spaces number out of max spaces number");
                    }

                    $$ = list;
                }
        ;

opt_default_tablespace:
            /* EMPTY */                                     { $$ = NULL; }
            | DEFAULT TABLESPACE tablespace_name            { $$ = $3; }
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

profile_name:
            ColId                           { $$ = $1; }
            | DEFAULT                       { $$ = "DEFAULT"; }
        ;

tablespace_name:
            ColId                           { $$ = $1; }
        ;

unreserved_keyword:
              ABORT_P
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
            | ALTER
            | ALWAYS
            | APP
            | APPEND
            | APPLY
            | ARCHIVE_P
            | ARCHIVELOG
            | ASOF_P
            | ASSERTION
            | ASSIGNMENT
            | AT
            | ATTRIBUTE
            | AUDIT
            | AUTOEXTEND
            | AUTOMAPPED
            | AUTO_INCREMENT
            | BACKWARD
            | BARRIER
            | BEFORE
            | BEGIN_P
            | BEGIN_NON_ANOYBLOCK
            | BLANKS
            | BLOB_P
            | BLOCKCHAIN
            | BOLCKSIZE
            | BODY_P
            | BUILD
            | BY
            | BYTE_P
            | CACHE
            | CALL
            | CALLED
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
            | COMPUTE
            | CONDITION
            | CONFIGURATION
            | CONNECT
            | CONNECTION
            | CONSISTENT
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
            | COST
            | CSV
            | CUBE
            | CURRENT_P
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
            | DBCOMPATIBILITY_P
            | DEALLOCATE
            | DECLARE
            | DEFAULTS
            | DEFERRED
            | DEFINER
            | DELETE_P
            | DELIMITER
            | DELIMITERS
            | DELTA
            | DENSE_RANK
            | DETERMINISTIC
            | DIAGNOSTICS
            | DICTIONARY
            | DIRECT
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
            | ENFORCED
            | ENUM_P
            | EOL
            | ERROR_P
            | ERRORS
            | ESCAPE
            | ESCAPED
            | ESCAPING
            | ESTIMATE
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
            | EXTERNAL
            | FAMILY
            | FAST
            | FEATURES             // DB4AI
            | FENCED
            | FIELDS
            | FILEHEADER_P
            | FILLER
            | FILL_MISSING_FIELDS
            | FILTER
            | FINAL
            | FIRST_P
            | FIXED_P
            | FLASHBACK
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
            | INDEX_P
            | INDEXES
            | INFILE
            | INFINITE_P
            | INHERIT
            | INHERITS
            | INITIAL_P
            | INITRANS
            | INLINE_P
            | INPUT_P
            | INSENSITIVE
            | INSERT
            | INSTANCE
            | INSTEAD
            | INTERNAL
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
            | LIBRARY
            | LINES
            | LIST
            | LISTEN
            | LOAD
            | LOCAL
            | LOCATION
            | LOCK_P
            | LOCKED
            | LOG_P
            | LOGFILE
            | LOGGING
            | LOGIN_ANY
            | LOGIN_FAILURE
            | LOGIN_SUCCESS
            | LOGOUT
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
            | NEXT
            | NO
            | NOARCHIVELOG
            | NOCOMPRESS
            | NODE
            | NOLOGGING
            | NOMAXVALUE
            | NOMINVALUE
            | NOTHING
            | NOTIFY
            | NOVALIDATE
            | NOWAIT
            | NULLCOLS
            | NULLS_P
            | NUMSTR
            | OBJECT_P
            | OF
            | OFF
            | OIDS
            | OPERATOR
            | OPTIMIZATION
            | OPTION
            | OPTIONALLY
            | OPTIONS
            | OVER
            | ORDINALITY
            | OUTFILE
            | OWNED
            | OWNER
            | PACKAGE
            | PACKAGES
            | PARALLEL_ENABLE
            | PARSER
            | PARTIAL
            | PARTITION
            | PARTITIONS
            | PASSING
            | PASSWORD
            | PATH
            | PCTFREE
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
            | PROFILE
            | PUBLIC
            | PUBLICATION
            | PUBLISH
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
            | RECURSIVE
            | REDISANYVALUE
            | REF
            | REFRESH
            | REGEXP
            | REGEXP_LIKE %prec UMINUS
            | REINDEX
            | RELATIVE_P
            | RELEASE
            | RELOPTIONS
            | REMOTE_P
            | REMOVE
            | RENAME
            | REPEAT
            | REPEATABLE
            | REPLACE
            | REPLICA
            | REPORT
            | RESET
            | RESIZE
            | RESOURCE
            | RESPECT_P
            | RESTART
            | RESTRICT
            | RESULT
            | RETURN
            | RETURNED_SQLSTATE
            | RETURNS
            | REUSE
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
            | SECURITY
            | SELF
            | SEPARATOR_P
            | SEQUENCE
            | SEQUENCES
            | SERIALIZABLE
            | SERVER_P
            | SESSION
            | SET
            | SETS
            | SHARE
            | SHIPPABLE
            | SHOW
            | SHUTDOWN
            | SIBLINGS
            | SIGNED
            | SIMPLE
            | SIZE
            | SKIP
            | SLAVE
            | SLICE
            | SMALLDATETIME_FORMAT_P
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
            | SYNONYM
            | SYSID
            | SYS_REFCURSOR                    { $$ = "refcursor"; }
            | SYSAUX
            | SYSTEM_P
            | TABLE_NAME
            | TABLES
            | TABLESPACE
            | TABLESPACES
            | TARGET
            | TEMP
            | TEMPFILE
            | TEMPLATE
            | TEMPORARY
            | TENANT
            | TERMINATED
            | TEXT_P
            | THAN
            | TIES
            | TIMESTAMP_FORMAT_P
            | TIMEZONE_HOUR_P
            | TIMEZONE_MINUTE_P
            | TIME_FORMAT_P
            | TRANSACTION
            | TRANSFORM
            | TRIGGER
            | TRUNCATE
            | TRUSTED
            | TSFIELD
            | TSTAG
            | TSTIME 
            | TYPE_P
            | TYPES_P
            | UNBOUNDED
            | UNCOMMITTED
            | UNDER
            | UNDO
            | UNENCRYPTED
            | UNKNOWN
            | UNLIMITED
            | UNLISTEN
            | UNLOCK
            | UNLOGGED
            | UNPIVOT
            | UNTIL
            | UNUSABLE
            | UPDATE
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
            | VIEW
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
            | JSON_EXISTS
            | LEAST
            | NATIONAL
            | NONE
            | NTH_VALUE_P
            | NULLIF
            | NVL
            | OUT_P
            | OVERLAY
            | POSITION
            | PRECISION
            | ROW
            | SETOF
            | SMALLDATETIME
            | TIME
            | TIMESTAMPDIFF
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
            | NCHAR
            | NUMERIC
            | NVARCHAR
            | NVARCHAR2
            | REAL
            | SMALLINT
            | SUBSTR
            | SUBSTRING
            | TIMESTAMP
            | TINYINT
            | TRIM
            | LNNVL
            | GROUP_CONCAT
            | EXTRACT
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
            | CURRENT_CATALOG
            | CURRENT_DATE
            | CURRENT_ROLE
            | CURRENT_TIME
            | CURRENT_TIMESTAMP
            | CURRENT_USER
            | DEFAULT
            | DEFERRABLE
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
            | FOREIGN
            | FROM
            | GRANT
            | GROUP_P
            | GROUPPARENT
            | HAVING
            | IMCSTORED
            | IN_P
            | INITIALLY
            | INTERSECT_P
            | INTO
            | IS
            | LEADING
            | LESS
            | LEVEL
            | LIMIT
            | LOCALTIME
            | LOCALTIMESTAMP
            | MINUS_P
            | MODIFY_P
            | NOCYCLE
            | NOT
            | NULL_P
            | OFFSET
            | ON
            | ONLY
            | OR
            | ORDER
            | PERFORMANCE
            | PLACING
            | PRIMARY
            | PROCEDURE
            | REFERENCES
            | REJECT_P
            | RETURNING
                        | ROWNUM
            | SHARE_MEMORY
            | SELECT
            | SESSION_USER
            | SHRINK
            | SOME
            | SYMMETRIC
            | SYSDATE
            | TABLE_P
            | THEN
            | TO
            | TRAILING
            | TRUE_P
            | UNIMCSTORED
            | UNION
            | UNIQUE
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
        ;

%%

static void
base_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner, const char *msg)
{
    scanner_yyerror(msg, yyscanner);
}

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

/*
 * Must undefine this stuff before including scan.c, since it has different
 * definitions for these macros.
 */
#undef yyerror
#undef yylval
#undef yylloc
#undef yylex

#define SCANINC

#ifdef SCANINC
#include "scan.inc"
#endif
