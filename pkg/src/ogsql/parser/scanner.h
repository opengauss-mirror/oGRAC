/* -------------------------------------------------------------------------
 *
 * scanner.h
 *		API for the core scanner (flex machine)
 *
 * The core scanner is also used by PL/pgsql, so we provide a public API
 * for it.	However, the rest of the backend is only expected to use the
 * higher-level API provided by parser.h.
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * pkg/src/ogsql/parser/scanner.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "ogsql_stmt.h"
#include "keywords.h"
#include "ogsql_cond.h"

/*
 * The scanner returns extra data about scanned tokens in this union type.
 * Note that this is a subset of the fields used in YYSTYPE of the bison
 * parsers built atop the scanner.
 */
typedef union core_YYSTYPE {
    int ival;            /* for integer literals */
    char* str;           /* for identifiers and non-integer literals */
    const char* keyword; /* canonical spelling of keywords */
} core_YYSTYPE;

typedef struct st_lex_locataion {
    source_location_t loc;
    int offset;
} lex_location_t;

/*
 * We track token locations in terms of byte offsets from the start of the
 * source string, not the column number/line number representation that
 * bison uses by default.  Also, to minimize overhead we track only one
 * location (usually the first token location) for each construct, not
 * the beginning and ending locations as bison does by default.  It's
 * therefore sufficient to make YYLTYPE an int.
 */
#define YYLTYPE lex_location_t

#define DELIMITER_LENGTH 16

/*
 * Another important component of the scanner's API is the token code numbers.
 * However, those are not defined in this file, because bison insists on
 * defining them for itself.  The token codes used by the core scanner are
 * the ASCII characters plus these:
 *	%token <str>	IDENT FCONST SCONST BCONST XCONST Op
 *	%token <ival>	ICONST PARAM
 *	%token			TYPECAST DOT_DOT COLON_EQUALS PARA_EQUALS
 * The above token definitions *must* be the first ones declared in any
 * bison parser built atop this scanner, so that they will have consistent
 * numbers assigned to them (specifically, IDENT = 258 and so on).
 */

/*
 * The YY_EXTRA data that a flex scanner allows us to pass around.
 * Private state needed by the core scanner goes here.	Note that the actual
 * yy_extra struct may be larger and have this as its first component, thus
 * allowing the calling parser to keep some fields of its own in YY_EXTRA.
 */
typedef struct core_yy_extra_type {
    /*
     * The string the scanner is physically scanning.  We keep this mainly so
     * that we can cheaply compute the offset of the current token (yytext).
     */
    char* scanbuf;
    size_t scanbuflen;

    sql_array_t ssa; /* for sub-selects */
    sql_stmt_t *stmt;
    object_stack_t withas_stack;
    char *origin_str;

    /*
     * The keyword list to use.
     */
    const ScanKeywordList *keywordlist;
    const uint16 *keyword_tokens;

    /*
     * literalbuf is used to accumulate literal values when multiple rules are
     * needed to parse a single literal.  Call startlit() to reset buffer to
     * empty, addlit() to add text.  NOTE: the string in literalbuf is NOT
     * necessarily null-terminated, but there always IS room to add a trailing
     * null at offset literallen.  We store a null only when we need it.
     */
    char* literalbuf; /* palloc'd expandable buffer */
    int literallen;   /* actual current string length */
    int literalalloc; /* current allocated buffer size */

    int xcdepth;     /* depth of nesting in slash-star comments */
    char* dolqstart; /* current $foo$ quote start string */

    /* first part of UTF16 surrogate pair for Unicode escapes */
    int32 utf16_first_part;

    /* state variables for literal-lexing warnings */
    bool8 warn_on_first_escape;
    bool8 saw_non_ascii;
    bool8 ident_quoted;
    bool8 warnOnTruncateIdent;

    /* record the message need by multi-query. */
    bool8 in_slash_proc_body;         /* check whether it's in a slash proc body */
    int paren_depth;                 /* record the current depth in  the '(' and ')' */
    bool8 is_createstmt;              /* check whether it's a create statement. */
    bool8 is_hint_str;                /* current identifier is in hint comment string */
    bool8 include_ora_comment;        /* dont igore comment when ture */
    int func_param_begin;            /* function and procedure param string start pos,exclude left parenthesis */
    int func_param_end;              /* function and procedure param string end pos,exclude right parenthesis */
    int return_pos_end;
    bool8 isPlpgsqlKeyWord;
    bool8 is_delimiter_name;
    bool8 is_last_colon;
    bool8 is_proc_end;
    bool8 multi_line_sql;
} core_yy_extra_type;

typedef struct column_parse_info {
    text_t owner;
    text_t table;
    text_t col_name;
} column_parse_info;

typedef struct swcb_clause {
    cond_tree_t *start_with_cond;
    cond_tree_t *connect_by_cond;
    bool32 connect_by_nocycle;
} swcb_clause;

typedef struct for_update_clause {
    galist_t *for_update_cols;
    rowmark_t for_update_params;
} for_update_clause;

typedef struct merge_when_clause {
    sql_insert_t *insert_ctx;
    cond_tree_t *insert_filter_cond;
    sql_update_t *update_ctx;
    cond_tree_t *update_filter_cond;
} merge_when_clause;

typedef struct name_with_owner {
    text_t owner;
    text_t name;
} name_with_owner;

typedef enum createdb_opt_type {
    CREATEDB_USER_OPT,
    CREATEDB_CONTROLFILE_OPT,
    CREATEDB_CHARSET_OPT,
    CREATEDB_ARCHIVELOG_OPT,
    CREATEDB_DEFAULT_OPT,
    CREATEDB_NOLOGGING_UNDO_OPT,
    CREATEDB_NOLOGGING_OPT,
    CREATEDB_SYSAUX_OPT,
    CREATEDB_SYSTEM_OPT,
    CREATEDB_INSTANCE_OPT,
    CREATEDB_MAXINSTANCE_OPT,

    CREATEDB_INSTANCE_NODE_UNDO_OPT,
    CREATEDB_INSTANCE_NODE_LOGFILE_OPT,
    CREATEDB_INSTANCE_NODE_TEMPORARY_OPT,
    CREATEDB_INSTANCE_NODE_NOLOGGING_OPT
} createdb_opt_type;

typedef struct createdb_user {
    char *user_name;
    char *password;
} createdb_user;

typedef struct createdb_space {
    galist_t *datafiles;
    bool32 in_memory;
} createdb_space;

typedef struct createdb_instance_node {
    uint32 id;
    galist_t *opts;
} createdb_instance_node;

typedef struct createdb_opt {
    createdb_opt_type type;
    union {
        createdb_user user;
        galist_t *list;
        char *charset;
        archive_mode_t archivelog_enable;
        createdb_space space;
        uint32 max_instance;
    };
} createdb_opt;

/*
 * The type of yyscanner is opaque outside scan.l.
 */
typedef void* core_yyscan_t;
typedef void* yyscan_t;

/* Constant data exported from parser/scan.l */
extern const uint16 ScanKeywordTokens[];

/* Entry points in parser/scan.l */
extern core_yyscan_t scanner_init(const sql_text_t *str,
                                  core_yy_extra_type* yyext,
                                  const ScanKeywordList *keywordlist,
                                  const uint16 *keyword_tokens,
                                  sql_stmt_t *stmt);

extern void scanner_finish(core_yyscan_t yyscanner);
extern int core_yylex(core_YYSTYPE* lvalp, YYLTYPE* llocp, core_yyscan_t yyscanner);
extern int scanner_errposition(int location, core_yyscan_t yyscanner);
extern void scanner_yyerror(const char* message, core_yyscan_t yyscanner);
extern void addErrorList(const char* message, int lines);
extern int ct_yyget_leng(core_yyscan_t yyscanner);
extern void *core_yyalloc(size_t bytes, core_yyscan_t yyscanner);
extern void core_yyfree(void *ptr, core_yyscan_t yyscanner);

typedef int (*coreYYlexFunc)(core_YYSTYPE* lvalp, YYLTYPE* llocp, core_yyscan_t yyscanner);

/*
 * User option type definition for CREATE USER statement
 */
typedef enum {
    USER_OPTION_DEFAULT_TABLESPACE,
    USER_OPTION_TEMPORARY_TABLESPACE,
    USER_OPTION_PASSWORD_EXPIRE,
    USER_OPTION_ACCOUNT_LOCK,
    USER_OPTION_ACCOUNT_UNLOCK,
    USER_OPTION_PROFILE,
    USER_OPTION_PROFILE_DEFAULT,
    USER_OPTION_PERMANENT
} user_option_type_t;

/*
 * User option structure for CREATE USER statement
 */
typedef struct st_user_option {
    user_option_type_t type;
    char *value;
} user_option_t;

#endif /* SCANNER_H */

