%{

#include "pl_compiler.h"
#include "ast_cl.h"
#include "typedef_cl.h"
#include "base_compiler.h"
#include "call_cl.h"
#include "cursor_cl.h"
#include "decl_cl.h"
#include "lines_cl.h"
#include "pl_udt.h"
#include "pl_common.h"
#include "pl_gram.h"
#include "gramparse.h"
#include "cond_parser.h"
#include "dml_cl.h"
#include "dml_parser.h"
#include "func_parser.h"
#include "pl_dc.h"
#include "ogsql_dependency.h"
#include "ogsql_privilege.h"
#include "pragma_cl.h"
#include "trigger_decl_cl.h"

/* Location tracking support --- simpler than bison's default */

#define YYLLOC_DEFAULT(Current, Rhs, N) \
    do { \
        if (N) \
            (Current) = (Rhs)[1]; \
        else \
            (Current) = (Rhs)[0]; \
    } while (0)

#define YYMALLOC(size) core_yyalloc(size, yyscanner)
#define YYFREE(ptr)   core_yyfree(ptr, yyscanner)

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, &yylloc, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, &yylloc, yyscanner)
#endif

#define parser_yyerror(msg)             \
do {                                    \
    plsql_yyerror(NULL, yyscanner, msg); \
    YYABORT;                            \
} while (0)

typedef struct st_pl_bison_exception_choice {
    pl_exception_t except;
    sql_text_t name;
} pl_bison_exception_choice_t;

typedef struct st_pl_bison_cursor_arg {
    const char *name;
    type_word_t *type;
    expr_tree_t *def_expr;
    source_location_t loc;
} pl_bison_cursor_arg_t;

typedef enum en_pl_bison_fragment_type {
    PL_BISON_FRAGMENT_EXPR_LIST,
    PL_BISON_FRAGMENT_EXPR_TREE,
    PL_BISON_FRAGMENT_COND_TREE
} pl_bison_fragment_type_t;

extern int plsql_yylex(union YYSTYPE *lvalp, YYLTYPE *llocp, core_yyscan_t yyscanner);
extern void plsql_push_back_token(int token, core_yyscan_t yyscanner);
extern union YYSTYPE *plsql_last_yylval(core_yyscan_t yyscanner);
extern YYLTYPE *plsql_last_yylloc(core_yyscan_t yyscanner);
extern int plsql_last_yyleng(core_yyscan_t yyscanner);
static void plsql_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner, const char* message);

#define PLSQL_YYLVAL(yyscanner) plsql_last_yylval(yyscanner)
#define PLSQL_YYLLOC(yyscanner) plsql_last_yylloc(yyscanner)
#define PLSQL_YYLENG(yyscanner) plsql_last_yyleng(yyscanner)
#define PLSQL_YYLEX(yyscanner) yylex(PLSQL_YYLVAL(yyscanner), PLSQL_YYLLOC(yyscanner), yyscanner)
static bool32 pl_bison_assign_left_starts_with_colon(core_yyscan_t yyscanner, int start_offset);
static status_t compile_assign_left_from_offsets(core_yyscan_t yyscanner, int start_offset, int end_offset,
    expr_node_t **left);
static status_t compile_assign_left_from_sql(sql_stmt_t *stmt, text_t *src, expr_node_t **left);
static status_t parse_expr_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line);
static status_t parse_call_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line, source_location_t loc);
static status_t read_return_sql_construct(sql_stmt_t *stmt, text_t *src, pl_line_return_t *line);
static status_t make_type_word(pl_compiler_t *compiler, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc, bool32 is_name_typemode, bool32 pl_type, bool32 pl_rowtype);
static status_t compile_dynamic_sql_expr(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr);
static status_t compile_static_sql_context(sql_stmt_t *stmt, text_t *src, key_wid_t key_wid, source_location_t loc,
    galist_t *input, pl_into_t *into, sql_context_t **context);
static status_t compile_static_sql_line(sql_stmt_t *stmt, text_t *src, key_wid_t key_wid, source_location_t loc,
    pl_line_sql_t *line);
static status_t compile_execute_immediate_stmt(core_yyscan_t yyscanner, source_location_t loc);
static status_t compile_execute_into_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler, pl_into_t *into,
    int *endtoken);
static status_t compile_execute_bulk_into_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler, pl_into_t *into,
    int *endtoken);
static status_t compile_execute_using_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler,
    pl_line_execute_t *line, int *endtoken);
static bool32 pl_bison_type_is_sys_refcursor(type_word_t *type);
static status_t init_sys_refcursor_decl(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc);
static status_t compile_sys_refcursor_decl(pl_compiler_t *compiler, char *name, source_location_t loc);
static status_t compile_cursor_decl(pl_compiler_t *compiler, char *name, galist_t *args, text_t *query,
    source_location_t loc);
static status_t compile_into_var_list(pl_compiler_t *compiler, galist_t *output, expr_node_t *node,
    source_location_t loc);
static status_t find_cursor_decl_by_node(pl_compiler_t *compiler, expr_node_t *node, source_location_t loc,
    plv_decl_t **decl);
static status_t find_top_loop(pl_compiler_t *compiler, source_location_t loc, pl_line_ctrl_t **line);
static status_t find_named_loop(pl_compiler_t *compiler, source_location_t loc, const char *name,
    pl_line_ctrl_t **line);
static status_t get_valid_expr_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr);
static status_t get_valid_cond_tree(sql_stmt_t *stmt, text_t *src, cond_tree_t **cond);
static status_t get_valid_call_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr);
static status_t pl_bison_make_parse_text(sql_stmt_t *stmt, const char *prefix, text_t *body, const char *suffix,
    sql_text_t *sql_text);
static status_t pl_bison_column_to_proc_node(sql_stmt_t *stmt, expr_node_t *proc);
static bool tok_is_keyword(int token, union YYSTYPE *lval, int kw_token, const char *kw_str);
static char *pl_token_text(int token, union YYSTYPE *lval);
static int pl_read_type_token(core_yyscan_t yyscanner, union YYSTYPE *lval, YYLTYPE *lloc, int *leng);
static char *pl_type_token_text(core_yyscan_t yyscanner, int token, union YYSTYPE *lval, YYLTYPE *lloc,
    int token_len);
static bool32 pl_token_text_equal(core_yyscan_t yyscanner, int token, union YYSTYPE *lval, YYLTYPE *lloc,
    int token_len, const char *expected);
static status_t pl_read_interval_datatype(core_yyscan_t yyscanner, sql_stmt_t *stmt, char **typename,
    galist_t **typemode, galist_t **second_typemode, int *tok);
static bool32 pl_bison_is_ident_char(char c);
static bool32 pl_bison_is_ident_text(const char *str, uint32 len);
static text_t *current_label_name(pl_compiler_t *compiler);
static status_t check_end_name(const text_t *expected, const char *actual, source_location_t loc);
static status_t check_block_end_name(pl_compiler_t *compiler, const text_t *expected,
    const pl_bison_end_name_t *actual, source_location_t loc);
static status_t check_current_loop_end_name(pl_compiler_t *compiler, const char *actual, source_location_t loc);
static status_t compile_label_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc);
static status_t compile_goto_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc);
static status_t compile_raise_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc);
static status_t compile_pragma_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc);
static status_t compile_exception_init_pragma(pl_compiler_t *compiler, const PLword *word, int32 err_code,
    source_location_t loc);
static status_t compile_exit_or_continue_stmt(sql_stmt_t *stmt, bool32 is_continue, const char *label_name,
    text_t *cond_src, source_location_t loc);
static status_t compile_case_start(sql_stmt_t *stmt, text_t *selector_src, pl_line_case_t **case_line);
static status_t compile_case_when(core_yyscan_t yyscanner, sql_stmt_t *stmt, text_t *cond_src,
    pl_line_when_case_t **when_line);
static status_t finish_case_stmt(pl_compiler_t *compiler, galist_t *when_lines, source_location_t loc);
static status_t compile_exception_start(pl_compiler_t *compiler, source_location_t loc,
    pl_line_except_t **except_line);
static status_t compile_exception_choice(pl_compiler_t *compiler, const char *name, source_location_t loc,
    void **choice);
static status_t compile_exception_when(core_yyscan_t yyscanner, sql_stmt_t *stmt, galist_t *choices,
    pl_line_when_t **when_line);
static status_t finish_exception_when(pl_compiler_t *compiler);
static status_t finish_exception_section(pl_compiler_t *compiler, source_location_t loc);
static status_t compile_cursor_arg_decl(pl_compiler_t *compiler, plv_decl_t *cursor, galist_t *decls,
    const char *name, type_word_t *type, expr_tree_t *def_expr, source_location_t loc);
static status_t compile_open_cursor_args_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node,
    source_location_t loc);
static status_t compile_open_for_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node, source_location_t loc);
static status_t compile_fetch_bulk_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node, source_location_t loc);
static char *pl_bison_identifier_at(core_yyscan_t yyscanner, int offset);
static status_t compile_for_start_stmt(core_yyscan_t yyscanner, const char *index_name, source_location_t loc,
    pl_line_for_t **for_line);
static status_t compile_forall_stmt(core_yyscan_t yyscanner, const char *index_name, text_t *lower_src,
    source_location_t loc);
static status_t create_expr_from_pl_node(sql_stmt_t *stmt, expr_node_t *node, source_location_t loc,
    expr_tree_t **expr);
static status_t try_create_pl_var_node_from_name(sql_stmt_t *stmt, const char *name, source_location_t loc,
    expr_node_t **node);
static status_t try_create_pl_var_expr_from_text(sql_stmt_t *stmt, text_t *src, source_location_t loc,
    expr_tree_t **expr);
static status_t pl_copy_cstr_name(core_yyscan_t yyscanner, const char *src, bool32 upper, char **dst);
static status_t pl_copy_ident_token_text(core_yyscan_t yyscanner, char **name);
static char *pl_bison_word_name(core_yyscan_t yyscanner, const PLword *word, int offset);
static void init_word_from_name(word_t *word, const char *name, source_location_t loc);
static status_t read_sql_expression_from_token(int token, int until, core_yyscan_t yyscanner, text_t **expr_src,
    expr_node_t **datum_node, source_location_t *datum_loc);
static text_t *read_sql_expression(int until, core_yyscan_t yyscanner);
static text_t *read_sql_expression2(int until, int until2, core_yyscan_t yyscanner, int *endtoken);
static bool32 is_sql_construct_terminator(int token, int paren_depth, int until, int until2, int until3,
    int until4, int until5, int until6);
static void update_sql_construct_depth(int token, int *paren_depth);
static status_t read_sql_construct_core(int start_offset, int token, int until, int until2, int until3, int until4,
    int until5, int until6, core_yyscan_t yyscanner, text_t **expr_src, int *endtoken, uint32 *token_count);
static text_t *read_sql_construct_from(int start_offset,
                                   int until,
                                   int until2,
                                   int until3,
                                   int until4,
                                   int until5,
                                   int until6,
                                   core_yyscan_t yyscanner,
                                   int *endtoken);
static text_t *read_sql_construct(int until,
                                   int until2,
                                   int until3,
                                   int until4,
                                   int until5,
                                   int until6,
                                   core_yyscan_t yyscanner,
                                   int *endtoken);


union YYSTYPE;					/* need forward reference for tok_is_keyword */

%}

%code requires {
typedef struct st_pl_bison_end_name {
    const char *owner;
    const char *name;
} pl_bison_end_name_t;
}

%expect 0
%name-prefix "plsql_yy"
%define api.pure
%locations

%parse-param {core_yyscan_t yyscanner}
%lex-param   {core_yyscan_t yyscanner}

%union {
    core_YYSTYPE core_yystype;
    /* Keep scalar token fields layout-compatible with core_YYSTYPE. */
    int ival;
    const char *keyword;
    PLword word;
    expr_tree_t *expr;
    expr_node_t *node;
    text_t *text;
    type_word_t *type;
    char *str;
    void *res;
    bool boolean;
    galist_t *list;
    record_attr_t *record_attr;
    pl_bison_end_name_t end_name;
}

%type <keyword>	unreserved_keyword
%type <res> loop_start while_start for_start case_start case_when_clause case_when_header cursor_arg
%type <expr> decl_defval decl_rec_defval cursor_arg_defval
%type <text> expr_until_semi expr_until_then expr_until_loop expr_until_range expr_until_when
%type <text> decl_rec_defval_expr cursor_query cursor_arg_defval_expr
%type <type> decl_datatype
%type <type> opt_collection_index
%type <str> decl_varname simple_name label_name opt_loop_end_name opt_exit_label for_index_name
%type <end_name> opt_block_end_name
%type <word> pragma_exception_name
%type <ival> pragma_error_code
%type <boolean> decl_notnull
%type <list> record_attr_list into_var_list case_when_list exception_choice_list cursor_arg_decls cursor_arg_list
%type <record_attr> record_attr

%token <str>    IDENT FCONST SCONST XCONST Op CmpOp COMMENTSTRING SET_USER_IDENT SET_IDENT UNDERSCORE_CHARSET FCONST_F FCONST_D
                OPER_CAT OPER_LSHIFT OPER_RSHIFT
%token <ival>   ICONST PARAM

%token            LEX_ERROR_TOKEN
%token            TYPECAST ORA_JOINOP DOT_DOT COLON_EQUALS PARA_EQUALS SET_IDENT_SESSION SET_IDENT_GLOBAL NULLS_FIRST NULLS_LAST
%token <str>      SIZE_B SIZE_KB SIZE_MB SIZE_GB SIZE_TB SIZE_PB SIZE_EB

%token <word>   T_WORD
%token <node> T_DATUM    /* a VAR */

%token <keyword>	K_ABSOLUTE
%token <keyword>	K_ALIAS
%token <keyword>	K_ALL
%token <keyword>	K_ALTER
%token <keyword>	K_ARRAY
%token <keyword>	K_AS
%token <keyword>	K_BACKWARD
%token <keyword>	K_BEGIN
%token <keyword>	K_BULK
%token <keyword>	K_BY
%token <keyword>        K_CALL
%token <keyword>	K_CASE
%token <keyword>	K_CATALOG_NAME
%token <keyword>	K_CLASS_ORIGIN
%token <keyword>	K_CLOSE
%token <keyword>	K_COLLATE
%token <keyword>	K_COLLECT
%token <keyword>	K_COLUMN_NAME
%token <keyword>	K_COMMIT
%token <keyword>	K_CONDITION
%token <keyword>	K_CONSTANT
%token <keyword>	K_CONSTRAINT_CATALOG
%token <keyword>	K_CONSTRAINT_NAME
%token <keyword>	K_CONSTRAINT_SCHEMA
%token <keyword>	K_CONTINUE
%token <keyword>	K_CURRENT
%token <keyword>	K_CURSOR
%token <keyword>	K_CURSOR_NAME
%token <keyword>	K_DEBUG
%token <keyword>	K_DECLARE
%token <keyword>	K_DEFAULT
%token <keyword>	K_DELETE
%token <keyword>	K_DETAIL
%token <keyword>	K_DETERMINISTIC
%token <keyword>	K_DIAGNOSTICS
%token <keyword>	K_DISTINCT
%token <keyword>        K_DO
%token <keyword>	K_DUMP
%token <keyword>	K_ELSE
%token <keyword>	K_ELSIF
%token <keyword>	K_END
%token <keyword>	K_ERRCODE
%token <keyword>	K_ERROR
%token <keyword>    K_EXCEPT
%token <keyword>	K_EXCEPTION
%token <keyword>	K_EXCEPTIONS
%token <keyword>	K_EXECUTE
%token <keyword>	K_EXIT
%token <keyword>	K_FALSE
%token <keyword>	K_FETCH
%token <keyword>	K_FIRST
%token <keyword>	K_FOR
%token <keyword>	K_FORALL
%token <keyword>	K_FOREACH
%token <keyword>	K_FORWARD
%token <keyword>	K_FOUND
%token <keyword>	K_FROM
%token <keyword>	K_FUNCTION
%token <keyword>	K_GET
%token <keyword>	K_GOTO
%token <keyword>	K_HANDLER
%token <keyword>	K_HINT
%token <keyword>	K_IF
%token <keyword>	K_IMMEDIATE
%token <keyword>    K_INSTANTIATION
%token <keyword>	K_IN
%token <keyword>	K_INDEX
%token <keyword>	K_INFO
%token <keyword>	K_INSERT
%token <keyword>	K_INTERSECT
%token <keyword>	K_INTO
%token <keyword>	K_IS
%token <keyword>        K_ITERATE
%token <keyword>	K_LAST
%token <keyword>        K_LEAVE
%token <keyword>	K_LIMIT
%token <keyword>	K_LOG
%token <keyword>	K_LOOP
%token <keyword>    K_MERGE
%token <keyword>	K_MESSAGE
%token <keyword>	K_MESSAGE_TEXT
%token <keyword>	K_MOVE
%token <keyword>    K_MULTISET
%token <keyword>    K_MULTISETS
%token <keyword>    K_MYSQL_ERRNO
%token <keyword>    K_NUMBER
%token <keyword>	K_NEXT
%token <keyword>	K_NO
%token <keyword>	K_NOT
%token <keyword>	K_NOTICE
%token <keyword>	K_NULL
%token <keyword>	K_OF
%token <keyword>	K_OPEN
%token <keyword>	K_OPTION
%token <keyword>	K_OR
%token <keyword>	K_OUT
%token <keyword>        K_PACKAGE
%token <keyword>	K_PERFORM
%token <keyword>	K_PIPE
%token <keyword>	K_PG_EXCEPTION_CONTEXT
%token <keyword>	K_PG_EXCEPTION_DETAIL
%token <keyword>	K_PG_EXCEPTION_HINT
%token <keyword>	K_PRAGMA
%token <keyword>	K_PRIOR
%token <keyword>	K_PROCEDURE
%token <keyword>	K_QUERY
%token <keyword>	K_RAISE
%token <keyword>	K_RECORD
%token <keyword>	K_REF
%token <keyword>	K_RELATIVE
%token <keyword>	K_RELEASE
%token <keyword>	K_REPEAT
%token <keyword>	K_REPLACE
%token <keyword>	K_RESULT_OID
%token <keyword>	K_RESIGNAL
%token <keyword>	K_RETURN
%token <keyword>	K_RETURNED_SQLSTATE
%token <keyword>	K_REVERSE
%token <keyword>	K_ROLLBACK
%token <keyword>	K_ROW
%token <keyword>	K_ROWTYPE
%token <keyword>	K_ROW_COUNT
%token <keyword>	K_SAVE
%token <keyword>	K_SAVEPOINT
%token <keyword>	K_SCHEMA_NAME
%token <keyword>	K_SELECT
%token <keyword>	K_SCROLL
%token <keyword>	K_SIGNAL
%token <keyword>	K_SLICE
%token <keyword>	K_SQLEXCEPTION
%token <keyword>	K_SQLSTATE
%token <keyword>	K_SQLWARNING
%token <keyword>	K_STACKED
%token <keyword>	K_STRICT
%token <keyword>	K_SUBCLASS_ORIGIN
%token <keyword>	K_SUBTYPE
%token <keyword>	K_SYS_REFCURSOR
%token <keyword>	K_TABLE
%token <keyword>	K_TABLE_NAME
%token <keyword>	K_THEN
%token <keyword>	K_TO
%token <keyword>	K_TRUE
%token <keyword>	K_TYPE
%token <keyword>	K_UNION
%token <keyword>	K_UNTIL
%token <keyword>	K_UPDATE
%token <keyword>	K_USE_COLUMN
%token <keyword>	K_USE_VARIABLE
%token <keyword>	K_USING
%token <keyword>	K_VARIABLE_CONFLICT
%token <keyword>	K_VARRAY
%token <keyword>	K_WARNING
%token <keyword>	K_WHEN
%token <keyword>	K_WHILE
%token <keyword>	K_WITH

%%

pl_body:
            pl_function
        ;

pl_function:
            pl_top_block
        ;

/*
 * Procedure/function bodies may start with declarations directly after AS/IS,
 * while nested executable blocks must start with DECLARE or BEGIN to avoid
 * treating ordinary statements as declaration prefixes.
 */
pl_top_block:
            opt_declare_keyword declare_sect_b pl_top_block_body
        ;

pl_block:
            K_DECLARE declare_sect_b pl_block_body
            | pl_block_body
        ;

pl_top_block_body:
            block_body_core opt_top_block_end_semi
        ;

pl_block_body:
            block_body_core ';'
        ;

block_body_core:
            K_BEGIN
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    pl_line_begin_t *line = NULL;
                    text_t *label_name = current_label_name(compiler);
                    text_t block_name = (label_name == NULL) ? CM_NULL_TEXT : *label_name;
                    plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&line);
                    plc_push(compiler, (pl_line_ctrl_t *)line, &block_name);
                    plc_convert_typedecl(compiler, compiler->decls);
                    line->decls = compiler->decls;
                    line->type_decls = compiler->type_decls;
                    line->name = label_name;
                    if (compiler->body == NULL) {
                        compiler->body = line;
                    }
                }
            block_body_stmts K_END opt_block_end_name
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    pl_line_ctrl_t *line = NULL;
                    pl_line_begin_t *begin_line = (pl_line_begin_t *)plc_get_current_beginln(compiler);
                    text_t *expected_name = NULL;

                    if (begin_line == NULL) {
                        parser_yyerror("current block expected");
                    } else {
                        expected_name = begin_line->name;
                        if (expected_name == NULL && compiler->stack.depth == 1 && compiler->obj != NULL) {
                            expected_name = &compiler->obj->name;
                        }
                        if (check_block_end_name(compiler, expected_name, &$5, @5.loc) != OG_SUCCESS) {
                            parser_yyerror("Undefined symbol");
                        }
                    }
                    compiler->line_loc = @4.loc;
                    plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END, (pl_line_ctrl_t **)&line);
                    if (begin_line != NULL) {
                        begin_line->end = line;
                    }
                    if (plc_pop(compiler, compiler->line_loc, PBE_END, NULL) != OG_SUCCESS) {
                        parser_yyerror("pop block failed");
                    }
                }
        ;

block_body_stmts:
            proc_sect opt_exception_sect
            | exception_sect
        ;

/*
 * The outer SQL parser may consume the statement delimiter before handing PL
 * text to this grammar.  Nested blocks keep the explicit terminator in
 * pl_block_body.
 */
opt_top_block_end_semi:
            ';'
            | /* EMPTY */
        ;

opt_declare_keyword:
            K_DECLARE
            | /* EMPTY */
        ;

opt_block_end_name:
            simple_name
                {
                    $$.owner = NULL;
                    $$.name = $1;
                }
            | simple_name '.' simple_name
                {
                    $$.owner = $1;
                    $$.name = $3;
                }
            | /* EMPTY */
                {
                    $$.owner = NULL;
                    $$.name = NULL;
                }
        ;

opt_loop_end_name:
            label_name                                  { $$ = $1; }
            | /* EMPTY */                               { $$ = NULL; }
        ;

opt_exception_sect:
            /* EMPTY */
            | exception_sect
        ;

exception_sect:
            K_EXCEPTION
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    pl_line_except_t *line = NULL;
                    if (compile_exception_start(compiler, @1.loc, &line) != OG_SUCCESS) {
                        parser_yyerror("compile exception failed");
                    }
                }
            exception_when_list
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (finish_exception_section(compiler, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("finish exception failed");
                    }
                }
        ;

exception_when_list:
            exception_when_clause
            | exception_when_list exception_when_clause
        ;

exception_when_clause:
            K_WHEN exception_choice_list K_THEN
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_line_when_t *line = NULL;
                    if (compile_exception_when(yyscanner, stmt, $2, &line) != OG_SUCCESS) {
                        parser_yyerror("compile exception when failed");
                    }
                }
            proc_sect
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (finish_exception_when(compiler) != OG_SUCCESS) {
                        parser_yyerror("finish exception when failed");
                    }
                }
        ;

exception_choice_list:
            label_name
                {
                    void *choice = NULL;
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS ||
                        compile_exception_choice(compiler, $1, @1.loc, &choice) != OG_SUCCESS ||
                        cm_galist_insert(list, choice) != OG_SUCCESS) {
                        parser_yyerror("compile exception choice failed");
                    }
                    $$ = list;
                }
            | exception_choice_list K_OR label_name
                {
                    void *choice = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_exception_choice(compiler, $3, @3.loc, &choice) != OG_SUCCESS ||
                        cm_galist_insert($1, choice) != OG_SUCCESS) {
                        parser_yyerror("compile exception choice failed");
                    }
                    $$ = $1;
                }
        ;

proc_sect:
            proc_stmts
        ;

proc_stmts:
            proc_stmt
            | proc_stmts proc_stmt
        ;

proc_stmt:
            pl_block
            | stmt_label
            | label_stmts
        ;

label_stmts:
            label_stmt
        ;

label_stmt:
            stmt_assign
            | stmt_return
            | stmt_null
            | stmt_if
            | stmt_proc_call
            | stmt_execute_immediate
            | stmt_loop
            | stmt_while
            | stmt_for
            | stmt_exit
            | stmt_continue
            | stmt_open
            | stmt_fetch
            | stmt_close
            | stmt_sql
            | stmt_commit
            | stmt_rollback
            | stmt_savepoint
            | stmt_case
            | stmt_goto
            | stmt_raise
            | stmt_forall
        ;

stmt_label:
            label_open label_name label_close
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_label_stmt(compiler, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile label failed");
                    }
                }
        ;

label_open:
            OPER_LSHIFT
            | Op
                {
                    if (strcmp($1, "<<") != 0) {
                        parser_yyerror("expected <<");
                    }
                }
        ;

label_close:
            OPER_RSHIFT
            | Op
                {
                    if (strcmp($1, ">>") != 0) {
                        parser_yyerror("expected >>");
                    }
                }
        ;

label_name:
            simple_name                                    { $$ = $1; }
        ;

stmt_null:
            K_NULL ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    pl_line_ctrl_t *line = NULL;
                    if (plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_NULL, &line) != OG_SUCCESS) {
                        parser_yyerror("compile null failed");
                    }
                }
        ;

stmt_assign:
            T_DATUM
                {
                    pl_line_normal_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    expr_node_t *left = NULL;
                    text_t *left_src = NULL;
                    text_t *expr_src = NULL;
                    bool32 is_proc_call = OG_FALSE;
                    int tok;

                    if (yychar == YYEMPTY) {
                        tok = YYLEX;
                    } else {
                        tok = yychar;
                        yychar = YYEMPTY;
                    }
                    if (tok != COLON_EQUALS) {
                        plsql_push_back_token(tok, yyscanner);
                        left_src = read_sql_construct_from(@1.offset, COLON_EQUALS, ';', 0, 0, 0, 0, yyscanner, &tok);
                        if (tok == ';') {
                            if (plc_alloc_line(compiler, sizeof(pl_line_normal_t), LINE_SETVAL,
                                (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                                parser_yyerror("compile procedure call failed");
                            }
                            if (parse_call_from_sql(stmt, left_src, line, @1.loc) != OG_SUCCESS) {
                                YYABORT;
                            }
                            if (plc_clone_expr_node(compiler, &line->proc) != OG_SUCCESS) {
                                parser_yyerror("clone procedure call failed");
                            }
                            is_proc_call = OG_TRUE;
                        } else if (tok != COLON_EQUALS) {
                            parser_yyerror("':=' expected");
                        } else if (compile_assign_left_from_sql(stmt, left_src, &left) != OG_SUCCESS) {
                            parser_yyerror("compile assignment target failed");
                        }
                    } else {
                        /*
                         * Keep yylloc here: it is the bison lookahead location for ":=".
                         * PLSQL_YYLLOC may be overwritten if the fallback path reads ahead.
                         */
                        if (pl_bison_assign_left_starts_with_colon(yyscanner, @1.offset)) {
                            left = $1;
                        } else if (compile_assign_left_from_offsets(yyscanner, @1.offset, yylloc.offset,
                            &left) != OG_SUCCESS) {
                            parser_yyerror("compile assignment target failed");
                        }
                    }
                    if (!is_proc_call) {
                        if (left == NULL) {
                            parser_yyerror("compile assignment target failed");
                        }
                        expr_src = read_sql_expression(';', yyscanner);
                        if (plc_alloc_line(compiler, sizeof(pl_line_normal_t), LINE_SETVAL,
                            (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                            parser_yyerror("compile assignment failed");
                        }
                        line->left = left;
                        if (plc_check_var_as_left(compiler, line->left, @1.loc, NULL) != OG_SUCCESS ||
                            parse_expr_from_sql(stmt, expr_src, line) != OG_SUCCESS ||
                            plc_clone_expr_node(compiler, &line->left) != OG_SUCCESS ||
                            plc_clone_expr_tree(compiler, &line->expr) != OG_SUCCESS ||
                            plc_clone_cond_tree(compiler, &line->cond) != OG_SUCCESS) {
                            parser_yyerror("compile assignment failed");
                        }
                    }
                }
        ;

stmt_return:
            K_RETURN expr_until_semi
                {
                    pl_line_return_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    plv_decl_t *decl = NULL;
                    plv_id_t ret_vid = {
                        .block = 0,
                        .id = 0,
                        .input_id = 0
                    };
                    YYLTYPE return_loc = @1;

                    if (plc_alloc_line(compiler, sizeof(pl_line_return_t), LINE_RETURN,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile return failed");
                    }
                    if ($2->len == 0) {
                        if (compiler->type == PL_FUNCTION) {
                            parser_yyerror("function return value expected");
                        }
                        line->expr = NULL;
                    } else {
                        if (compiler->type != PL_FUNCTION) {
                            plsql_yyerror(&return_loc, yyscanner, "; expected");
                            YYABORT;
                        }
                        if (read_return_sql_construct(stmt, $2, line) != OG_SUCCESS) {
                            parser_yyerror("compile return expr failed");
                        }

                        decl = plc_find_param_by_id(compiler, ret_vid);
                        if (decl == NULL) {
                            parser_yyerror("Undefined symbol");
                        }
                        if (plc_check_decl_as_left(compiler, decl, @1.loc, NULL) != OG_SUCCESS) {
                            parser_yyerror("invalid return target");
                        }
                        if (plc_verify_expr(compiler, line->expr) != OG_SUCCESS) {
                            parser_yyerror("verify expr failed");
                        }
                        if (plc_clone_expr_tree(compiler, &line->expr) != OG_SUCCESS) {
                            parser_yyerror("clone expr failed");
                        }
                        if (!sql_is_skipped_expr(line->expr)) {
                            if (plc_verify_stack_var_assign(compiler, decl, line->expr) != OG_SUCCESS) {
                                parser_yyerror("verify return assign failed");
                            }
                        }
                    }
                }
        ;

stmt_if:        stmt_if_expr stmt_elsifs stmt_else K_END K_IF ';'
                    {
                        pl_line_ctrl_t *line = NULL;
                        pl_line_ctrl_t *pop_line = NULL;
                        pl_line_if_t *if_line = NULL;
                        pl_line_elsif_t *elsif_line = NULL;
                        pl_line_else_t *else_line = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                        compiler->line_loc = @4.loc;

                        plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_IF, (pl_line_ctrl_t **)&line);
                        plc_pop(compiler, compiler->line_loc, PBE_END_IF, &pop_line);

                        if (pop_line->type == LINE_IF) {
                            if_line = (pl_line_if_t *)pop_line;
                            if_line->f_line = line;
                            if_line->next = line;
                        } else if (pop_line->type == LINE_ELIF) {
                            elsif_line = (pl_line_elsif_t *)pop_line;
                            elsif_line->f_line = line;
                            elsif_line->next = line;

                            while (elsif_line->if_line->ctrl.type != LINE_IF) {
                                elsif_line = (pl_line_elsif_t *)elsif_line->if_line;
                                elsif_line->next = line;
                            }

                            if_line = (pl_line_if_t *)elsif_line->if_line;
                            if_line->next = line;
                        } else { /* pop_line is a LINE_ELSE */
                            else_line = (pl_line_else_t*)pop_line;
                            if (else_line->if_line->ctrl.type == LINE_IF) {
                                if_line = (pl_line_if_t *)else_line->if_line;
                                if_line->next = line;
                            } else {
                                elsif_line = (pl_line_elsif_t *)else_line->if_line;
                                elsif_line->next = line;

                                while (elsif_line->if_line->ctrl.type != LINE_IF) {
                                    elsif_line = (pl_line_elsif_t *)elsif_line->if_line;
                                    elsif_line->next = line;
                                }

                                if_line = (pl_line_if_t *)elsif_line->if_line;
                                if_line->next = line;
                            }
                        }
                    }
        ;

stmt_proc_call:
            T_WORD
                {
                    pl_line_normal_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    plc_alloc_line(compiler, sizeof(pl_line_normal_t), LINE_SETVAL, (pl_line_ctrl_t **)&line);
                    if (parse_call_from_sql(stmt, src, line, @1.loc) != OG_SUCCESS) {
                        YYABORT;
                    }
                    if (plc_clone_expr_node(compiler, &line->proc) != OG_SUCCESS) {
                        parser_yyerror("clone procedure call failed");
                    }
                }
        ;

stmt_execute_immediate:
            K_EXECUTE K_IMMEDIATE
                {
                    if (compile_execute_immediate_stmt(yyscanner, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile execute immediate failed");
                    }
                }
        ;

loop_start:
            K_LOOP
                {
                    pl_line_loop_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    text_t *label_name = current_label_name(compiler);
                    text_t loop_name = (label_name == NULL) ? CM_NULL_TEXT : *label_name;

                    if (plc_alloc_line(compiler, sizeof(pl_line_loop_t), LINE_LOOP,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile loop failed");
                    }
                    if (plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &loop_name) != OG_SUCCESS) {
                        parser_yyerror("push loop failed");
                    }
                    line->stack_line = CURR_BLOCK_BEGIN(compiler);
                    $$ = line;
                }
        ;

stmt_loop:
            loop_start proc_sect K_END K_LOOP opt_loop_end_name ';'
                {
                    pl_line_loop_t *loop_line = (pl_line_loop_t *)$1;
                    pl_line_end_loop_t *end_line = NULL;
                    pl_line_ctrl_t *pop_line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    compiler->line_loc = @3.loc;
                    if (plc_alloc_line(compiler, sizeof(pl_line_end_loop_t), LINE_END_LOOP,
                        (pl_line_ctrl_t **)&end_line) != OG_SUCCESS) {
                        parser_yyerror("compile end loop failed");
                    }
                    if (check_current_loop_end_name(compiler, $5, @5.loc) != OG_SUCCESS) {
                        parser_yyerror("Undefined symbol");
                    }
                    if (plc_pop(compiler, compiler->line_loc, PBE_END_LOOP, &pop_line) != OG_SUCCESS) {
                        parser_yyerror("pop loop failed");
                    }
                    end_line->loop = pop_line;
                    loop_line->next = (pl_line_ctrl_t *)end_line;
                }
        ;

while_start:
            K_WHILE expr_until_loop
                {
                    pl_line_while_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *label_name = current_label_name(compiler);
                    text_t loop_name = (label_name == NULL) ? CM_NULL_TEXT : *label_name;

                    if (plc_alloc_line(compiler, sizeof(pl_line_while_t), LINE_WHILE,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile while failed");
                    }
                    if (get_valid_cond_tree(stmt, $2, &line->cond) != OG_SUCCESS ||
                        plc_verify_cond(compiler, line->cond) != OG_SUCCESS ||
                        plc_clone_cond_tree(compiler, &line->cond) != OG_SUCCESS) {
                        parser_yyerror("compile while condition failed");
                    }
                    if (plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &loop_name) != OG_SUCCESS) {
                        parser_yyerror("push while failed");
                    }
                    line->name = label_name;
                    line->stack_line = CURR_BLOCK_BEGIN(compiler);
                    $$ = line;
                }
        ;

stmt_while:
            while_start proc_sect K_END K_LOOP opt_loop_end_name ';'
                {
                    pl_line_while_t *while_line = (pl_line_while_t *)$1;
                    pl_line_end_loop_t *end_line = NULL;
                    pl_line_ctrl_t *pop_line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    compiler->line_loc = @3.loc;
                    if (plc_alloc_line(compiler, sizeof(pl_line_end_loop_t), LINE_END_LOOP,
                        (pl_line_ctrl_t **)&end_line) != OG_SUCCESS) {
                        parser_yyerror("compile end while failed");
                    }
                    if (check_current_loop_end_name(compiler, $5, @5.loc) != OG_SUCCESS) {
                        parser_yyerror("Undefined symbol");
                    }
                    if (plc_pop(compiler, compiler->line_loc, PBE_END_LOOP, &pop_line) != OG_SUCCESS) {
                        parser_yyerror("pop while failed");
                    }
                    end_line->loop = pop_line;
                    while_line->next = (pl_line_ctrl_t *)end_line;
                }
        ;

for_index_name:
            T_WORD
                {
                    $$ = pl_bison_word_name(yyscanner, &$1, @1.offset);
                    if ($$ == NULL) {
                        parser_yyerror("invalid for loop variable");
                    }
                }
            | T_DATUM
                {
                    $$ = pl_bison_identifier_at(yyscanner, @1.offset);
                    if ($$ == NULL) {
                        parser_yyerror("compile for loop variable failed");
                    }
                }
        ;

for_start:
            K_FOR for_index_name K_IN
                {
                    pl_line_for_t *line = NULL;
                    if (compile_for_start_stmt(yyscanner, $2, @1.loc, &line) != OG_SUCCESS) {
                        parser_yyerror("compile for loop failed");
                    }
                    $$ = line;
                }
        ;

stmt_for:
            for_start proc_sect K_END K_LOOP opt_loop_end_name ';'
                {
                    pl_line_for_t *for_line = (pl_line_for_t *)$1;
                    pl_line_end_loop_t *end_line = NULL;
                    pl_line_ctrl_t *pop_line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    compiler->line_loc = @3.loc;
                    if (plc_alloc_line(compiler, sizeof(pl_line_end_loop_t), LINE_END_LOOP,
                        (pl_line_ctrl_t **)&end_line) != OG_SUCCESS) {
                        parser_yyerror("compile end for failed");
                    }
                    if (check_current_loop_end_name(compiler, $5, @5.loc) != OG_SUCCESS) {
                        parser_yyerror("Undefined symbol");
                    }
                    if (plc_pop(compiler, compiler->line_loc, PBE_END_LOOP, &pop_line) != OG_SUCCESS) {
                        parser_yyerror("pop for loop failed");
                    }
                    end_line->loop = pop_line;
                    for_line->next = (pl_line_ctrl_t *)end_line;
                }
        ;

stmt_exit:
            K_EXIT opt_exit_label ';'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (compile_exit_or_continue_stmt(stmt, OG_FALSE, $2, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile exit failed");
                    }
                }
            | K_EXIT opt_exit_label K_WHEN expr_until_semi
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (compile_exit_or_continue_stmt(stmt, OG_FALSE, $2, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile exit when failed");
                    }
                }
        ;

stmt_continue:
            K_CONTINUE opt_exit_label ';'
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (compile_exit_or_continue_stmt(stmt, OG_TRUE, $2, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile continue failed");
                    }
                }
            | K_CONTINUE opt_exit_label K_WHEN expr_until_semi
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (compile_exit_or_continue_stmt(stmt, OG_TRUE, $2, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile continue when failed");
                    }
                }
        ;

opt_exit_label:
            label_name                                    { $$ = $1; }
            | /* EMPTY */                                 { $$ = NULL; }
        ;

stmt_open:
            K_OPEN T_DATUM ';'
                {
                    pl_line_open_t *line = NULL;
                    plv_decl_t *decl = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    if (find_cursor_decl_by_node(compiler, $2, @2.loc, &decl) != OG_SUCCESS) {
                        parser_yyerror("cursor expected");
                    }
                    if (decl->cursor.ogx->is_sysref || decl->cursor.ogx->context == NULL) {
                        parser_yyerror("explicit cursor expected");
                    }
                    if (plc_alloc_line(compiler, sizeof(pl_line_open_t), LINE_OPEN,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile open cursor failed");
                    }
                    line->vid = decl->vid;
                    line->exprs = NULL;
                }
            | K_OPEN T_DATUM '('
                {
                    if (compile_open_cursor_args_stmt(yyscanner, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile open cursor args failed");
                    }
                }
            ';'
            | K_OPEN T_DATUM K_FOR
                {
                    if (compile_open_for_stmt(yyscanner, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile open for failed");
                    }
                }
        ;

cursor_query:
                {
                    $$ = read_sql_expression(';', yyscanner);
                }
        ;

stmt_fetch:
            K_FETCH T_DATUM K_INTO into_var_list ';'
                {
                    pl_line_fetch_t *line = NULL;
                    plv_decl_t *decl = NULL;
                    expr_node_t *into_node = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    if (find_cursor_decl_by_node(compiler, $2, @2.loc, &decl) != OG_SUCCESS) {
                        parser_yyerror("cursor expected");
                    }
                    if (plc_alloc_line(compiler, sizeof(pl_line_fetch_t), LINE_FETCH,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile fetch failed");
                    }
                    line->vid = decl->vid;
                    line->into.output = $4;
                    line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
                    line->into.into_type = INTO_AS_VALUE;
                    line->into.is_bulk = OG_FALSE;
                    if (line->into.output->count == 1) {
                        into_node = (expr_node_t *)cm_galist_get(line->into.output, 0);
                        if (NODE_DATATYPE(into_node) == OG_TYPE_RECORD) {
                            line->into.into_type = INTO_AS_REC;
                        } else if (NODE_DATATYPE(into_node) == OG_TYPE_OBJECT) {
                            parser_yyerror("type mismatch found at OBJECT type between anonymous record and INTO variables");
                        }
                    }
                    if (decl->cursor.ogx->is_sysref == OG_FALSE && decl->cursor.ogx->context != NULL &&
                        plc_verify_into_clause(decl->cursor.ogx->context, &line->into, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("verify fetch into failed");
                    }
                }
            | K_FETCH T_DATUM K_BULK
                {
                    if (compile_fetch_bulk_stmt(yyscanner, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile fetch bulk collect failed");
                    }
                }
        ;

stmt_close:
            K_CLOSE T_DATUM ';'
                {
                    pl_line_close_t *line = NULL;
                    plv_decl_t *decl = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    if (find_cursor_decl_by_node(compiler, $2, @2.loc, &decl) != OG_SUCCESS) {
                        parser_yyerror("cursor expected");
                    }
                    if (plc_alloc_line(compiler, sizeof(pl_line_close_t), LINE_CLOSE,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile close failed");
                    }
                    line->vid = decl->vid;
                }
        ;

into_var_list:
            T_DATUM
                {
                    galist_t *list = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;

                    if (plc_init_galist(compiler, &list) != OG_SUCCESS ||
                        compile_into_var_list(compiler, list, $1, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile into variable failed");
                    }
                    $$ = list;
                }
            | into_var_list ',' T_DATUM
                {
                    if (compile_into_var_list(
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler,
                        $1, $3, @3.loc) != OG_SUCCESS) {
                        parser_yyerror("compile into variable failed");
                    }
                    $$ = $1;
                }
        ;

stmt_sql:
            K_SELECT
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_SELECT, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_INSERT
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_INSERT, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_UPDATE
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_UPDATE, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_DELETE
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_DELETE, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_MERGE
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_MERGE, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_REPLACE
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_REPLACE, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
            | K_WITH
                {
                    pl_line_sql_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    text_t *src = read_sql_construct_from(@1.offset, ';', 0, 0, 0, 0, 0, yyscanner, NULL);

                    if (plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS ||
                        plc_init_galist(compiler, &line->input) != OG_SUCCESS ||
                        compile_static_sql_line(stmt, src, KEY_WORD_WITH, @1.loc, line) != OG_SUCCESS) {
                        YYABORT;
                    }
                }
        ;

stmt_commit:
            K_COMMIT ';'
                {
                    pl_line_ctrl_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_COMMIT, &line) != OG_SUCCESS) {
                        parser_yyerror("compile commit failed");
                    }
                }
        ;

stmt_rollback:
            K_ROLLBACK ';'
                {
                    pl_line_rollback_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (plc_alloc_line(compiler, sizeof(pl_line_rollback_t), LINE_ROLLBACK,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile rollback failed");
                    }
                    line->savepoint = CM_NULL_TEXT;
                }
            | K_ROLLBACK K_TO T_WORD ';'
                {
                    pl_line_rollback_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    text_t name;

                    if (plc_alloc_line(compiler, sizeof(pl_line_rollback_t), LINE_ROLLBACK,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile rollback failed");
                    }
                    cm_str2text($3.ident, &name);
                    if (pl_copy_text(compiler->entity, &name, &line->savepoint) != OG_SUCCESS) {
                        parser_yyerror("copy rollback savepoint failed");
                    }
                }
            | K_ROLLBACK K_TO K_SAVEPOINT T_WORD ';'
                {
                    pl_line_rollback_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    text_t name;

                    if (plc_alloc_line(compiler, sizeof(pl_line_rollback_t), LINE_ROLLBACK,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile rollback failed");
                    }
                    cm_str2text($4.ident, &name);
                    if (pl_copy_text(compiler->entity, &name, &line->savepoint) != OG_SUCCESS) {
                        parser_yyerror("copy rollback savepoint failed");
                    }
                }
        ;

stmt_savepoint:
            K_SAVEPOINT T_WORD ';'
                {
                    pl_line_savepoint_t *line = NULL;
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    text_t name;

                    if (plc_alloc_line(compiler, sizeof(pl_line_savepoint_t), LINE_SAVEPOINT,
                        (pl_line_ctrl_t **)&line) != OG_SUCCESS) {
                        parser_yyerror("compile savepoint failed");
                    }
                    cm_str2text($2.ident, &name);
                    if (pl_copy_text(compiler->entity, &name, &line->savepoint) != OG_SUCCESS) {
                        parser_yyerror("copy savepoint failed");
                    }
                }
        ;

stmt_case:
            case_start case_when_list stmt_else K_END K_CASE ';'
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (finish_case_stmt(compiler, $2, @4.loc) != OG_SUCCESS) {
                        parser_yyerror("compile end case failed");
                    }
                }
        ;

case_start:
            K_CASE expr_until_when
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_line_case_t *line = NULL;
                    if (compile_case_start(stmt, $2, &line) != OG_SUCCESS) {
                        parser_yyerror("compile case failed");
                    }
                    $$ = line;
                }
        ;

case_when_list:
            case_when_clause
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS ||
                        cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("record case when failed");
                    }
                    $$ = list;
                }
            | case_when_list K_WHEN case_when_clause
                {
                    if (cm_galist_insert($1, $3) != OG_SUCCESS) {
                        parser_yyerror("record case when failed");
                    }
                    $$ = $1;
                }
        ;

case_when_clause:
            case_when_header proc_sect                    { $$ = $1; }
        ;

case_when_header:
            expr_until_then
                {
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_line_when_case_t *line = NULL;
                    if (compile_case_when(yyscanner, stmt, $1, &line) != OG_SUCCESS) {
                        parser_yyerror("compile case when failed");
                    }
                    $$ = line;
                }
        ;

stmt_goto:
            K_GOTO label_name ';'
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_goto_stmt(compiler, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile goto failed");
                    }
                }
        ;

stmt_raise:
            K_RAISE ';'
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_raise_stmt(compiler, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile raise failed");
                    }
                }
            | K_RAISE label_name ';'
                {
                    pl_compiler_t *compiler =
                        (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_raise_stmt(compiler, $2, @2.loc) != OG_SUCCESS) {
                        parser_yyerror("compile raise failed");
                    }
                }
        ;

stmt_forall:
            K_FORALL T_WORD K_IN expr_until_range
                {
                    if (compile_forall_stmt(yyscanner, $2.ident, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile forall failed");
                    }
                }
        ;

stmt_if_expr:
            K_IF expr_until_then
                {
                    pl_line_if_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    plc_alloc_line(compiler, sizeof(pl_line_if_t), LINE_IF, (pl_line_ctrl_t **)&line);
                    if (get_valid_cond_tree(stmt, $2, &line->cond) != OG_SUCCESS) {
                        parser_yyerror("invalid condition expr");
                    }
                    if (plc_verify_cond(compiler, line->cond) != OG_SUCCESS) {
                        parser_yyerror("verify condition expr failed");
                    }
                    plc_clone_cond_tree(compiler, &line->cond);
                    plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT);
                    line->t_line = NULL;
                }
            proc_sect
        ;

stmt_elsifs:    /* EMPTY */
                | stmt_elsifs K_ELSIF expr_until_then
                    {
                        pl_line_elsif_t *line = NULL;
                        pl_line_ctrl_t *brother_line = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                        compiler->line_loc = @2.loc;
                        plc_alloc_line(compiler, sizeof(pl_line_elsif_t), LINE_ELIF, (pl_line_ctrl_t **)&line);
                        if (get_valid_cond_tree(stmt, $3, &line->cond) != OG_SUCCESS) {
                            parser_yyerror("invalid condition expr");
                        }
                        if (plc_verify_cond(compiler, line->cond) != OG_SUCCESS) {
                            parser_yyerror("verify condition expr failed");
                        }
                        plc_clone_cond_tree(compiler, &line->cond);
                        plc_pop(compiler, compiler->line_loc, PBE_ELIF, (pl_line_ctrl_t **)&brother_line);
                        line->if_line = (pl_line_if_t *)brother_line;
                        line->if_line->f_line = (pl_line_ctrl_t *)line;
                        line->t_line = NULL;
                        plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT);
                    }
                proc_sect
        ;

stmt_else:      /* EMPTY */
                | K_ELSE
                    {
                        pl_line_ctrl_t *brother_line = NULL;
                        pl_line_else_t *else_line = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                        compiler->line_loc = @1.loc;
                        plc_alloc_line(compiler, sizeof(pl_line_else_t), LINE_ELSE, (pl_line_ctrl_t **)&else_line);
                        plc_pop(compiler, compiler->line_loc, PBE_ELSE, (pl_line_ctrl_t **)&brother_line);
                        else_line->if_line = (pl_line_if_t *)brother_line;
                        else_line->if_line->f_line = (pl_line_ctrl_t *)else_line;
                        plc_push_ctl(compiler, (pl_line_ctrl_t *)else_line, &CM_NULL_TEXT);
                    }
                proc_sect
        ;

expr_until_semi:
                {
                    $$ = read_sql_expression(';', yyscanner);
                }
        ;

expr_until_then:
                {
                    $$ = read_sql_expression(K_THEN, yyscanner);
                }
        ;

expr_until_loop:
                {
                    $$ = read_sql_expression(K_LOOP, yyscanner);
                }
        ;

expr_until_range:
                {
                    $$ = read_sql_expression(DOT_DOT, yyscanner);
                }
        ;

expr_until_when:
                {
                    $$ = read_sql_expression(K_WHEN, yyscanner);
                }
        ;

declare_sect_b:
            decl_stmts
            | /* EMPTY */
        ;

decl_stmts:
            decl_stmt
            | decl_stmts decl_stmt
        ;

decl_defval:    ';'
                    { $$ = NULL; }
                | decl_defkey expr_until_semi
                    {
                        expr_tree_t *expr = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        if (get_valid_expr_tree(stmt, $2, &expr) != OG_SUCCESS) {
                            parser_yyerror("invalid default expr");
                        }
                        $$ = expr;
                    }
        ;

decl_rec_defval:
                    { $$ = NULL; }
                | decl_defkey decl_rec_defval_expr
                    {
                        expr_tree_t *expr = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        if (get_valid_expr_tree(stmt, $2, &expr) != OG_SUCCESS) {
                            parser_yyerror("invalid default expr");
                        }
                        $$ = expr;
                    }
        ;

decl_rec_defval_expr:
                {
                    int tok;
                    $$ = read_sql_expression2(',', ')', yyscanner, &tok);
                    plsql_push_back_token(tok, yyscanner);
                }
        ;

decl_defkey:    COLON_EQUALS
                | K_DEFAULT
        ;

decl_stmt:
            decl_varname decl_datatype decl_notnull decl_defval
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    galist_t *decls = compiler->decls;
                    plv_decl_t *decl = NULL;
                    type_word_t *type = $2;
                    bool32 nullable = $3;
                    text_t name_text;
                    bool32 is_sys_refcursor = pl_bison_type_is_sys_refcursor(type);

                    if (cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl) != OG_SUCCESS) {
                        parser_yyerror("alloc declaration failed");
                    }
                    errno_t rc = memset_s(decl, sizeof(plv_decl_t), 0, sizeof(plv_decl_t));
                    knl_securec_check(rc);
                    decl->vid.block = (int16)compiler->stack.depth;
                    decl->vid.id = (uint16)(decls->count - 1); // not overflow
                    decl->loc = @1.loc;
                    decl->drct = PLV_DIR_NONE;
                    decl->nullable = (bool8)nullable;
                    cm_str2text($1, &name_text);
                    if (pl_copy_name(compiler->entity, &name_text, &decl->name) != OG_SUCCESS) {
                        parser_yyerror("copy declaration name failed");
                    }

                    if (is_sys_refcursor) {
                        if (!nullable) {
                            OG_SRC_THROW_ERROR(@1.loc, ERR_INVALID_DATA_TYPE,
                                "sys_refcursor not null declaration is not supported");
                            parser_yyerror("compile sys_refcursor failed");
                        }
                        if ($4 != NULL) {
                            parser_yyerror("sys_refcursor default value is not supported");
                        }
                        if (init_sys_refcursor_decl(compiler, decl, @1.loc) != OG_SUCCESS) {
                            parser_yyerror("compile sys_refcursor failed");
                        }
                    } else if (!nullable && $4 == NULL) {
                        OG_SRC_THROW_ERROR(@1.loc, ERR_INVALID_DATA_TYPE,
                            "type defining, not null declaration must have default value");
                        parser_yyerror("not null declaration must have default value");
                    } else if (type->pl_rowtype || type->pl_type) {
                        plattr_assist_t plattr_ass;
                        plattr_ass.type = DECL_INHERIT;
                        plattr_ass.decl = decl;
                        plattr_ass.decls = compiler->decls;
                        plattr_ass.is_args = OG_TRUE;
                        if (plc_bison_compile_plv_type(compiler, &plattr_ass, type) != OG_SUCCESS) {
                            parser_yyerror("compile pl type failed");
                        }
                        if (plc_check_decl_datatype(compiler, decl, OG_FALSE) != OG_SUCCESS) {
                            parser_yyerror("check pl type failed");
                        }
                    } else {
                        bool32 result = OG_FALSE;
                        /* check userdef type in block */
                        if (plc_bison_try_compile_local_type(compiler, decl, type, &result) != OG_SUCCESS) {
                            parser_yyerror("try compile local type failed");
                        }

                        if (!result) {
                            decl->type = PLV_VAR;
                            if (plc_bison_compile_type(compiler, PLC_PMODE(decl->drct), &decl->variant.type,
                                type) != OG_SUCCESS) {
                                parser_yyerror("compile type failed");
                            }
                            if (plc_check_datatype(compiler, &decl->variant.type, OG_FALSE) != OG_SUCCESS) {
                                parser_yyerror("check type failed");
                            }
                            if (decl->variant.type.is_array) {
                                decl->type = PLV_ARRAY;
                            }
                        }
                    }

                    if (!is_sys_refcursor && plc_bison_compile_default_def(compiler, decl, $4) != OG_SUCCESS) {
                        parser_yyerror("verify default expr failed");
                    }
                }
            | decl_varname K_EXCEPTION ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    plv_decl_t *decl = NULL;
                    text_t name_text;
                    errno_t rc;

                    if (cm_galist_new(compiler->decls, sizeof(plv_decl_t), (void **)&decl) != OG_SUCCESS) {
                        parser_yyerror("alloc exception decl failed");
                    }
                    rc = memset_s(decl, sizeof(plv_decl_t), 0, sizeof(plv_decl_t));
                    knl_securec_check(rc);
                    decl->vid.block = (int16)compiler->stack.depth;
                    decl->vid.id = (uint16)(compiler->decls->count - 1);
                    decl->loc = @1.loc;
                    decl->type = PLV_EXCPT;
                    cm_str2text($1, &name_text);
                    if (pl_copy_name(compiler->entity, &name_text, &decl->name) != OG_SUCCESS) {
                        parser_yyerror("copy exception name failed");
                    }
                    decl->excpt.is_userdef = OG_TRUE;
                    decl->excpt.err_code = OG_INVALID_INT32;
                }
            | K_PRAGMA T_WORD ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    char *pragma_name = pl_bison_word_name(yyscanner, &$2, @2.offset);
                    if (pragma_name == NULL) {
                        parser_yyerror("invalid pragma name");
                    }
                    if (compile_pragma_stmt(compiler, pragma_name, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile pragma failed");
                    }
                }
            | K_PRAGMA T_WORD '(' pragma_exception_name ',' pragma_error_code ')' ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    char *pragma_name = pl_bison_word_name(yyscanner, &$2, @2.offset);
                    if (pragma_name == NULL) {
                        parser_yyerror("invalid pragma name");
                    }
                    if (!cm_str_equal_ins(pragma_name, "exception_init")) {
                        OG_SRC_THROW_ERROR(@2.loc, ERR_PL_EXPECTED_FAIL_FMT, "EXCEPTION_INIT", pragma_name);
                        YYABORT;
                    }
                    if (compile_exception_init_pragma(compiler, &$4, (int32)$6, @4.loc) != OG_SUCCESS) {
                        parser_yyerror("compile exception init pragma failed");
                    }
                }
            | decl_varname K_SYS_REFCURSOR ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_sys_refcursor_decl(compiler, $1, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile sys_refcursor failed");
                    }
                }
            | K_CURSOR decl_varname cursor_arg_decls K_IS cursor_query
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_cursor_decl(compiler, $2, $3, $5, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile cursor failed");
                    }
                }
            | K_CURSOR decl_varname cursor_arg_decls ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_cursor_decl(compiler, $2, $3, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile cursor failed");
                    }
                }
            | K_CURSOR decl_varname K_IS cursor_query
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_cursor_decl(compiler, $2, NULL, $4, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile cursor failed");
                    }
                }
            | K_CURSOR decl_varname ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (compile_cursor_decl(compiler, $2, NULL, NULL, @1.loc) != OG_SUCCESS) {
                        parser_yyerror("compile cursor failed");
                    }
                }
            | K_TYPE decl_varname K_IS K_RECORD '(' record_attr_list ')' ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (plc_bison_compile_type_def(compiler, $2, $6, @1.loc, MATCH_RECORD) != OG_SUCCESS) {
                        parser_yyerror("parse record type failed");
                    }
                }
            | K_TYPE decl_varname K_IS K_REF K_CURSOR ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (plc_bison_compile_type_def(compiler, $2, NULL, @1.loc, MATCH_REF) != OG_SUCCESS) {
                        parser_yyerror("parse ref cursor type failed");
                    }
                }
            | K_TYPE decl_varname K_IS K_TABLE K_OF decl_datatype opt_collection_index ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    plc_bison_collection_type_def_t type_def = { $2, $6, $7, 0, @1.loc, MATCH_TABLE };
                    if (plc_bison_compile_collection_type_def(compiler, &type_def) != OG_SUCCESS) {
                        parser_yyerror("parse table type failed");
                    }
                }
            | K_TYPE decl_varname K_IS K_VARRAY '(' ICONST ')' K_OF decl_datatype ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    plc_bison_collection_type_def_t type_def = { $2, $9, NULL, (uint32)$6, @1.loc, MATCH_VARRAY };
                    if (plc_bison_compile_collection_type_def(compiler, &type_def) != OG_SUCCESS) {
                        parser_yyerror("parse varray type failed");
                    }
                }
        ;

opt_collection_index:
            K_INDEX K_BY decl_datatype                    { $$ = $3; }
            | /* EMPTY */                                 { $$ = NULL; }
        ;

cursor_arg_decls:
            '(' cursor_arg_list ')'                        { $$ = $2; }
            | '(' ')'                                      { $$ = NULL; parser_yyerror("cursor parameter expected"); }
        ;

cursor_arg_list:
            cursor_arg
                {
                    galist_t *list = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_create_list(stmt, &list) != OG_SUCCESS ||
                        cm_galist_insert(list, $1) != OG_SUCCESS) {
                        parser_yyerror("create cursor arg list failed");
                    }
                    $$ = list;
                }
            | cursor_arg_list ',' cursor_arg
                {
                    if (cm_galist_insert($1, $3) != OG_SUCCESS) {
                        parser_yyerror("append cursor arg failed");
                    }
                    $$ = $1;
                }
        ;

cursor_arg:
            simple_name opt_cursor_arg_in decl_datatype cursor_arg_defval
                {
                    pl_bison_cursor_arg_t *arg = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (sql_alloc_mem(stmt->context, sizeof(pl_bison_cursor_arg_t), (void **)&arg) != OG_SUCCESS) {
                        parser_yyerror("alloc cursor arg failed");
                    }
                    arg->name = $1;
                    arg->type = $3;
                    arg->def_expr = $4;
                    arg->loc = @1.loc;
                    $$ = arg;
                }
        ;

opt_cursor_arg_in:
            K_IN
            | /* EMPTY */
        ;

cursor_arg_defval:
            decl_defkey cursor_arg_defval_expr
                {
                    expr_tree_t *expr = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    if (get_valid_expr_tree(stmt, $2, &expr) != OG_SUCCESS) {
                        parser_yyerror("invalid cursor arg default expr");
                    }
                    $$ = expr;
                }
            | /* EMPTY */                                  { $$ = NULL; }
        ;

cursor_arg_defval_expr:
                {
                    int tok;
                    $$ = read_sql_expression2(',', ')', yyscanner, &tok);
                    plsql_push_back_token(tok, yyscanner);
                }
        ;

decl_notnull:   K_NOT K_NULL
                    { $$ = OG_FALSE; }
                | /* EMPTY */
                    { $$ = OG_TRUE; }
        ;

record_attr_list:   record_attr
                        {
                            galist_t *list = NULL;
                            sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                            if (sql_create_list(stmt, &list) != OG_SUCCESS) {
                                parser_yyerror("create list failed");
                            }
                            if (cm_galist_insert(list, $1) != OG_SUCCESS) {
                                parser_yyerror("insert list failed");
                            }
                            $$ = list;
                        }
                    | record_attr_list ',' record_attr
                        {
                            galist_t *list = $1;
                            if (cm_galist_insert(list, $3) != OG_SUCCESS) {
                                parser_yyerror("insert list failed");
                            }
                            $$ = list;
                        }
        ;

record_attr:    decl_varname decl_datatype decl_notnull decl_rec_defval
                    {
                        record_attr_t *attr_def = NULL;
                        sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                        pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;

                        if (sql_alloc_mem(compiler->stmt->context, sizeof(record_attr_t), (void **)&attr_def) != OG_SUCCESS) {
                            parser_yyerror("alloc mem failed");
                        }

                        attr_def->name = $1;
                        attr_def->type = $2;
                        attr_def->nullable = $3;
                        attr_def->def_expr = $4;
                        attr_def->loc = @1.loc;
                        $$ = attr_def;
                    }
        ;

decl_datatype:
                {
                    /* make a type_word_t */
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;
                    int tok;
                    source_location_t loc;
                    union YYSTYPE tok_lval;
                    YYLTYPE tok_lloc;
                    int tok_len;
                    char *typename = NULL;
                    type_word_t *type = NULL;
                    bool32 pl_type = OG_FALSE;
                    bool32 pl_rowtype = OG_FALSE;
                    bool32 is_interval = OG_FALSE;
                    bool32 is_name_typemode = OG_FALSE;
                    bool32 is_char = OG_FALSE;
                    galist_t *typemode = NULL;
                    galist_t *second_typemode = NULL;
                    text_t *text = NULL;

                    /*
                     * This empty production can be reduced after bison has already read the
                     * datatype as lookahead. Consume yychar first so declarations like
                     * "v int := 0" do not skip "int" and start parsing at ":=".
                     * Snapshot lval/lloc/leng together: datatype helpers must
                     * not depend on yyextra->last_token after another manual lex.
                     */
                    if (yychar == YYEMPTY) {
                        tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                    } else {
                        tok = yychar;
                        tok_lval = yylval;
                        tok_lloc = yylloc;
                        tok_len = PLSQL_YYLENG(yyscanner);
                        yychar = YYEMPTY;
                    }
                    loc = tok_lloc.loc;
                    typename = pl_type_token_text(yyscanner, tok, &tok_lval, &tok_lloc, tok_len);
                    if (typename == NULL) {
                        parser_yyerror("expected datatype");
                    }

                    if (cm_strcmpi(typename, "interval") == 0) {
                        is_interval = OG_TRUE;
                        if (pl_read_interval_datatype(yyscanner, stmt, &typename, &typemode,
                            &second_typemode, &tok) != OG_SUCCESS) {
                            parser_yyerror("parse interval datatype failed");
                        }
                    } else {
                        while ((tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len)) == '.') {
                            tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                            char *sub_name = pl_type_token_text(yyscanner, tok, &tok_lval, &tok_lloc, tok_len);
                            if (sub_name == NULL) {
                                parser_yyerror("expected identifier after '.'");
                            }
                            if (typemode == NULL) {
                                sql_create_list(stmt, &typemode);
                            }
                            is_name_typemode = OG_TRUE;
                            cm_galist_new(typemode, sizeof(text_t), (pointer_t *)&text);
                            cm_str2text(sub_name, text);
                        }
                        if (tok == '(') {
                            expr_tree_t *expr = NULL;
                            is_name_typemode = OG_FALSE;
                            if (sql_create_list(stmt, &typemode) != OG_SUCCESS) {
                                parser_yyerror("create typemode failed");
                            }
                            for (;;) {
                                tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                                if (tok != ICONST) {
                                    parser_yyerror("expected type modifier");
                                }
                                if (sql_create_int_const_expr(stmt, &expr, tok_lval.ival, tok_lloc.loc) != OG_SUCCESS ||
                                    cm_galist_insert(typemode, expr) != OG_SUCCESS) {
                                    parser_yyerror("append type modifier failed");
                                }
                                tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                                if (pl_token_text_equal(yyscanner, tok, &tok_lval, &tok_lloc, tok_len, "char")) {
                                    is_char = OG_TRUE;
                                    tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                                } else if (pl_token_text_equal(yyscanner, tok, &tok_lval, &tok_lloc, tok_len, "byte")) {
                                    is_char = OG_FALSE;
                                    tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                                }
                                if (tok == ')') {
                                    break;
                                }
                                if (tok != ',') {
                                    parser_yyerror("expected ',' or ')' in type modifier");
                                }
                            }
                            tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                        }
                        if (pl_token_text_equal(yyscanner, tok, &tok_lval, &tok_lloc, tok_len, "unsigned")) {
                            if (cm_strcmpi(typename, "integer") == 0 || cm_strcmpi(typename, "int") == 0) {
                                typename = "uint";
                            } else if (cm_strcmpi(typename, "smallint") == 0 || cm_strcmpi(typename, "short") == 0) {
                                typename = "usmallint";
                            } else if (cm_strcmpi(typename, "tinyint") == 0) {
                                typename = "utinyint";
                            } else if (cm_strcmpi(typename, "bigint") == 0) {
                                typename = "ubigint";
                            } else if (cm_strcmpi(typename, "binary_integer") == 0) {
                                typename = "uint";
                            } else if (cm_strcmpi(typename, "binary_bigint") == 0) {
                                typename = "ubigint";
                            } else {
                                parser_yyerror("unexpected unsigned datatype");
                            }
                            tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                        }
                    }
                    if (tok == '%') {
                        tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
                        if (tok_is_keyword(tok, &tok_lval, K_TYPE, "type")) {
                            pl_type = OG_TRUE;
                        } else if (tok_is_keyword(tok, &tok_lval, K_ROWTYPE, "rowtype")) {
                            pl_rowtype = OG_TRUE;
                        } else {
                            parser_yyerror("expected TYPE or ROWTYPE");
                        }
                    } else {
                        plsql_push_back_token(tok, yyscanner);
                    }

                    if (make_type_word(compiler, &type, typename, typemode, loc, is_name_typemode,
                        pl_type, pl_rowtype) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }
                    type->is_char = is_char;

                    if (is_interval) {
                        type->second_typemde = second_typemode;
                    }
                    $$ = type;
                }
        ;

simple_name:
            T_WORD
                {
                    $$ = pl_bison_word_name(yyscanner, &$1, @1.offset);
                    if ($$ == NULL) {
                        parser_yyerror("invalid name");
                    }
                }
            | unreserved_keyword
                {
                    char *tmp = NULL;
                    if (pl_copy_cstr_name(yyscanner, $1, OG_FALSE, &tmp) != OG_SUCCESS) {
                        parser_yyerror("alloc name failed");
                    }
                    $$ = tmp;
                }
        ;

decl_varname:
            T_WORD
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    char *ident = pl_bison_word_name(yyscanner, &$1, @1.offset);
                    text_t name;
                    if (ident == NULL) {
                        parser_yyerror("invalid varname");
                    }
                    cm_str2text(ident, &name);
                    bool32 result = OG_FALSE;
                    plc_check_duplicate(compiler->decls, (text_t *)&name, $1.quoted, &result);

                    if (result) {
                        parser_yyerror("duplicate varname");
                    }
                    $$ = ident;
                }
            | unreserved_keyword
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    char *tmp = NULL;
                    text_t name;

                    if (pl_copy_cstr_name(yyscanner, $1, OG_TRUE, &tmp) != OG_SUCCESS) {
                        parser_yyerror("alloc name failed");
                    }
                    cm_str2text(tmp, &name);
                    bool32 result = OG_FALSE;

                    plc_check_duplicate(compiler->decls, (text_t *)&name, OG_FALSE, &result);

                    if (result) {
                        parser_yyerror("duplicate varname");
                    }
                    $$ = tmp;
                }
        ;

pragma_exception_name:
            T_WORD
                {
                    char *name = pl_bison_word_name(yyscanner, &$1, @1.offset);
                    if (name == NULL) {
                        parser_yyerror("invalid pragma exception name");
                    }
                    $$.ident = name;
                    $$.quoted = $1.quoted;
                }
            | unreserved_keyword
                {
                    char *tmp = NULL;
                    if (pl_copy_cstr_name(yyscanner, $1, OG_TRUE, &tmp) != OG_SUCCESS) {
                        parser_yyerror("alloc pragma exception name failed");
                    }
                    $$.ident = tmp;
                    $$.quoted = OG_FALSE;
                }
        ;

pragma_error_code:
            ICONST                                      { $$ = $1; }
            | '-' ICONST
                {
                    if ($2 == OG_MIN_INT32) {
                        parser_yyerror("invalid pragma error code");
                    }
                    $$ = -$2;
                }
        ;

unreserved_keyword:
                            K_ABSOLUTE
                | K_ALIAS
                | K_ALTER
                | K_ARRAY
                | K_AS
                | K_BACKWARD
                | K_BULK
                | K_CALL
                | K_CATALOG_NAME
                | K_CLASS_ORIGIN
                | K_COLLECT
                | K_COLUMN_NAME
                | K_COMMIT
                | K_CONDITION
                | K_CONSTANT
                | K_CONSTRAINT_CATALOG
                | K_CONSTRAINT_NAME
                | K_CONSTRAINT_SCHEMA
                | K_CONTINUE
                | K_CURRENT
                | K_CURSOR_NAME
                | K_DEBUG
                | K_DETAIL
                | K_DISTINCT
                | K_DUMP
                | K_ERRCODE
                | K_ERROR
                | K_EXCEPT
                | K_EXCEPTIONS
                | K_FALSE
                | K_FIRST
                | K_FORWARD
                | K_FOUND
                | K_HANDLER
                | K_HINT
                | K_IMMEDIATE
                | K_INDEX
                | K_INFO
                | K_INTERSECT
                | K_IS
                | K_ITERATE
                | K_LAST
                | K_LEAVE
                | K_LOG
                | K_MERGE
                | K_MESSAGE
                | K_MESSAGE_TEXT
                | K_MULTISET
                | K_MYSQL_ERRNO
                | K_NEXT
                | K_NO
                | K_NOTICE
                | K_OPTION
                | K_PACKAGE
                | K_INSTANTIATION
                | K_PERFORM
                | K_PG_EXCEPTION_CONTEXT
                | K_PG_EXCEPTION_DETAIL
                | K_PG_EXCEPTION_HINT
                | K_PIPE
                | K_PRAGMA
                | K_PRIOR
                | K_QUERY
                | K_RECORD
                | K_RELATIVE
                | K_RELEASE
                | K_REPEAT
                | K_RESIGNAL
                | K_RESULT_OID
                | K_RETURNED_SQLSTATE
                | K_REVERSE
                | K_ROLLBACK
                | K_ROW
                | K_ROW_COUNT
                | K_ROWTYPE
                | K_SAVE
                | K_SCHEMA_NAME
                | K_SCROLL
                | K_SIGNAL
                | K_SLICE
                | K_SQLEXCEPTION
                | K_SQLSTATE
                | K_SQLWARNING
                | K_STACKED
                | K_SUBCLASS_ORIGIN
                | K_SUBTYPE
                | K_SYS_REFCURSOR
                | K_TABLE
                | K_TABLE_NAME
                | K_TRUE
                | K_UNION
                | K_UNTIL
                | K_USE_COLUMN
                | K_USE_VARIABLE
                | K_VARIABLE_CONFLICT
                | K_VARRAY
                | K_WARNING
                | K_WITH
        ;

%%

static status_t compile_pragma_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc)
{
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    uint32 max_stack_depth = (compiler->type == PL_TRIGGER) ? 1 : 0;

    if (!cm_str_equal_ins(name, "autonomous_transaction")) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "pragma syntax word", name);
        return OG_ERROR;
    }

#ifdef OG_RAC_ING
    if (IS_COORDINATOR && IS_APP_CONN(compiler->stmt->session)) {
        OG_SRC_THROW_ERROR(loc, ERR_CAPABILITY_NOT_SUPPORT, "AUTONOMOUS_TRANSACTION on coordinator is");
        return OG_ERROR;
    }
#endif

    if (compiler->stack.depth > max_stack_depth) {
        OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "autonomous transaction must be in top stack");
        return OG_ERROR;
    }

    entity->is_auton_trans = OG_TRUE;
    return OG_SUCCESS;
}

static status_t compile_exception_init_pragma(pl_compiler_t *compiler, const PLword *word, int32 err_code,
    source_location_t loc)
{
    text_t name;
    word_t name_word;
    plv_decl_t *decl = NULL;

    if (word == NULL || word->ident == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "user defined exception variant name", "token");
        return OG_ERROR;
    }

    cm_str2text((char *)word->ident, &name);
    init_word_from_name(&name_word, word->ident, loc);
    name_word.type = word->quoted ? WORD_TYPE_DQ_STRING : WORD_TYPE_VARIANT;
    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, &name_word));
    plc_find_decl_ex(compiler, &name_word, PLV_EXCPT, NULL, &decl);
    if (decl == NULL && compiler->decls != NULL) {
        plc_find_in_decls(compiler->decls, &name, OG_FALSE, &decl);
    }
    if (decl == NULL || ((decl->type & PLV_EXCPT) == 0)) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "user defined exception variant name", word->ident);
        return OG_ERROR;
    }

    if (!((err_code > ERR_ERRNO_BASE && err_code < ERR_CODE_CEIL) ||
        (err_code >= ERR_MIN_USER_DEFINE_ERROR && err_code <= ERR_MAX_USER_DEFINE_ERROR))) {
        OG_SRC_THROW_ERROR(loc, ERR_PROGRAM_ERROR_FMT, "illegal error code for PRAGMA EXCEPTION_INIT");
        return OG_ERROR;
    }

    decl->excpt.err_code = (uint32)err_code;
    return OG_SUCCESS;
}

static void plsql_yyerror(YYLTYPE *yylloc, core_yyscan_t yyscanner, const char* message)
{
    source_location_t loc = (yylloc == NULL) ? PLSQL_YYLLOC(yyscanner)->loc : yylloc->loc;

    OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, message);
    return;
}

static bool tok_is_keyword(int token, union YYSTYPE *lval, int kw_token, const char *kw_str)
{
    if (token == kw_token)
    {
        return true;
    }

//    else if (token == T_DATUM)
//    {
        /*
         * It's a variable, so recheck the string name.  Note we will not
         * match composite names (hence an unreserved word followed by "."
         * will not be recognized).
         */
//        if (!lval->wdatum.quoted && lval->wdatum.ident != NULL &&
//            strcmp(lval->wdatum.ident, kw_str) == 0)
//            return true;
//    }
    return false;				/* not the keyword */
}

static char *pl_token_text(int token, union YYSTYPE *lval)
{
    if (token == YYEOF) {
        return "EOF";
    }
    if (token == ';') {
        return "';'";
    }
    if (token == ',') {
        return "','";
    }
    if (token == '(') {
        return "'('";
    }
    if (token == ')') {
        return "')'";
    }
    if (token == T_WORD) {
        return lval->word.ident;
    }
    if (token == IDENT) {
        return lval->str;
    }
    if (lval->keyword != NULL) {
        return (char *)lval->keyword;
    }
    return NULL;
}

static char *pl_copy_text_token(sql_stmt_t *stmt, text_t *text)
{
    char *buf = NULL;
    errno_t rc;

    if (sql_alloc_mem(stmt->context, text->len + 1, (void **)&buf) != OG_SUCCESS) {
        return NULL;
    }
    if (text->len != 0) {
        rc = memcpy_s(buf, text->len + 1, text->str, text->len);
        if (rc != EOK) {
            return NULL;
        }
    }
    buf[text->len] = '\0';
    return buf;
}

static int pl_read_type_token(core_yyscan_t yyscanner, union YYSTYPE *lval, YYLTYPE *lloc, int *leng)
{
    int token = PLSQL_YYLEX(yyscanner);

    *lval = *PLSQL_YYLVAL(yyscanner);
    *lloc = *PLSQL_YYLLOC(yyscanner);
    *leng = PLSQL_YYLENG(yyscanner);
    return token;
}

static char *pl_type_token_text(core_yyscan_t yyscanner, int token, union YYSTYPE *lval, YYLTYPE *lloc,
    int token_len)
{
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    char *text = NULL;
    char *src = NULL;
    char *buf = NULL;
    errno_t rc;

    if (token == T_DATUM && lval->node != NULL) {
        var_address_pair_t *pair = sql_get_last_addr_pair(lval->node);
        if (pair != NULL && pair->type == UDT_STACK_ADDR && pair->stack->decl != NULL) {
            return pl_copy_text_token(stmt, &pair->stack->decl->name);
        }
    }

    text = pl_token_text(token, lval);
    if (text != NULL) {
        return text;
    }

    /*
     * Declaration datatypes are read by the PL bison parser, while datatype
     * keywords are tokenized by the shared SQL scanner. For SQL keywords that
     * are not PL tokens, copy the original lexeme instead of depending on the
     * core grammar token enum being visible from this generated parser.
     */
    if (token_len <= 0) {
        return NULL;
    }

    src = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + lloc->offset;
    if (!pl_bison_is_ident_text(src, (uint32)token_len)) {
        return NULL;
    }

    if (sql_alloc_mem(stmt->context, (uint32)token_len + 1, (void **)&buf) != OG_SUCCESS) {
        return NULL;
    }
    rc = memcpy_s(buf, (uint32)token_len + 1, src, (uint32)token_len);
    if (rc != EOK) {
        return NULL;
    }
    buf[token_len] = '\0';
    return buf;
}

static bool32 pl_token_text_equal(core_yyscan_t yyscanner, int token, union YYSTYPE *lval, YYLTYPE *lloc,
    int token_len, const char *expected)
{
    char *text = pl_type_token_text(yyscanner, token, lval, lloc, token_len);
    return (text != NULL && cm_strcmpi(text, expected) == 0);
}

static status_t pl_expect_type_token(core_yyscan_t yyscanner, int token, union YYSTYPE *lval, YYLTYPE *lloc,
    int token_len, const char *expected)
{
    char *actual = pl_type_token_text(yyscanner, token, lval, lloc, token_len);

    if (actual != NULL && cm_strcmpi(actual, expected) == 0) {
        return OG_SUCCESS;
    }
    OG_SRC_THROW_ERROR(lloc->loc, ERR_PL_EXPECTED_FAIL_FMT, expected, (actual == NULL) ? "token" : actual);
    return OG_ERROR;
}

static status_t pl_append_type_modifier(sql_stmt_t *stmt, galist_t **typemode, int value, source_location_t loc)
{
    expr_tree_t *expr = NULL;

    if (*typemode == NULL) {
        OG_RETURN_IFERR(sql_create_list(stmt, typemode));
    }
    OG_RETURN_IFERR(sql_create_int_const_expr(stmt, &expr, value, loc));
    return cm_galist_insert(*typemode, expr);
}

static status_t pl_read_optional_type_modifier(core_yyscan_t yyscanner, sql_stmt_t *stmt, galist_t **typemode,
    int *tok, union YYSTYPE *tok_lval, YYLTYPE *tok_lloc, int *tok_len)
{
    if (*tok != '(') {
        return OG_SUCCESS;
    }

    for (;;) {
        *tok = pl_read_type_token(yyscanner, tok_lval, tok_lloc, tok_len);
        if (*tok != ICONST) {
            char *actual = pl_token_text(*tok, tok_lval);
            OG_SRC_THROW_ERROR(tok_lloc->loc, ERR_PL_EXPECTED_FAIL_FMT, "type modifier",
                (actual == NULL) ? "token" : actual);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pl_append_type_modifier(stmt, typemode, tok_lval->ival, tok_lloc->loc));

        *tok = pl_read_type_token(yyscanner, tok_lval, tok_lloc, tok_len);
        if (*tok == ')') {
            break;
        }
        if (*tok != ',') {
            char *actual = pl_token_text(*tok, tok_lval);
            OG_SRC_THROW_ERROR(tok_lloc->loc, ERR_PL_EXPECTED_FAIL_FMT, "',' or ')'",
                (actual == NULL) ? "token" : actual);
            return OG_ERROR;
        }
    }

    *tok = pl_read_type_token(yyscanner, tok_lval, tok_lloc, tok_len);
    return OG_SUCCESS;
}

static status_t pl_read_interval_year_type(core_yyscan_t yyscanner, sql_stmt_t *stmt,
    galist_t **typemode, int *tok)
{
    union YYSTYPE tok_lval;
    YYLTYPE tok_lloc;
    int tok_len;

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    OG_RETURN_IFERR(pl_read_optional_type_modifier(yyscanner, stmt, typemode, tok, &tok_lval, &tok_lloc,
        &tok_len));
    OG_RETURN_IFERR(pl_expect_type_token(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "to"));

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    OG_RETURN_IFERR(pl_expect_type_token(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "month"));

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    return OG_SUCCESS;
}

static status_t pl_read_interval_day_type(core_yyscan_t yyscanner, sql_stmt_t *stmt,
    galist_t **typemode, galist_t **second_typemode, int *tok)
{
    union YYSTYPE tok_lval;
    YYLTYPE tok_lloc;
    int tok_len;

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    OG_RETURN_IFERR(pl_read_optional_type_modifier(yyscanner, stmt, typemode, tok, &tok_lval, &tok_lloc,
        &tok_len));
    OG_RETURN_IFERR(pl_expect_type_token(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "to"));

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    OG_RETURN_IFERR(pl_expect_type_token(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "second"));

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    return pl_read_optional_type_modifier(yyscanner, stmt, second_typemode, tok, &tok_lval, &tok_lloc,
        &tok_len);
}

static status_t pl_read_interval_datatype(core_yyscan_t yyscanner, sql_stmt_t *stmt, char **typename,
    galist_t **typemode, galist_t **second_typemode, int *tok)
{
    union YYSTYPE tok_lval;
    YYLTYPE tok_lloc;
    int tok_len;

    *tok = pl_read_type_token(yyscanner, &tok_lval, &tok_lloc, &tok_len);
    if (pl_token_text_equal(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "year")) {
        *typename = "interval year to month";
        return pl_read_interval_year_type(yyscanner, stmt, typemode, tok);
    }
    if (pl_token_text_equal(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len, "day")) {
        *typename = "interval day to second";
        return pl_read_interval_day_type(yyscanner, stmt, typemode, second_typemode, tok);
    }

    char *actual = pl_type_token_text(yyscanner, *tok, &tok_lval, &tok_lloc, tok_len);
    OG_SRC_THROW_ERROR(tok_lloc.loc, ERR_PL_EXPECTED_FAIL_FMT, "DAY or YEAR",
        (actual == NULL) ? "token" : actual);
    return OG_ERROR;
}

static void init_word_from_name(word_t *word, const char *name, source_location_t loc)
{
    errno_t rc = memset_s(word, sizeof(word_t), 0, sizeof(word_t));
    knl_securec_check(rc);
    word->type = WORD_TYPE_VARIANT;
    word->loc = loc;
    word->text.loc = loc;
    cm_str2text((char *)name, &word->text.value);
}

static text_t *current_label_name(pl_compiler_t *compiler)
{
    pl_line_label_t *label = (pl_line_label_t *)compiler->last_line;
    if (label == NULL || label->ctrl.type != LINE_LABEL) {
        return NULL;
    }
    return &label->name;
}

static status_t check_end_name(const text_t *expected, const char *actual, source_location_t loc)
{
    text_t actual_text;

    if (actual == NULL) {
        return OG_SUCCESS;
    }
    cm_str2text((char *)actual, &actual_text);
    if (expected != NULL && cm_text_equal_ins((text_t *)expected, &actual_text)) {
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR(loc, ERR_UNDEFINED_SYMBOL_FMT, actual);
    return OG_ERROR;
}

static status_t check_block_end_name(pl_compiler_t *compiler, const text_t *expected,
    const pl_bison_end_name_t *actual, source_location_t loc)
{
    text_t actual_owner;

    if (actual == NULL || actual->name == NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(check_end_name(expected, actual->name, loc));
    if (actual->owner == NULL) {
        return OG_SUCCESS;
    }

    if (compiler == NULL || compiler->obj == NULL || expected != &compiler->obj->name) {
        OG_SRC_THROW_ERROR(loc, ERR_UNDEFINED_SYMBOL_FMT, actual->owner);
        return OG_ERROR;
    }

    cm_str2text((char *)actual->owner, &actual_owner);
    if (!cm_text_equal_ins(&compiler->obj->user, &actual_owner)) {
        OG_SRC_THROW_ERROR(loc, ERR_UNDEFINED_SYMBOL_FMT, actual->owner);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t check_current_loop_end_name(pl_compiler_t *compiler, const char *actual, source_location_t loc)
{
    if (compiler->control_stack.depth == 0) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "END LOOP");
        return OG_ERROR;
    }
    return check_end_name(&compiler->control_stack.items[compiler->control_stack.depth - 1].name, actual, loc);
}

static status_t add_label_line(pl_compiler_t *compiler, pl_line_ctrl_t *line)
{
    if (compiler->labels.count >= PL_MAX_BLOCK_DEPTH) {
        OG_SRC_THROW_ERROR(line->loc, ERR_PL_EXCEED_LABEL_MAX, PL_MAX_BLOCK_DEPTH);
        return OG_ERROR;
    }

    compiler->labels.lines[compiler->labels.count++] = line;
    return OG_SUCCESS;
}

static status_t compile_label_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc)
{
    word_t word;
    pl_line_label_t *line = NULL;

    init_word_from_name(&word, name, loc);
    OG_RETURN_IFERR(plc_label_name_verify(compiler, &word));
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_label_t), LINE_LABEL, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(pl_copy_object_name_ci(compiler->entity, word.type, (text_t *)&word.text, &line->name));
    line->stack_line = CURR_BLOCK_BEGIN(compiler);
    return add_label_line(compiler, (pl_line_ctrl_t *)line);
}

static status_t compile_goto_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc)
{
    word_t word;
    pl_line_goto_t *line = NULL;

    init_word_from_name(&word, name, loc);
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_goto_t), LINE_GOTO, (pl_line_ctrl_t **)&line));
    return pl_copy_object_name_ci(compiler->entity, word.type, (text_t *)&word.text, &line->label);
}

static status_t compile_raise_decl(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word,
    pl_line_raise_t *raise_line)
{
    int32 except_id;

    if (decl != NULL) {
        OG_RETURN_IFERR(pl_copy_name(compiler->entity, (text_t *)&word->text, &raise_line->excpt_name));
        raise_line->excpt_info.is_userdef = decl->excpt.is_userdef;
        raise_line->excpt_info.error_code =
            (decl->excpt.err_code == INVALID_EXCEPTION) ? ERR_USER_DEFINED_EXCEPTION : (int32)decl->excpt.err_code;
        raise_line->excpt_info.vid = decl->vid;
        return OG_SUCCESS;
    }

    except_id = pl_get_exception_id(word);
    if (except_id == INVALID_EXCEPTION) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_PL_INVALID_EXCEPTION_FMT, W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, (text_t *)&word->text, &raise_line->excpt_name));
    raise_line->excpt_info.is_userdef = OG_FALSE;
    raise_line->excpt_info.error_code = except_id;
    return OG_SUCCESS;
}

static status_t compile_raise_stmt(pl_compiler_t *compiler, const char *name, source_location_t loc)
{
    word_t word;
    pl_line_raise_t *line = NULL;
    plv_decl_t *decl = NULL;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_raise_t), LINE_RAISE, (pl_line_ctrl_t **)&line));
    if (name != NULL) {
        init_word_from_name(&word, name, loc);
        OG_RETURN_IFERR(plc_verify_word_as_var(compiler, &word));
        plc_find_decl_ex(compiler, &word, PLV_EXCPT, NULL, &decl);
        return compile_raise_decl(compiler, decl, &word, line);
    }

    for (int32 i = (int32)compiler->stack.depth - 1; i >= 0; i--) {
        if (compiler->stack.items[i].entry->type == LINE_EXCEPTION) {
            line->excpt_name = CM_NULL_TEXT;
            line->excpt_info.is_userdef = OG_FALSE;
            line->excpt_info.error_code = INVALID_EXCEPTION;
            return OG_SUCCESS;
        }
    }

    OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
        "a RAISE statement with no exception name must be inside an exception handler");
    return OG_ERROR;
}

static status_t find_named_loop(pl_compiler_t *compiler, source_location_t loc, const char *name,
    pl_line_ctrl_t **line)
{
    text_t loop_name;
    cm_str2text((char *)name, &loop_name);

    for (int32 i = (int32)compiler->control_stack.depth - 1; i >= 0; i--) {
        pl_line_type_t type = compiler->control_stack.items[i].entry->type;
        if ((type == LINE_LOOP || type == LINE_WHILE || type == LINE_FOR) &&
            cm_text_equal_ins(&compiler->control_stack.items[i].name, &loop_name)) {
            *line = compiler->control_stack.items[i].entry;
            return OG_SUCCESS;
        }
    }

    *line = NULL;
    OG_SRC_THROW_ERROR_EX(loc, ERR_PL_SYNTAX_ERROR_FMT, "no in loop name %s statement.", name);
    return OG_ERROR;
}

static status_t compile_exit_or_continue_stmt(sql_stmt_t *stmt, bool32 is_continue, const char *label_name,
    text_t *cond_src, source_location_t loc)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_line_ctrl_t **next = NULL;
    void **cond = NULL;

    if (is_continue) {
        pl_line_continue_t *line = NULL;
        OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_continue_t), LINE_CONTINUE,
            (pl_line_ctrl_t **)&line));
        cond = &line->cond;
        next = &line->next;
    } else {
        pl_line_exit_t *line = NULL;
        OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_exit_t), LINE_EXIT, (pl_line_ctrl_t **)&line));
        cond = &line->cond;
        next = &line->next;
    }

    if (cond_src != NULL) {
        OG_RETURN_IFERR(get_valid_cond_tree(stmt, cond_src, (cond_tree_t **)cond));
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)*cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)cond));
    } else {
        *cond = NULL;
    }

    return (label_name == NULL) ? find_top_loop(compiler, loc, next) :
        find_named_loop(compiler, loc, label_name, next);
}

static status_t pl_bison_clone_fragment_tree(pl_compiler_t *compiler, pl_bison_fragment_type_t type, void *raw_tree,
    void **tree)
{
    expr_tree_t *expr = NULL;
    cond_tree_t *cond = NULL;
    galist_t *expr_list = NULL;

    switch (type) {
        case PL_BISON_FRAGMENT_EXPR_LIST:
            expr_list = (galist_t *)raw_tree;
            if (expr_list == NULL || expr_list->count == 0) {
                OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
                return OG_ERROR;
            }
            expr = (expr_tree_t *)cm_galist_get(expr_list, 0);
            if (expr == NULL) {
                OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
                return OG_ERROR;
            }
            return sql_clone_expr_tree(compiler->entity, expr, (expr_tree_t **)tree, pl_alloc_mem);

        case PL_BISON_FRAGMENT_EXPR_TREE:
            expr = (expr_tree_t *)raw_tree;
            if (expr == NULL || expr->root == NULL) {
                OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
                return OG_ERROR;
            }
            return sql_clone_expr_tree(compiler->entity, expr, (expr_tree_t **)tree, pl_alloc_mem);

        case PL_BISON_FRAGMENT_COND_TREE:
            cond = (cond_tree_t *)raw_tree;
            if (cond == NULL) {
                OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
                return OG_ERROR;
            }
            return sql_clone_cond_tree(compiler->entity, cond, (cond_tree_t **)tree, pl_alloc_mem);

        default:
            OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
            return OG_ERROR;
    }
}

static status_t pl_bison_parse_fragment_tree(sql_stmt_t *stmt, const char *prefix, text_t *src, const char *suffix,
    pl_bison_fragment_type_t type, void **tree)
{
    sql_text_t sql_text = { 0 };
    sql_stmt_t *sub_stmt = NULL;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    void *raw_tree = NULL;
    status_t status = OG_ERROR;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    sql_stmt_t *save_compiler_stmt = NULL;

    if (compiler == NULL) {
        OG_THROW_ERROR(ERR_INVALID_EXPRESSION);
        return OG_ERROR;
    }

    *tree = NULL;
    OGSQL_SAVE_STACK(stmt);
    do {
        OG_BREAK_IF_ERROR(pl_bison_make_parse_text(stmt, prefix, src, suffix, &sql_text));
        OG_BREAK_IF_ERROR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

        sql_init_stmt(stmt->session, sub_stmt, stmt->id);
        sub_stmt->pl_compiler = stmt->pl_compiler;
        save_compiler_stmt = compiler->stmt;
        sub_stmt->context = NULL;
        sub_stmt->session->current_stmt = sub_stmt;

        OG_BREAK_IF_ERROR(sql_alloc_context(sub_stmt));
        sub_stmt->plsql_mode = stmt->plsql_mode;
        sub_stmt->context->type = stmt->context->type;
        sub_stmt->context->params = stmt->context->params;
        sub_stmt->context->pname_count = stmt->context->pname_count;
        compiler->stmt = sub_stmt;
        OG_BREAK_IF_ERROR(raw_parser(sub_stmt, &sql_text, &raw_tree));
        stmt->context->pname_count = sub_stmt->context->pname_count;
        OG_BREAK_IF_ERROR(pl_bison_clone_fragment_tree(compiler, type, raw_tree, tree));
        status = OG_SUCCESS;
    } while (0);

    if (save_compiler_stmt != NULL) {
        compiler->stmt = save_compiler_stmt;
    }
    stmt->session->current_stmt = save_curr_stmt;
    if (sub_stmt != NULL) {
        sql_release_lob_info(sub_stmt);
        sql_release_resource(sub_stmt, OG_TRUE);
        sql_release_context(sub_stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t pl_bison_rewrite_trigger_fragment(sql_stmt_t *stmt, text_t *src, text_t *rewritten)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    source_location_t loc = { 0 };

    if (compiler == NULL) {
        *rewritten = *src;
        return OG_SUCCESS;
    }
    loc = compiler->line_loc;
    return plc_rewrite_trigger_variants(compiler, src, rewritten, loc, PLC_TRIGGER_REWRITE_AS_NAME);
}

static status_t get_valid_expr_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    source_location_t loc = { 0 };
    text_t rewritten_src;

    *expr = NULL;
    OG_RETURN_IFERR(pl_bison_rewrite_trigger_fragment(stmt, src, &rewritten_src));
    src = &rewritten_src;
    if (compiler != NULL) {
        loc = compiler->line_loc;
        OG_RETURN_IFERR(try_create_pl_var_expr_from_text(stmt, src, loc, expr));
        if (*expr != NULL) {
            return OG_SUCCESS;
        }
    }

    /*
     * DEFAULT is an internal raw-parser entry selector. It lets PL fragments
     * reuse the bison SQL expression grammar without depending on session-owned
     * legacy parser state.
     */
    return pl_bison_parse_fragment_tree(stmt, "DEFAULT ", src, "", PL_BISON_FRAGMENT_EXPR_LIST, (void **)expr);
}

static status_t get_valid_cond_tree(sql_stmt_t *stmt, text_t *src, cond_tree_t **cond)
{
    text_t rewritten_src;

    *cond = NULL;
    OG_RETURN_IFERR(pl_bison_rewrite_trigger_fragment(stmt, src, &rewritten_src));
    src = &rewritten_src;
    return pl_bison_parse_fragment_tree(stmt, "CHECK (", src, ")", PL_BISON_FRAGMENT_COND_TREE, (void **)cond);
}

static status_t get_valid_call_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr)
{
    text_t rewritten_src;

    *expr = NULL;
    OG_RETURN_IFERR(pl_bison_rewrite_trigger_fragment(stmt, src, &rewritten_src));
    src = &rewritten_src;
    /* PROCEDURE selects the SQL-bison entry for PL statement-level calls. */
    return pl_bison_parse_fragment_tree(stmt, "PROCEDURE ", src, "", PL_BISON_FRAGMENT_EXPR_TREE, (void **)expr);
}

static status_t read_return_sql_construct(sql_stmt_t *stmt, text_t *src, pl_line_return_t *line)
{
    return get_valid_expr_tree(stmt, src, &line->expr);
}

static status_t pl_bison_make_parse_text(sql_stmt_t *stmt, const char *prefix, text_t *body, const char *suffix,
    sql_text_t *sql_text)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    uint32 prefix_len = (uint32)strlen(prefix);
    uint32 suffix_len = (uint32)strlen(suffix);
    uint32 sql_len;
    char *sql_buf = NULL;

    if (prefix_len > OG_MAX_UINT32 - suffix_len ||
        body->len > OG_MAX_UINT32 - prefix_len - suffix_len) {
        OG_THROW_ERROR(ERR_SQL_TOO_LONG, body->len);
        return OG_ERROR;
    }
    sql_len = prefix_len + body->len + suffix_len;
    if (sql_len == OG_MAX_UINT32) {
        OG_THROW_ERROR(ERR_SQL_TOO_LONG, body->len);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_stack_alloc(stmt, sql_len + 1, (void **)&sql_buf));
    if (prefix_len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(sql_buf, sql_len + 1, prefix, prefix_len));
    }
    if (body->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(sql_buf + prefix_len, sql_len + 1 - prefix_len, body->str, body->len));
    }
    if (suffix_len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(sql_buf + prefix_len + body->len, sql_len + 1 - prefix_len - body->len,
            suffix, suffix_len));
    }
    sql_buf[sql_len] = '\0';

    sql_text->str = sql_buf;
    sql_text->len = sql_len;
    sql_text->loc.line = 1;
    sql_text->loc.column = 1;
    if (compiler != NULL) {
        sql_text->loc = compiler->line_loc;
    }
    sql_text->implicit = OG_FALSE;
    return OG_SUCCESS;
}

static bool32 pl_bison_assign_left_starts_with_colon(core_yyscan_t yyscanner, int start_offset)
{
    core_yy_extra_type *extra = &og_yyget_extra(yyscanner)->core_yy_extra;

    return (start_offset >= 0 && (uint32)start_offset < extra->scanbuflen &&
        extra->scanbuf[start_offset] == ':');
}

static status_t compile_assign_left_from_offsets(core_yyscan_t yyscanner, int start_offset, int end_offset,
    expr_node_t **left)
{
    text_t src;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

    if (start_offset < 0 || end_offset <= start_offset) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "invalid assignment target");
        return OG_ERROR;
    }

    src.str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + start_offset;
    src.len = (uint32)(end_offset - start_offset);
    return compile_assign_left_from_sql(stmt, &src, left);
}

static status_t compile_assign_left_from_sql(sql_stmt_t *stmt, text_t *src, expr_node_t **left)
{
    expr_tree_t *expr = NULL;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(get_valid_expr_tree(stmt, src, &expr));
    if (expr == NULL || expr->root == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "invalid assignment target");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_check_var_as_left(compiler, expr->root, expr->loc, NULL));
    *left = expr->root;
    return OG_SUCCESS;
}

static status_t parse_expr_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line)
{
    pl_compiler_t *compiler = stmt->pl_compiler;

    if (get_valid_expr_tree(stmt, src, &line->expr) == OG_SUCCESS) {
        if (plc_verify_setval(compiler, line->left, line->expr) != OG_SUCCESS) {
            line->expr = NULL;
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    cm_reset_error();
    line->expr = NULL;
    OG_RETURN_IFERR(get_valid_cond_tree(stmt, src, &line->cond));
    OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));

    return OG_SUCCESS;
}

static status_t parse_call_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line, source_location_t loc)
{
    expr_tree_t *call_expr = NULL;
    expr_node_t *proc = NULL;
    pl_compiler_t *compiler = stmt->pl_compiler;

    OG_RETURN_IFERR(get_valid_call_tree(stmt, src, &call_expr));

    proc = call_expr->root;
    proc->loc = loc;
    if (proc->type == EXPR_NODE_COLUMN) {
        OG_RETURN_IFERR(pl_bison_column_to_proc_node(stmt, proc));
    } else if (proc->type == EXPR_NODE_FUNC || proc->type == EXPR_NODE_USER_FUNC) {
        proc->type = EXPR_NODE_PROC;
    } else if (proc->type == EXPR_NODE_V_METHOD) {
        /* Collection methods such as x.delete(...) are verified by plc_compile_call. */
    } else if (proc->type != EXPR_NODE_PROC && proc->type != EXPR_NODE_USER_PROC) {
        OG_SRC_THROW_ERROR(proc->loc, ERR_PL_SYNTAX_ERROR_FMT, "an undefined procedure was called");
        return OG_ERROR;
    }

    return plc_compile_call(compiler, proc, line);
}

static void pl_bison_set_word_part(word_t *word, uint32 id, sql_text_t *text)
{
    word->ex_words[id].type = WORD_TYPE_VARIANT;
    word->ex_words[id].text = *text;
    word->ex_count++;
}

static status_t pl_bison_column_to_proc_node(sql_stmt_t *stmt, expr_node_t *proc)
{
    word_t word = { 0 };
    column_word_t *column = &proc->word.column;

    if (column->name.len == 0) {
        OG_SRC_THROW_ERROR(proc->loc, ERR_PL_SYNTAX_ERROR_FMT, "an undefined procedure was called");
        return OG_ERROR;
    }

    word.id = OG_INVALID_ID32;
    word.type = WORD_TYPE_VARIANT;
    word.ori_type = WORD_TYPE_VARIANT;
    word.loc = proc->loc;
    if (column->user.len != 0) {
        word.text = column->user;
        pl_bison_set_word_part(&word, 0, &column->table);
        pl_bison_set_word_part(&word, 1, &column->name);
    } else if (column->table.len != 0) {
        word.text = column->table;
        pl_bison_set_word_part(&word, 0, &column->name);
    } else {
        word.text = column->name;
    }

    OG_RETURN_IFERR(plc_prepare_noarg_call(&word));
    proc->type = EXPR_NODE_PROC;
    proc->argument = NULL;
    return sql_word_as_func(stmt, &word, &proc->word);
}

static expr_tree_t *current_case_selector(pl_compiler_t *compiler)
{
    for (int32 i = (int32)compiler->control_stack.depth - 1; i >= 0; i--) {
        pl_line_ctrl_t *line = compiler->control_stack.items[i].entry;
        if (line->type == LINE_CASE) {
            return ((pl_line_case_t *)line)->selector;
        }
        if (line->type == LINE_WHEN_CASE) {
            return ((pl_line_when_case_t *)line)->selector;
        }
        if (line->type == LINE_ELSE) {
            pl_line_else_t *else_line = (pl_line_else_t *)line;
            return ((pl_line_when_case_t *)else_line->if_line)->selector;
        }
    }
    return NULL;
}

static status_t compile_case_start(sql_stmt_t *stmt, text_t *selector_src, pl_line_case_t **case_line)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_case_t), LINE_CASE, (pl_line_ctrl_t **)case_line));
    if (selector_src->len == 0) {
        (*case_line)->selector = NULL;
    } else {
        OG_RETURN_IFERR(get_valid_expr_tree(stmt, selector_src, &(*case_line)->selector));
        OG_RETURN_IFERR(plc_verify_expr(compiler, (*case_line)->selector));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &(*case_line)->selector));
    }

    return plc_push_ctl(compiler, (pl_line_ctrl_t *)*case_line, &CM_NULL_TEXT);
}

static status_t compile_case_when(core_yyscan_t yyscanner, sql_stmt_t *stmt, text_t *cond_src,
    pl_line_when_case_t **when_line)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_line_ctrl_t *brother_line = NULL;
    expr_tree_t *selector = current_case_selector(compiler);

    if (compiler->control_stack.depth == 0) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_UNEXPECTED_FMT, "CASE WHEN");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_case_t), LINE_WHEN_CASE,
        (pl_line_ctrl_t **)when_line));
    if (selector == NULL) {
        OG_RETURN_IFERR(get_valid_cond_tree(stmt, cond_src, (cond_tree_t **)&(*when_line)->cond));
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)(*when_line)->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&(*when_line)->cond));
    } else {
        OG_RETURN_IFERR(get_valid_expr_tree(stmt, cond_src, (expr_tree_t **)&(*when_line)->cond));
        OG_RETURN_IFERR(plc_verify_expr(compiler, (expr_tree_t *)(*when_line)->cond));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, (expr_tree_t **)&(*when_line)->cond));
    }

    OG_RETURN_IFERR(plc_pop(compiler, PLSQL_YYLLOC(yyscanner)->loc, PBE_WHEN_CASE, &brother_line));
    (*when_line)->if_line = (brother_line->type == LINE_CASE) ? NULL : (pl_line_if_t *)brother_line;
    (*when_line)->t_line = NULL;
    (*when_line)->selector = selector;
    if (brother_line->type == LINE_WHEN_CASE) {
        ((pl_line_when_case_t *)brother_line)->f_line = (pl_line_ctrl_t *)*when_line;
    }
    return plc_push_ctl(compiler, (pl_line_ctrl_t *)*when_line, &CM_NULL_TEXT);
}

static status_t finish_case_stmt(pl_compiler_t *compiler, galist_t *when_lines, source_location_t loc)
{
    pl_line_when_case_t *end_case = NULL;
    pl_line_ctrl_t *brother_line = NULL;
    expr_tree_t *selector = current_case_selector(compiler);

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_case_t), LINE_END_CASE,
        (pl_line_ctrl_t **)&end_case));
    OG_RETURN_IFERR(plc_pop(compiler, loc, PBE_END_CASE, &brother_line));
    if (brother_line->type == LINE_WHEN_CASE) {
        ((pl_line_when_case_t *)brother_line)->f_line = (pl_line_ctrl_t *)end_case;
    }
    end_case->selector = selector;

    for (uint32 i = 0; i < when_lines->count; i++) {
        pl_line_when_case_t *when_line = (pl_line_when_case_t *)cm_galist_get(when_lines, i);
        when_line->next = (pl_line_ctrl_t *)end_case;
    }
    return OG_SUCCESS;
}

static status_t compile_exception_start(pl_compiler_t *compiler, source_location_t loc,
    pl_line_except_t **except_line)
{
    pl_line_begin_t *begin_line = NULL;
    text_t block_name = CM_NULL_TEXT;

    for (int32 i = (int32)compiler->stack.depth - 1; i >= 0; i--) {
        if (compiler->stack.items[i].entry->type == LINE_BEGIN) {
            begin_line = (pl_line_begin_t *)compiler->stack.items[i].entry;
            break;
        }
    }
    if (begin_line == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_UNEXPECTED_FMT, "symbol exception");
        return OG_ERROR;
    }
    if (begin_line->except != NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "exception has existed in this \"begin-exception-end\"");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_except_t), LINE_EXCEPTION,
        (pl_line_ctrl_t **)except_line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &(*except_line)->excpts));
    begin_line->except = (pl_line_ctrl_t *)*except_line;
    return plc_push(compiler, (pl_line_ctrl_t *)*except_line, &block_name);
}

static status_t compile_exception_choice(pl_compiler_t *compiler, const char *name, source_location_t loc,
    void **choice)
{
    word_t word;
    plv_decl_t *decl = NULL;
    pl_bison_exception_choice_t *item = NULL;

    init_word_from_name(&word, name, loc);
    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, &word));
    plc_find_decl_ex(compiler, &word, PLV_EXCPT, NULL, &decl);

    OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(pl_bison_exception_choice_t), (void **)&item));
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, (text_t *)&word.text, &item->name.value));
    item->name.loc = loc;
    OG_RETURN_IFERR(plc_compile_exception_set_except(decl, &word, &item->except));
    *choice = item;
    return OG_SUCCESS;
}

static status_t compile_exception_when(core_yyscan_t yyscanner, sql_stmt_t *stmt, galist_t *choices,
    pl_line_when_t **when_line)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_line_begin_t *begin_line = NULL;

    for (int32 i = (int32)compiler->stack.depth - 1; i >= 0; i--) {
        if (compiler->stack.items[i].entry->type == LINE_BEGIN) {
            begin_line = (pl_line_begin_t *)compiler->stack.items[i].entry;
            break;
        }
    }

    if (begin_line == NULL || begin_line->except == NULL) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_UNEXPECTED_FMT, "WHEN");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_t), LINE_WHEN, (pl_line_ctrl_t **)when_line));
    cm_galist_init(&(*when_line)->excepts, compiler->entity, pl_alloc_mem);

    for (uint32 i = 0; i < choices->count; i++) {
        pl_bison_exception_choice_t *choice = (pl_bison_exception_choice_t *)cm_galist_get(choices, i);
        if (plc_find_line_except(compiler, *when_line, &choice->except, &choice->name) == OG_SUCCESS ||
            plc_check_except_exists(compiler, ((pl_line_except_t *)begin_line->except)->excpts, &choice->except,
                &choice->name) == OG_SUCCESS) {
            return OG_ERROR;
        }
        if (choice->except.is_userdef == OG_FALSE && choice->except.error_code == OTHERS &&
            (*when_line)->excepts.count > 0) {
            OG_SRC_THROW_ERROR(choice->name.loc, ERR_PL_SYNTAX_ERROR_FMT,
                "no choices may appear with choice OTHERS in an exception handler");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(cm_galist_insert(&(*when_line)->excepts, &choice->except));
    }

    return cm_galist_insert(((pl_line_except_t *)begin_line->except)->excpts, *when_line);
}

static status_t finish_exception_when(pl_compiler_t *compiler)
{
    pl_line_ctrl_t *line_end = NULL;
    return plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_WHEN, &line_end);
}

static status_t finish_exception_section(pl_compiler_t *compiler, source_location_t loc)
{
    pl_line_ctrl_t *except_end = NULL;
    pl_line_ctrl_t *pop_line = NULL;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_EXCEPTION, &except_end));
    OG_RETURN_IFERR(plc_pop(compiler, loc, PBE_END_EXCEPTION, &pop_line));
    ((pl_line_except_t *)pop_line)->end = except_end;
    return OG_SUCCESS;
}

static status_t compile_dynamic_sql_expr(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr)
{
    return get_valid_expr_tree(stmt, src, expr);
}

static bool32 pl_bison_is_ident_start_char(char c)
{
    unsigned char ch = (unsigned char)c;

    return (bool32)(ch >= 0x80 || CM_IS_LETER(c) || c == '_' || c == '#');
}

static bool32 pl_bison_is_ident_char(char c)
{
    return (bool32)(pl_bison_is_ident_start_char(c) || CM_IS_DIGIT(c) || c == '$');
}

static bool32 pl_bison_is_ident_text(const char *str, uint32 len)
{
    if (str == NULL || len == 0 || !pl_bison_is_ident_start_char(str[0])) {
        return OG_FALSE;
    }
    for (uint32 i = 0; i < len; i++) {
        if (!pl_bison_is_ident_char(str[i])) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 pl_bison_match_word_at(text_t *src, uint32 pos, const char *word)
{
    uint32 word_len = (uint32)strlen(word);

    if (pos + word_len > src->len) {
        return OG_FALSE;
    }
    if (pos > 0 && pl_bison_is_ident_char(src->str[pos - 1])) {
        return OG_FALSE;
    }
    if (pos + word_len < src->len && pl_bison_is_ident_char(src->str[pos + word_len])) {
        return OG_FALSE;
    }
    return (cm_strcmpni(src->str + pos, word, word_len) == 0);
}

static void pl_bison_skip_quoted_text(text_t *src, uint32 *pos)
{
    char quote = src->str[*pos];

    (*pos)++;
    while (*pos < src->len) {
        if (src->str[*pos] == quote) {
            if (quote == '\'' && *pos + 1 < src->len && src->str[*pos + 1] == quote) {
                *pos += 2;
                continue;
            }
            (*pos)++;
            return;
        }
        (*pos)++;
    }
}

static void pl_bison_skip_comment(text_t *src, uint32 *pos)
{
    if (*pos + 1 >= src->len) {
        return;
    }
    if (src->str[*pos] == '-' && src->str[*pos + 1] == '-') {
        *pos += 2;
        while (*pos < src->len && src->str[*pos] != '\n') {
            (*pos)++;
        }
        return;
    }
    if (src->str[*pos] == '/' && src->str[*pos + 1] == '*') {
        *pos += 2;
        while (*pos + 1 < src->len) {
            if (src->str[*pos] == '*' && src->str[*pos + 1] == '/') {
                *pos += 2;
                return;
            }
            (*pos)++;
        }
    }
}

static bool32 pl_bison_next_word_is(text_t *src, uint32 *pos, const char *word)
{
    while (*pos < src->len && cm_is_space((int)src->str[*pos])) {
        (*pos)++;
    }
    if (!pl_bison_match_word_at(src, *pos, word)) {
        return OG_FALSE;
    }
    *pos += (uint32)strlen(word);
    return OG_TRUE;
}

static bool32 pl_bison_find_top_word(text_t *src, const char *word, uint32 start, uint32 *pos)
{
    int32 depth = 0;

    for (uint32 i = start; i < src->len;) {
        if (src->str[i] == '\'' || src->str[i] == '"' || src->str[i] == '`') {
            pl_bison_skip_quoted_text(src, &i);
            continue;
        }
        if (i + 1 < src->len &&
            ((src->str[i] == '-' && src->str[i + 1] == '-') || (src->str[i] == '/' && src->str[i + 1] == '*'))) {
            pl_bison_skip_comment(src, &i);
            continue;
        }
        if (src->str[i] == '(') {
            depth++;
            i++;
            continue;
        }
        if (src->str[i] == ')') {
            if (depth > 0) {
                depth--;
            }
            i++;
            continue;
        }
        if (depth == 0 && pl_bison_match_word_at(src, i, word)) {
            *pos = i;
            return OG_TRUE;
        }
        i++;
    }
    return OG_FALSE;
}

static key_wid_t pl_bison_leading_sql_keyword(text_t *src, key_wid_t default_key)
{
    text_t trimmed = *src;

    cm_trim_text(&trimmed);
    if (pl_bison_match_word_at(&trimmed, 0, "select")) {
        return KEY_WORD_SELECT;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "with")) {
        return KEY_WORD_WITH;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "insert")) {
        return KEY_WORD_INSERT;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "update")) {
        return KEY_WORD_UPDATE;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "delete")) {
        return KEY_WORD_DELETE;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "merge")) {
        return KEY_WORD_MERGE;
    }
    if (pl_bison_match_word_at(&trimmed, 0, "replace")) {
        return KEY_WORD_REPLACE;
    }
    return default_key;
}

static status_t pl_bison_check_single_into_target(pl_into_t *into, source_location_t loc)
{
    expr_node_t *node = NULL;

    into->into_type = INTO_AS_VALUE;
    if (into->output->count != 1) {
        return OG_SUCCESS;
    }

    node = (expr_node_t *)cm_galist_get(into->output, 0);
    if (NODE_DATATYPE(node) == OG_TYPE_RECORD) {
        into->into_type = INTO_AS_REC;
    }
    if (NODE_DATATYPE(node) == OG_TYPE_OBJECT) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
            "type mismatch found at OBJECT type between anonymous record and INTO variables");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t pl_bison_compile_into_target(sql_stmt_t *stmt, text_t *src, pl_into_t *into, source_location_t loc)
{
    expr_node_t *node = NULL;

    cm_trim_text(src);
    if (src->len == 0) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "identifier", "EOF");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(compile_assign_left_from_sql(stmt, src, &node));
    return compile_into_var_list((pl_compiler_t *)stmt->pl_compiler, into->output, node, loc);
}

static status_t pl_bison_check_bulk_into_target(pl_into_t *into, uint8 *attr_type, source_location_t loc)
{
    expr_node_t *node = NULL;
    var_address_pair_t *pair = NULL;
    plv_decl_t *decl = NULL;

    node = (expr_node_t *)cm_galist_get(into->output, into->output->count - 1);
    pair = sql_get_last_addr_pair(node);
    decl = (pair == NULL || pair->type != UDT_STACK_ADDR || pair->stack == NULL) ? NULL : pair->stack->decl;
    if (decl == NULL || decl->type != PLV_COLLECTION || decl->collection->attr_type == UDT_COLLECTION) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
            "cannot mix between single row and multi-row (BULK) in INTO list");
        return OG_ERROR;
    }
    if (into->output->count == 1) {
        *attr_type = decl->collection->attr_type;
    }

    return OG_SUCCESS;
}

static status_t pl_bison_check_bulk_into_targets(pl_into_t *into, uint8 attr_type, source_location_t loc)
{
    into->into_type = INTO_AS_COLL;
    if (into->output->count != 1) {
        return OG_SUCCESS;
    }

    if (attr_type == UDT_RECORD) {
        into->into_type = INTO_AS_COLL_REC;
    } else if (attr_type == UDT_OBJECT) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
            "type mismatch found at OBJECT type between anonymous record and INTO variables");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t pl_bison_compile_into_targets(sql_stmt_t *stmt, text_t *src, pl_into_t *into, bool32 is_bulk,
    source_location_t loc)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    uint32 start = 0;
    int32 depth = 0;
    uint8 attr_type = 0;

    OG_RETURN_IFERR(plc_init_galist(compiler, &into->output));
    into->is_bulk = is_bulk;
    into->prefetch_rows = is_bulk ? OG_INVALID_ID32 : INTO_VALUES_PREFETCH_COUNT;

    for (uint32 i = 0; i <= src->len; i++) {
        if (i < src->len && (src->str[i] == '\'' || src->str[i] == '"' || src->str[i] == '`')) {
            pl_bison_skip_quoted_text(src, &i);
            i--;
            continue;
        }
        if (i + 1 < src->len &&
            ((src->str[i] == '-' && src->str[i + 1] == '-') || (src->str[i] == '/' && src->str[i + 1] == '*'))) {
            pl_bison_skip_comment(src, &i);
            i--;
            continue;
        }
        if (i < src->len && src->str[i] == '(') {
            depth++;
            continue;
        }
        if (i < src->len && src->str[i] == ')') {
            if (depth > 0) {
                depth--;
            }
            continue;
        }
        if (i == src->len || (depth == 0 && src->str[i] == ',')) {
            text_t item = {
                .str = src->str + start,
                .len = i - start
            };
            OG_RETURN_IFERR(pl_bison_compile_into_target(stmt, &item, into, loc));
            if (is_bulk) {
                OG_RETURN_IFERR(pl_bison_check_bulk_into_target(into, &attr_type, loc));
            }
            start = i + 1;
        }
    }

    if (is_bulk) {
        return pl_bison_check_bulk_into_targets(into, attr_type, loc);
    }
    return pl_bison_check_single_into_target(into, loc);
}

static status_t pl_bison_sql_without_range(sql_stmt_t *stmt, text_t *src, uint32 begin, uint32 end, text_t *sql)
{
    uint32 new_len;
    char *buf = NULL;

    if (begin >= end || end > src->len) {
        *sql = *src;
        cm_trim_text(sql);
        return OG_SUCCESS;
    }

    new_len = src->len - (end - begin);
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, new_len + 1, (void **)&buf));
    if (begin > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, new_len + 1, src->str, begin));
    }
    if (end < src->len) {
        MEMS_RETURN_IFERR(memcpy_s(buf + begin, new_len + 1 - begin, src->str + end, src->len - end));
    }
    buf[new_len] = '\0';
    sql->str = buf;
    sql->len = new_len;
    cm_trim_text(sql);
    return OG_SUCCESS;
}

static bool32 pl_bison_find_select_into(text_t *src, uint32 *clause_start, uint32 *target_start,
    uint32 *target_end, bool32 *is_bulk)
{
    uint32 from_pos;
    uint32 into_pos;
    uint32 bulk_pos;
    uint32 probe;

    if (pl_bison_find_top_word(src, "from", 0, &from_pos) &&
        (!pl_bison_find_top_word(src, "into", 0, &into_pos) || from_pos < into_pos)) {
        return OG_FALSE;
    }

    if (pl_bison_find_top_word(src, "bulk", 0, &bulk_pos)) {
        probe = bulk_pos + (uint32)strlen("bulk");
        if (pl_bison_next_word_is(src, &probe, "collect") && pl_bison_next_word_is(src, &probe, "into") &&
            pl_bison_find_top_word(src, "from", probe, &from_pos)) {
            *clause_start = bulk_pos;
            *target_start = probe;
            *target_end = from_pos;
            *is_bulk = OG_TRUE;
            return OG_TRUE;
        }
    }

    if (!pl_bison_find_top_word(src, "into", 0, &into_pos)) {
        return OG_FALSE;
    }
    if (!pl_bison_find_top_word(src, "from", into_pos + (uint32)strlen("into"), &from_pos)) {
        return OG_FALSE;
    }

    *clause_start = into_pos;
    *target_start = into_pos + (uint32)strlen("into");
    *target_end = from_pos;
    *is_bulk = OG_FALSE;
    return OG_TRUE;
}

static bool32 pl_bison_find_returning_into(text_t *src, uint32 *clause_start, uint32 *target_start,
    uint32 *target_end, bool32 *is_bulk)
{
    uint32 return_pos;
    uint32 into_pos;
    uint32 bulk_pos;
    uint32 probe;

    if (!pl_bison_find_top_word(src, "returning", 0, &return_pos) &&
        !pl_bison_find_top_word(src, "return", 0, &return_pos)) {
        return OG_FALSE;
    }

    if (pl_bison_find_top_word(src, "bulk", return_pos, &bulk_pos)) {
        probe = bulk_pos + (uint32)strlen("bulk");
        if (pl_bison_next_word_is(src, &probe, "collect") && pl_bison_next_word_is(src, &probe, "into")) {
            *clause_start = bulk_pos;
            *target_start = probe;
            *target_end = src->len;
            *is_bulk = OG_TRUE;
            return OG_TRUE;
        }
    }

    if (!pl_bison_find_top_word(src, "into", return_pos, &into_pos)) {
        return OG_FALSE;
    }
    *clause_start = into_pos;
    *target_start = into_pos + (uint32)strlen("into");
    *target_end = src->len;
    *is_bulk = OG_FALSE;
    return OG_TRUE;
}

static status_t pl_bison_prepare_static_sql(sql_stmt_t *stmt, text_t *src, key_wid_t key_wid, pl_into_t *into,
    source_location_t loc, text_t *sql)
{
    uint32 clause_start;
    uint32 target_start;
    uint32 target_end;
    bool32 is_bulk = OG_FALSE;
    text_t target;

    key_wid = pl_bison_leading_sql_keyword(src, key_wid);
    if (into != NULL && (key_wid == KEY_WORD_SELECT || key_wid == KEY_WORD_WITH) &&
        pl_bison_find_select_into(src, &clause_start, &target_start, &target_end, &is_bulk)) {
        target.str = src->str + target_start;
        target.len = target_end - target_start;
        OG_RETURN_IFERR(pl_bison_compile_into_targets(stmt, &target, into, is_bulk, loc));
        return pl_bison_sql_without_range(stmt, src, clause_start, target_end, sql);
    }

    if (into != NULL &&
        (key_wid == KEY_WORD_INSERT || key_wid == KEY_WORD_UPDATE || key_wid == KEY_WORD_DELETE) &&
        pl_bison_find_returning_into(src, &clause_start, &target_start, &target_end, &is_bulk)) {
        target.str = src->str + target_start;
        target.len = target_end - target_start;
        OG_RETURN_IFERR(pl_bison_compile_into_targets(stmt, &target, into, is_bulk, loc));
        return pl_bison_sql_without_range(stmt, src, clause_start, target_end, sql);
    }

    *sql = *src;
    cm_trim_text(sql);
    return OG_SUCCESS;
}

static status_t compile_static_sql_context(sql_stmt_t *stmt, text_t *src, key_wid_t key_wid, source_location_t loc,
    galist_t *input, pl_into_t *into, sql_context_t **context)
{
    text_t sql = { 0 };
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    if (pl_bison_prepare_static_sql(stmt, src, key_wid, into, loc, &sql) != OG_SUCCESS) {
        pl_check_and_set_loc(loc);
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    key_wid = pl_bison_leading_sql_keyword(&sql, key_wid);
    pl_bison_static_sql_arg_t arg = { context, &sql, key_wid, &loc, &entity->sqls, input };
    if (pl_bison_parse_static_sql(stmt, &arg) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    if (!(*context)->cacheable) {
        pl_entity_uncacheable(compiler->entity);
    }
    return OG_SUCCESS;
}

static void set_cursor_args_visible(plv_decl_t *decl, bool32 visible)
{
    if (decl->cursor.ogx->args == NULL) {
        return;
    }

    for (uint32 i = 0; i < decl->cursor.ogx->args->count; i++) {
        plv_decl_t *arg = (plv_decl_t *)cm_galist_get(decl->cursor.ogx->args, i);
        arg->arg_type = visible ? PLV_NORMAL_ARG : PLV_CURSOR_ARG;
    }
}

static status_t compile_static_cursor_sql_context(pl_compiler_t *compiler, text_t *src, source_location_t loc,
    plv_decl_t *decl)
{
    text_t sql = { 0 };
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    key_wid_t key_wid;
    status_t status;

    if (pl_bison_prepare_static_sql(stmt, src, KEY_WORD_SELECT, NULL, loc, &sql) != OG_SUCCESS) {
        pl_check_and_set_loc(loc);
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    key_wid = pl_bison_leading_sql_keyword(&sql, KEY_WORD_SELECT);
    /*
     * Cursor parameters are hidden from the surrounding PL block, but they must be visible while compiling
     * the cursor query itself.
     */
    set_cursor_args_visible(decl, OG_TRUE);
    pl_bison_static_sql_arg_t arg = {
        &decl->cursor.ogx->context, &sql, key_wid, &loc, &entity->sqls, decl->cursor.input
    };
    status = pl_bison_parse_static_sql(stmt, &arg);
    set_cursor_args_visible(decl, OG_FALSE);
    if (status != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    if (!decl->cursor.ogx->context->cacheable) {
        pl_entity_uncacheable(compiler->entity);
    }
    return sql_append_references(&entity->ref_list, decl->cursor.ogx->context);
}

static status_t compile_static_sql_line(sql_stmt_t *stmt, text_t *src, key_wid_t key_wid, source_location_t loc,
    pl_line_sql_t *line)
{
    pl_compiler_t *compiler = stmt->pl_compiler;
    pl_entity_t *entity = compiler->entity;

    line->is_dynamic_sql = OG_FALSE;
    OG_RETURN_IFERR(compile_static_sql_context(stmt, src, key_wid, loc, line->input, &line->into, &line->context));
    if (IS_DML_INTO_PL_VAR(line->context->type) && line->context->rs_columns != NULL) {
        OG_RETURN_IFERR(plc_verify_into_clause(line->context, &line->into, line->ctrl.loc));
    }
    return sql_append_references(&entity->ref_list, line->context);
}

static status_t compile_execute_into_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler, pl_into_t *into,
    int *endtoken)
{
    expr_node_t *node = NULL;
    int tok;

    into->is_bulk = OG_FALSE;
    OG_RETURN_IFERR(plc_init_galist(compiler, &into->output));

    for (;;) {
        tok = PLSQL_YYLEX(yyscanner);
        if (tok != T_DATUM) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "identifier", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }

        node = PLSQL_YYLVAL(yyscanner)->node;
        OG_RETURN_IFERR(compile_into_var_list(compiler, into->output, node, PLSQL_YYLLOC(yyscanner)->loc));

        tok = PLSQL_YYLEX(yyscanner);
        if (tok != ',') {
            break;
        }
    }

    into->into_type = INTO_AS_VALUE;
    if (into->output->count == 1) {
        node = (expr_node_t *)cm_galist_get(into->output, 0);
        if (NODE_DATATYPE(node) == OG_TYPE_RECORD) {
            into->into_type = INTO_AS_REC;
        } else if (NODE_DATATYPE(node) == OG_TYPE_OBJECT) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "type mismatch found at OBJECT type between anonymous record and INTO variables");
            return OG_ERROR;
        }
    }

    *endtoken = tok;
    return OG_SUCCESS;
}

static status_t compile_execute_bulk_into_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler, pl_into_t *into,
    int *endtoken)
{
    expr_node_t *node = NULL;
    var_address_pair_t *pair = NULL;
    plv_decl_t *decl = NULL;
    uint8 attr_type = 0;
    int tok;

    tok = PLSQL_YYLEX(yyscanner);
    if (tok != K_COLLECT) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "COLLECT", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    tok = PLSQL_YYLEX(yyscanner);
    if (tok != K_INTO) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "INTO", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    into->is_bulk = OG_TRUE;
    into->prefetch_rows = OG_INVALID_ID32;
    OG_RETURN_IFERR(plc_init_galist(compiler, &into->output));

    for (;;) {
        tok = PLSQL_YYLEX(yyscanner);
        if (tok != T_DATUM) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "identifier", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }

        node = PLSQL_YYLVAL(yyscanner)->node;
        pair = sql_get_last_addr_pair(node);
        decl = (pair == NULL || pair->type != UDT_STACK_ADDR || pair->stack == NULL) ? NULL : pair->stack->decl;
        if (decl == NULL || decl->type != PLV_COLLECTION) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "cannot mix between single row and multi-row (BULK) in INTO list");
            return OG_ERROR;
        }
        if (decl->collection->attr_type == UDT_COLLECTION) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "cannot mix between single row and multi-row (BULK) in INTO list");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(compile_into_var_list(compiler, into->output, node, PLSQL_YYLLOC(yyscanner)->loc));
        if (into->output->count == 1) {
            attr_type = decl->collection->attr_type;
        }

        tok = PLSQL_YYLEX(yyscanner);
        if (tok != ',') {
            break;
        }
    }

    into->into_type = INTO_AS_COLL;
    if (into->output->count == 1) {
        if (attr_type == UDT_RECORD) {
            into->into_type = INTO_AS_COLL_REC;
        } else if (attr_type == UDT_OBJECT) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "type mismatch found at OBJECT type between anonymous record and INTO variables");
            return OG_ERROR;
        }
    }

    *endtoken = tok;
    return OG_SUCCESS;
}

static status_t verify_execute_using_expr(pl_compiler_t *compiler, expr_tree_t *expr)
{
    uint32 excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID |
        SQL_EXCL_DEFAULT | SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID |
        SQL_EXCL_METH_PROC | SQL_EXCL_PL_PROC;

    return plc_verify_expr_node(compiler, expr->root, NULL, excl_flags);
}

static status_t read_execute_using_expr(core_yyscan_t yyscanner, int first_token, text_t **expr_src, int *endtoken)
{
    int expr_start;

    if (first_token == K_PRIOR) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
        return OG_ERROR;
    }

    expr_start = PLSQL_YYLLOC(yyscanner)->offset;
    plsql_push_back_token(first_token, yyscanner);
    *expr_src = read_sql_construct_from(expr_start, ',', ';', 0, 0, 0, 0, yyscanner, endtoken);
    return OG_SUCCESS;
}

static status_t compile_execute_using_item(core_yyscan_t yyscanner, pl_compiler_t *compiler,
    pl_line_execute_t *line, int *endtoken)
{
    plv_direction_t dir = PLV_DIR_IN;
    pl_using_expr_t *using_expr = NULL;
    expr_tree_t *expr = NULL;
    text_t *expr_src = NULL;
    int tok = PLSQL_YYLEX(yyscanner);

    if (tok == K_IN) {
        tok = PLSQL_YYLEX(yyscanner);
        if (tok == K_OUT) {
            dir = PLV_DIR_INOUT;
            tok = PLSQL_YYLEX(yyscanner);
        } else {
            dir = PLV_DIR_IN;
        }
    } else if (tok == K_OUT) {
        dir = PLV_DIR_OUT;
        tok = PLSQL_YYLEX(yyscanner);
    }

    if (tok == ';' || tok == ',' || tok == YYEOF) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "expression", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(read_execute_using_expr(yyscanner, tok, &expr_src, endtoken));
    OG_RETURN_IFERR(get_valid_expr_tree(compiler->stmt, expr_src, &expr));
    OG_RETURN_IFERR(verify_execute_using_expr(compiler, expr));
    if (dir == PLV_DIR_OUT || dir == PLV_DIR_INOUT) {
        OG_RETURN_IFERR(plc_verify_out_expr(compiler, expr, NULL));
        OG_RETURN_IFERR(plc_verify_using_out_cursor(compiler, expr));
    }
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
    OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(pl_using_expr_t), (void **)&using_expr));
    using_expr->expr = expr;
    using_expr->dir = dir;
    return cm_galist_insert(line->using_exprs, using_expr);
}

static status_t compile_execute_using_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler,
    pl_line_execute_t *line, int *endtoken)
{
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->using_exprs));

    for (;;) {
        OG_RETURN_IFERR(compile_execute_using_item(yyscanner, compiler, line, endtoken));
        if (*endtoken != ',') {
            return OG_SUCCESS;
        }
    }
}

static status_t compile_execute_immediate_stmt(core_yyscan_t yyscanner, source_location_t loc)
{
    pl_line_execute_t *line = NULL;
    text_t *dynamic_sql_src = NULL;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    int endtoken = 0;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_execute_t), LINE_EXECUTE, (pl_line_ctrl_t **)&line));
    dynamic_sql_src = read_sql_construct(K_INTO, K_BULK, K_USING, ';', 0, 0, yyscanner, &endtoken);
    OG_RETURN_IFERR(compile_dynamic_sql_expr(stmt, dynamic_sql_src, &line->dynamic_sql));
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->dynamic_sql));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->dynamic_sql));

    if (endtoken == K_INTO) {
        OG_RETURN_IFERR(compile_execute_into_clause(yyscanner, compiler, &line->into, &endtoken));
        line->into.prefetch_rows = INTO_VALUES_PREFETCH_COUNT;
    } else if (endtoken == K_BULK) {
        OG_RETURN_IFERR(compile_execute_bulk_into_clause(yyscanner, compiler, &line->into, &endtoken));
    }

    if (endtoken == K_USING) {
        OG_RETURN_IFERR(compile_execute_using_clause(yyscanner, compiler, line, &endtoken));
    }

    if (endtoken != ';') {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static bool32 pl_bison_type_is_sys_refcursor(type_word_t *type)
{
    return (type != NULL && type->typemode == NULL && type->str != NULL &&
        (cm_strcmpi(type->str, "sys_refcursor") == 0 || cm_strcmpi(type->str, "refcursor") == 0));
}

static status_t init_sys_refcursor_decl(pl_compiler_t *compiler, plv_decl_t *decl, source_location_t loc)
{
    decl->loc = loc;
    decl->type = PLV_CUR;
    OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ogx));
    decl->cursor.sql.value = CM_NULL_TEXT;
    decl->cursor.sql.loc = loc;
    decl->cursor.sql.implicit = OG_FALSE;
    decl->cursor.ogx->is_sysref = (bool8)OG_TRUE;
    decl->cursor.ogx->is_err = (bool8)OG_FALSE;
    decl->cursor.ogx->args = NULL;
    decl->cursor.ogx->context = NULL;
    decl->cursor.input = NULL;
    decl->cursor.record = NULL;
    return OG_SUCCESS;
}

static status_t compile_sys_refcursor_decl(pl_compiler_t *compiler, char *name, source_location_t loc)
{
    plv_decl_t *decl = NULL;
    text_t name_text;

    OG_RETURN_IFERR(cm_galist_new(compiler->decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = (uint16)(compiler->decls->count - 1);
    cm_str2text(name, &name_text);
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, &name_text, &decl->name));
    return init_sys_refcursor_decl(compiler, decl, loc);
}

static status_t check_duplicate_cursor_arg(galist_t *args, const text_t *name, source_location_t loc)
{
    for (uint32 i = 0; i < args->count; i++) {
        plv_decl_t *arg = (plv_decl_t *)cm_galist_get(args, i);
        if (cm_text_equal_ins(&arg->name, name)) {
            OG_SRC_THROW_ERROR(loc, ERR_PL_DUP_ARG_FMT, T2S(name), "cursor");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t compile_cursor_arg_decl(pl_compiler_t *compiler, plv_decl_t *cursor, galist_t *decls,
    const char *name, type_word_t *type, expr_tree_t *def_expr, source_location_t loc)
{
    plv_decl_t *decl = NULL;
    text_t arg_name;

    cm_str2text((char *)name, &arg_name);
    OG_RETURN_IFERR(check_duplicate_cursor_arg(cursor->cursor.ogx->args, &arg_name, loc));
    OG_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = (uint16)(decls->count - 1);
    decl->loc = loc;
    decl->drct = PLV_DIR_IN;
    decl->type = PLV_VAR;
    decl->arg_type = PLV_CURSOR_ARG;
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, &arg_name, &decl->name));
    OG_RETURN_IFERR(plc_bison_compile_type(compiler, PLC_PMODE(decl->drct), &decl->variant.type, type));
    OG_RETURN_IFERR(plc_check_decl_datatype(compiler, decl, OG_TRUE));
    if (OG_IS_VARLEN_TYPE(decl->variant.type.datatype)) {
        decl->variant.type.size = OG_STRING_BUFFER_SIZE;
    }
    OG_RETURN_IFERR(plc_bison_compile_default_def(compiler, decl, def_expr));
    return cm_galist_insert(cursor->cursor.ogx->args, decl);
}

static status_t compile_cursor_decl(pl_compiler_t *compiler, char *name, galist_t *args, text_t *query,
    source_location_t loc)
{
    plv_decl_t *decl = NULL;
    text_t name_text;

    OG_RETURN_IFERR(cm_galist_new(compiler->decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = (uint16)(compiler->decls->count - 1);
    decl->loc = loc;
    decl->type = PLV_CUR;
    cm_str2text(name, &name_text);
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, &name_text, &decl->name));
    OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ogx));
    decl->cursor.ogx->is_sysref = (bool8)OG_FALSE;
    decl->cursor.ogx->is_err = (bool8)OG_FALSE;
    decl->cursor.ogx->args = NULL;
    decl->cursor.ogx->context = NULL;
    decl->cursor.sql.value = (query == NULL) ? CM_NULL_TEXT : *query;
    OG_RETURN_IFERR(plc_init_galist(compiler, &decl->cursor.input));
    if (args != NULL) {
        OG_RETURN_IFERR(plc_init_galist(compiler, &decl->cursor.ogx->args));
        for (uint32 i = 0; i < args->count; i++) {
            pl_bison_cursor_arg_t *arg = (pl_bison_cursor_arg_t *)cm_galist_get(args, i);
            OG_RETURN_IFERR(compile_cursor_arg_decl(compiler, decl, compiler->decls, arg->name, arg->type,
                arg->def_expr, arg->loc));
        }
    }

    if (query == NULL) {
        decl->cursor.ogx->context = NULL;
        return OG_SUCCESS;
    }

    return compile_static_cursor_sql_context(compiler, query, loc, decl);
}

static bool32 token_is_name(int token)
{
    return token == T_WORD || (token >= K_ABSOLUTE && token <= K_WITH);
}

static char *token_name_text(core_yyscan_t yyscanner, int token)
{
    if (token == T_WORD) {
        return PLSQL_YYLVAL(yyscanner)->word.ident;
    }
    return pl_token_text(token, PLSQL_YYLVAL(yyscanner));
}

static status_t make_text_from_offsets(core_yyscan_t yyscanner, int start_offset, int end_offset, text_t **src)
{
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

    OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(text_t), (void **)src));
    (*src)->str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + start_offset;
    (*src)->len = (uint32)(end_offset - start_offset);
    return OG_SUCCESS;
}

static status_t compile_into_var_list(pl_compiler_t *compiler, galist_t *output, expr_node_t *node,
    source_location_t loc)
{
    var_address_t *addr = NULL;
    var_address_pair_t *pair = NULL;
    plv_decl_t *decl = NULL;

    OG_RETURN_IFERR(plc_check_var_as_left(compiler, node, loc, NULL));
    addr = NODE_VALUE_PTR(var_address_t, node);
    if (addr == NULL || addr->pairs == NULL || addr->pairs->count == 0) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return OG_ERROR;
    }

    pair = (var_address_pair_t *)cm_galist_get(addr->pairs, 0);
    if (pair == NULL || pair->type != UDT_STACK_ADDR || pair->stack == NULL || pair->stack->decl == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return OG_ERROR;
    }
    decl = pair->stack->decl;
    if (addr->pairs->count == 1 && decl->type != PLV_PARAM) {
        SET_FUNC_RETURN_TYPE(decl, node);
    }
    OG_RETURN_IFERR(plc_clone_expr_node(compiler, &node));
    return cm_galist_insert(output, node);
}

static status_t find_cursor_decl_by_node(pl_compiler_t *compiler, expr_node_t *node, source_location_t loc,
    plv_decl_t **decl)
{
    var_address_pair_t *pair = sql_get_last_addr_pair(node);

    if (pair == NULL || pair->type != UDT_STACK_ADDR || pair->stack->decl == NULL ||
        pair->stack->decl->type != PLV_CUR) {
        OG_SRC_THROW_ERROR(loc, ERR_INVALID_CURSOR);
        return OG_ERROR;
    }
    *decl = pair->stack->decl;
    return OG_SUCCESS;
}

static status_t compile_open_arg_expr(pl_compiler_t *compiler, galist_t *exprs, text_t *expr_src,
    const char *arg_name)
{
    expr_tree_t *expr = NULL;
    text_t name_text;

    OG_RETURN_IFERR(get_valid_expr_tree(compiler->stmt, expr_src, &expr));
    OG_RETURN_IFERR(plc_verify_expr(compiler, expr));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
    if (arg_name != NULL) {
        cm_str2text((char *)arg_name, &name_text);
        OG_RETURN_IFERR(pl_copy_text(compiler->entity, &name_text, &expr->arg_name));
    }
    return cm_galist_insert(exprs, expr);
}

static status_t compile_open_arg_list(core_yyscan_t yyscanner, pl_compiler_t *compiler, galist_t *exprs,
    int *endtoken)
{
    int tok = PLSQL_YYLEX(yyscanner);
    int next_tok;
    int expr_start;
    int delimiter_offset;
    char *arg_name = NULL;
    text_t *expr_src = NULL;

    if (tok == ')') {
        *endtoken = tok;
        return OG_SUCCESS;
    }

    for (;;) {
        arg_name = NULL;
        expr_start = PLSQL_YYLLOC(yyscanner)->offset;
        if (token_is_name(tok)) {
            char *first_name = token_name_text(yyscanner, tok);
            next_tok = PLSQL_YYLEX(yyscanner);
            if (next_tok == PARA_EQUALS) {
                arg_name = first_name;
                tok = PLSQL_YYLEX(yyscanner);
                if (tok == ',' || tok == ')' || tok == YYEOF) {
                    OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "expression", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
                    return OG_ERROR;
                }
                expr_start = PLSQL_YYLLOC(yyscanner)->offset;
                plsql_push_back_token(tok, yyscanner);
                expr_src = read_sql_construct_from(expr_start, ',', ')', 0, 0, 0, 0, yyscanner, endtoken);
            } else if (next_tok == ',' || next_tok == ')') {
                delimiter_offset = PLSQL_YYLLOC(yyscanner)->offset;
                *endtoken = next_tok;
                OG_RETURN_IFERR(make_text_from_offsets(yyscanner, expr_start, delimiter_offset, &expr_src));
            } else {
                plsql_push_back_token(next_tok, yyscanner);
                expr_src = read_sql_construct_from(expr_start, ',', ')', 0, 0, 0, 0, yyscanner, endtoken);
            }
        } else {
            plsql_push_back_token(tok, yyscanner);
            expr_src = read_sql_construct_from(expr_start, ',', ')', 0, 0, 0, 0, yyscanner, endtoken);
        }

        OG_RETURN_IFERR(compile_open_arg_expr(compiler, exprs, expr_src, arg_name));
        if (*endtoken == ')') {
            return OG_SUCCESS;
        }
        if (*endtoken != ',') {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "',' or ')'", pl_token_text(*endtoken, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }
        tok = PLSQL_YYLEX(yyscanner);
        if (tok == ')' || tok == YYEOF) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "expression", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }
    }
}

static status_t compile_open_cursor_args_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node,
    source_location_t loc)
{
    pl_line_open_t *line = NULL;
    plv_decl_t *decl = NULL;
    int endtoken = 0;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(find_cursor_decl_by_node(compiler, cursor_node, loc, &decl));
    if (decl->cursor.ogx->is_sysref || decl->cursor.ogx->context == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_open_t), LINE_OPEN, (pl_line_ctrl_t **)&line));
    line->vid = decl->vid;
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->exprs));
    OG_RETURN_IFERR(compile_open_arg_list(yyscanner, compiler, line->exprs, &endtoken));
    if (endtoken != ')') {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "')'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    if (line->exprs->count == 0) {
        line->exprs = NULL;
        return OG_SUCCESS;
    }
    return plc_verify_cursor_args(compiler, line->exprs, decl->cursor.ogx->args, loc);
}

static status_t compile_refcur_using_item(core_yyscan_t yyscanner, pl_compiler_t *compiler, galist_t *using_exprs,
    int *endtoken)
{
    expr_tree_t *expr = NULL;
    text_t *expr_src = NULL;
    int tok = PLSQL_YYLEX(yyscanner);

    if (tok == K_IN) {
        tok = PLSQL_YYLEX(yyscanner);
    }
    if (tok == K_OUT) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "OUT and IN/OUT modes cannot be opened in refcursor");
        return OG_ERROR;
    }
    if (tok == ',' || tok == ';' || tok == YYEOF) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "expression", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    expr_src = read_sql_construct_from(PLSQL_YYLLOC(yyscanner)->offset, ',', ';', 0, 0, 0, 0, yyscanner, endtoken);
    OG_RETURN_IFERR(get_valid_expr_tree(compiler->stmt, expr_src, &expr));
    OG_RETURN_IFERR(plc_verify_expr(compiler, expr));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
    return cm_galist_insert(using_exprs, expr);
}

static status_t compile_refcur_using_clause(core_yyscan_t yyscanner, pl_compiler_t *compiler,
    pl_line_open_t *line, int *endtoken)
{
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->using_exprs));
    for (;;) {
        OG_RETURN_IFERR(compile_refcur_using_item(yyscanner, compiler, line->using_exprs, endtoken));
        if (*endtoken != ',') {
            return OG_SUCCESS;
        }
    }
}

static status_t compile_open_for_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node, source_location_t loc)
{
    pl_line_open_t *line = NULL;
    plv_decl_t *decl = NULL;
    text_t *src = NULL;
    int endtoken = 0;
    int tok;
    source_location_t query_loc;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(find_cursor_decl_by_node(compiler, cursor_node, loc, &decl));
    if (!decl->cursor.ogx->is_sysref) {
        OG_SRC_THROW_ERROR(loc, ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_open_t), LINE_OPEN, (pl_line_ctrl_t **)&line));
    line->vid = decl->vid;
    tok = PLSQL_YYLEX(yyscanner);
    query_loc = PLSQL_YYLLOC(yyscanner)->loc;
    if (tok == K_SELECT) {
        src = read_sql_construct_from(PLSQL_YYLLOC(yyscanner)->offset, ';', 0, 0, 0, 0, 0, yyscanner, &endtoken);
        if (endtoken != ';') {
            OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }
        line->is_dynamic_sql = OG_FALSE;
        OG_RETURN_IFERR(plc_init_galist(compiler, &line->input));
        decl->cursor.input = line->input;
        if (compile_static_sql_context(stmt, src, KEY_WORD_SELECT, query_loc, line->input, NULL,
            &line->context) != OG_SUCCESS) {
            decl->cursor.input = NULL;
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_append_references(&((pl_entity_t *)compiler->entity)->ref_list, line->context));
        decl->cursor.input = NULL;
        return OG_SUCCESS;
    }

    if (tok == YYEOF) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "cursor query", "EOF");
        return OG_ERROR;
    }

    src = read_sql_construct_from(PLSQL_YYLLOC(yyscanner)->offset, K_USING, ';', 0, 0, 0, 0, yyscanner, &endtoken);
    line->is_dynamic_sql = OG_TRUE;
    OG_RETURN_IFERR(get_valid_expr_tree(stmt, src, &line->dynamic_sql));
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->dynamic_sql));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->dynamic_sql));
    if (endtoken == K_USING) {
        OG_RETURN_IFERR(compile_refcur_using_clause(yyscanner, compiler, line, &endtoken));
    }
    if (endtoken != ';') {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t compile_fetch_bulk_stmt(core_yyscan_t yyscanner, expr_node_t *cursor_node, source_location_t loc)
{
    pl_line_fetch_t *line = NULL;
    plv_decl_t *decl = NULL;
    int endtoken = 0;
    text_t *limit_src = NULL;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(find_cursor_decl_by_node(compiler, cursor_node, loc, &decl));
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_fetch_t), LINE_FETCH, (pl_line_ctrl_t **)&line));
    line->vid = decl->vid;
    OG_RETURN_IFERR(compile_execute_bulk_into_clause(yyscanner, compiler, &line->into, &endtoken));
    if (endtoken == K_LIMIT) {
        limit_src = read_sql_expression(';', yyscanner);
        OG_RETURN_IFERR(get_valid_expr_tree(stmt, limit_src, &line->into.limit));
        OG_RETURN_IFERR(plc_verify_limit_expr(compiler, line->into.limit));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->into.limit));
        endtoken = ';';
    }
    if (endtoken != ';') {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    if (decl->cursor.ogx->is_sysref == OG_FALSE && decl->cursor.ogx->context != NULL) {
        return plc_verify_into_clause(decl->cursor.ogx->context, &line->into, loc);
    }
    return OG_SUCCESS;
}

static status_t copy_context_rscols_to_record(pl_compiler_t *compiler, sql_context_t *sql_ctx, plv_record_t *record,
    source_location_t loc)
{
    for (uint32 col_id = 0; col_id < sql_ctx->rs_columns->count; col_id++) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(sql_ctx->rs_columns, col_id);
        plv_record_attr_t *attr = NULL;
        if (col->typmod.is_array) {
            OG_SRC_THROW_ERROR(loc, ERR_PL_UNSUPPORT);
            return OG_ERROR;
        }
        attr = udt_record_alloc_attr(compiler->entity, record);
        if (attr == NULL) {
            pl_check_and_set_loc(loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pl_copy_name_cs(compiler->entity, &col->name, &attr->name, OG_FALSE));
        attr->type = UDT_SCALAR;
        OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
        attr->scalar_field->type_mode = col->typmod;
        attr->default_expr = NULL;
        attr->nullable = OG_FALSE;
        if (attr->scalar_field->type_mode.datatype != OG_TYPE_UNKNOWN) {
            OG_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, OG_FALSE));
        }
    }
    return OG_SUCCESS;
}

static status_t init_for_line_common(pl_compiler_t *compiler, const char *index_name, pl_line_for_t **for_line,
    bool32 is_cursor)
{
    text_t idx_name;
    text_t *label_name = current_label_name(compiler);
    text_t loop_name = (label_name == NULL) ? CM_NULL_TEXT : *label_name;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_for_t), LINE_FOR, (pl_line_ctrl_t **)for_line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &(*for_line)->decls));
    OG_RETURN_IFERR(cm_galist_new((*for_line)->decls, sizeof(plv_decl_t), (void **)&(*for_line)->id));
    (*for_line)->id->vid.block = (int16)compiler->stack.depth;
    (*for_line)->id->vid.id = 0;
    cm_str2text((char *)index_name, &idx_name);
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, &idx_name, &(*for_line)->id->name));
    (*for_line)->is_cur = is_cursor;
    (*for_line)->is_push = OG_FALSE;
    (*for_line)->name = label_name;
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)*for_line, &loop_name));
    return plc_push_ctl(compiler, (pl_line_ctrl_t *)*for_line, &loop_name);
}

static status_t init_for_cursor_record(pl_compiler_t *compiler, pl_line_for_t *line)
{
    plv_decl_t *type_record = NULL;

    line->id->type = PLV_RECORD;
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&type_record));
    type_record->vid.block = (int16)compiler->stack.depth;
    type_record->vid.id = (uint16)(line->decls->count - 1);
    type_record->type = PLV_TYPE;
    type_record->typdef.type = PLV_RECORD;
    type_record->typdef.record.root = type_record;
    type_record->typdef.record.is_anonymous = OG_TRUE;
    line->id->record = &type_record->typdef.record;
    return OG_SUCCESS;
}

static status_t create_expr_from_pl_node(sql_stmt_t *stmt, expr_node_t *node, source_location_t loc, expr_tree_t **expr)
{
    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    (*expr)->loc = loc;
    node->owner = *expr;
    node->loc = loc;
    node->left = NULL;
    node->right = NULL;
    APPEND_CHAIN(&((*expr)->chain), node);
    return sql_generate_expr(*expr);
}

static status_t try_create_pl_var_node_from_name(sql_stmt_t *stmt, const char *name, source_location_t loc,
    expr_node_t **node)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    text_t name_text;
    plv_decl_t *decl = NULL;
    plc_variant_name_t variant_name;
    char block_name_buf[OG_NAME_BUFFER_SIZE];
    char name_buf[OG_NAME_BUFFER_SIZE];
    uint32 types = PLV_VARIANT_AND_CUR;

    *node = NULL;
    if (name == NULL || compiler == NULL) {
        return OG_SUCCESS;
    }

    cm_str2text((char *)name, &name_text);
    PLC_INIT_VARIANT_NAME(&variant_name, block_name_buf, name_buf, OG_FALSE, types);
    variant_name.block_name.len = 0;
    plc_concat_text_upper_by_type(&variant_name.name, OG_MAX_NAME_LEN, &name_text, WORD_TYPE_VARIANT);
    plc_find_block_decl(compiler, &variant_name, &decl);
    if (decl == NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node));
    MEMS_RETURN_IFERR(memset_s(*node, sizeof(expr_node_t), 0, sizeof(expr_node_t)));
    (*node)->loc = loc;
    (*node)->value.type = OG_TYPE_COLUMN;
    (*node)->value.v_col.ss_start = OG_INVALID_ID32;
    (*node)->value.v_col.ss_end = OG_INVALID_ID32;
    return plc_build_var_address(stmt, decl, *node, UDT_STACK_ADDR);
}

static status_t try_create_pl_var_expr_from_text(sql_stmt_t *stmt, text_t *src, source_location_t loc,
    expr_tree_t **expr)
{
    text_t ident = *src;
    char *name = NULL;
    expr_node_t *node = NULL;

    *expr = NULL;
    cm_trim_text(&ident);
    if (!pl_bison_is_ident_text(ident.str, ident.len)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_stack_alloc(stmt, ident.len + 1, (void **)&name));
    MEMS_RETURN_IFERR(memcpy_s(name, ident.len + 1, ident.str, ident.len));
    name[ident.len] = '\0';

    OG_RETURN_IFERR(try_create_pl_var_node_from_name(stmt, name, loc, &node));
    if (node == NULL) {
        return OG_SUCCESS;
    }
    return create_expr_from_pl_node(stmt, node, loc, expr);
}

static status_t pl_copy_cstr_name(core_yyscan_t yyscanner, const char *src, bool32 upper, char **dst)
{
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    uint32 len = (uint32)strlen(src);

    *dst = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, len + 1, (void **)dst));
    if (len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(*dst, len + 1, src, len));
    }
    (*dst)[len] = '\0';
    if (upper) {
        for (uint32 i = 0; i < len; i++) {
            (*dst)[i] = UPPER((*dst)[i]);
        }
    }
    return OG_SUCCESS;
}

static status_t pl_copy_ident_token_text(core_yyscan_t yyscanner, char **name)
{
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    uint32 token_len;
    char *src = NULL;

    *name = NULL;
    if (PLSQL_YYLENG(yyscanner) <= 0) {
        return OG_SUCCESS;
    }
    token_len = (uint32)PLSQL_YYLENG(yyscanner);

    src = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + PLSQL_YYLLOC(yyscanner)->offset;
    if (!pl_bison_is_ident_text(src, token_len)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_stack_alloc(stmt, token_len + 1, (void **)name));
    MEMS_RETURN_IFERR(memcpy_s(*name, token_len + 1, src, token_len));
    (*name)[token_len] = '\0';
    return OG_SUCCESS;
}

static status_t compile_for_bound_expr(sql_stmt_t *stmt, pl_compiler_t *compiler, text_t *src,
    expr_node_t *datum_node, source_location_t datum_loc, expr_tree_t **expr)
{
    if (datum_node != NULL) {
        OG_RETURN_IFERR(create_expr_from_pl_node(stmt, datum_node, datum_loc, expr));
    } else {
        OG_RETURN_IFERR(get_valid_expr_tree(stmt, src, expr));
    }
    OG_RETURN_IFERR(plc_verify_expr(compiler, *expr));
    return plc_clone_expr_tree(compiler, expr);
}

static status_t finish_numeric_for_start(core_yyscan_t yyscanner, const char *index_name, bool32 reverse,
    text_t *lower_src, expr_node_t *lower_node, source_location_t lower_loc, source_location_t loc,
    pl_line_for_t **for_line)
{
    expr_node_t *upper_node = NULL;
    source_location_t upper_loc = loc;
    text_t *upper_src = NULL;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(read_sql_expression_from_token(PLSQL_YYLEX(yyscanner), K_LOOP, yyscanner, &upper_src,
        &upper_node, &upper_loc));
    OG_RETURN_IFERR(init_for_line_common(compiler, index_name, for_line, OG_FALSE));
    (*for_line)->id->type = PLV_VAR;
    (*for_line)->id->variant.type.datatype = OG_TYPE_INTEGER;
    OG_RETURN_IFERR(compile_for_bound_expr(stmt, compiler, lower_src, lower_node, lower_loc,
        &(*for_line)->lower_expr));
    OG_RETURN_IFERR(compile_for_bound_expr(stmt, compiler, upper_src, upper_node, upper_loc,
        &(*for_line)->upper_expr));
    (*for_line)->reverse = reverse;
    return OG_SUCCESS;
}

static status_t finish_implicit_cursor_for_start(core_yyscan_t yyscanner, const char *index_name,
    source_location_t loc, pl_line_for_t **for_line)
{
    int tok = PLSQL_YYLEX(yyscanner);
    int endtoken = 0;
    text_t *query = NULL;
    plv_decl_t *imp_cur = NULL;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    if (tok != K_SELECT) {
        OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "SELECT", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    query = read_sql_construct_from(PLSQL_YYLLOC(yyscanner)->offset, ')', 0, 0, 0, 0, 0, yyscanner, &endtoken);
    if (endtoken != ')' || PLSQL_YYLEX(yyscanner) != K_LOOP) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "LOOP", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(init_for_line_common(compiler, index_name, for_line, OG_TRUE));
    OG_RETURN_IFERR(init_for_cursor_record(compiler, *for_line));
    (*for_line)->is_impcur = OG_TRUE;
    OG_RETURN_IFERR(cm_galist_new((*for_line)->decls, sizeof(plv_decl_t), (void **)&imp_cur));
    OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(plv_cursor_context_t), (void **)&imp_cur->cursor.ogx));
    OG_RETURN_IFERR(plc_init_galist(compiler, &imp_cur->cursor.input));
    imp_cur->vid.block = (*for_line)->id->vid.block;
    imp_cur->vid.id = (uint16)((*for_line)->decls->count - 1);
    imp_cur->type = PLV_IMPCUR;
    (*for_line)->cursor_id = imp_cur->vid;
    OG_RETURN_IFERR(compile_static_sql_context(stmt, query, KEY_WORD_SELECT, loc, imp_cur->cursor.input, NULL,
        &(*for_line)->context));
    OG_RETURN_IFERR(sql_append_references(&entity->ref_list, (*for_line)->context));
    OG_RETURN_IFERR(copy_context_rscols_to_record(compiler, (*for_line)->context, (*for_line)->id->record, loc));
    OG_RETURN_IFERR(plc_init_galist(compiler, &(*for_line)->into.output));
    OG_RETURN_IFERR(udt_build_list_address_single(stmt, (*for_line)->into.output, (*for_line)->id, UDT_STACK_ADDR));
    (*for_line)->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    (*for_line)->into.into_type = (uint8)INTO_AS_REC;
    (*for_line)->into.is_bulk = OG_FALSE;
    imp_cur->cursor.sql.value = CM_NULL_TEXT;
    imp_cur->cursor.ogx->context = (*for_line)->context;
    return OG_SUCCESS;
}

static status_t finish_explicit_cursor_for_start(core_yyscan_t yyscanner, const char *index_name,
    expr_node_t *cursor_node, source_location_t loc, pl_line_for_t **for_line)
{
    int tok;
    int endtoken = 0;
    plv_decl_t *decl = NULL;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(find_cursor_decl_by_node(compiler, cursor_node, loc, &decl));
    if (decl->cursor.ogx->is_sysref || decl->cursor.ogx->context == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_INVALID_CURSOR);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(init_for_line_common(compiler, index_name, for_line, OG_TRUE));
    OG_RETURN_IFERR(init_for_cursor_record(compiler, *for_line));
    (*for_line)->is_impcur = OG_FALSE;
    (*for_line)->cursor_id = decl->vid;
    tok = PLSQL_YYLEX(yyscanner);
    if (tok == '(') {
        OG_RETURN_IFERR(plc_init_galist(compiler, &(*for_line)->exprs));
        OG_RETURN_IFERR(compile_open_arg_list(yyscanner, compiler, (*for_line)->exprs, &endtoken));
        if (endtoken != ')') {
            OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "')'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }
        if ((*for_line)->exprs->count == 0) {
            (*for_line)->exprs = NULL;
        } else {
            OG_RETURN_IFERR(plc_verify_cursor_args(compiler, (*for_line)->exprs, decl->cursor.ogx->args, loc));
        }
        tok = PLSQL_YYLEX(yyscanner);
    } else {
        (*for_line)->exprs = NULL;
    }
    if (tok != K_LOOP) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "LOOP", pl_token_text(tok, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(copy_context_rscols_to_record(compiler, decl->cursor.ogx->context, (*for_line)->id->record, loc));
    OG_RETURN_IFERR(plc_init_galist(compiler, &(*for_line)->into.output));
    OG_RETURN_IFERR(udt_build_list_address_single(stmt, (*for_line)->into.output, (*for_line)->id, UDT_STACK_ADDR));
    (*for_line)->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    (*for_line)->into.into_type = (uint8)INTO_AS_REC;
    (*for_line)->into.is_bulk = OG_FALSE;
    return OG_SUCCESS;
}

static status_t compile_for_start_stmt(core_yyscan_t yyscanner, const char *index_name, source_location_t loc,
    pl_line_for_t **for_line)
{
    int tok = PLSQL_YYLEX(yyscanner);
    text_t *lower_src = NULL;
    expr_node_t *lower_node = NULL;
    source_location_t lower_loc = loc;
    bool32 reverse = OG_FALSE;

    if (tok == K_REVERSE) {
        reverse = OG_TRUE;
        tok = PLSQL_YYLEX(yyscanner);
    }
    if (tok == '(') {
        return finish_implicit_cursor_for_start(yyscanner, index_name, loc, for_line);
    }
    if (!reverse && tok == T_DATUM) {
        var_address_pair_t *pair = sql_get_last_addr_pair(PLSQL_YYLVAL(yyscanner)->node);
        if (pair != NULL && pair->type == UDT_STACK_ADDR && pair->stack->decl != NULL &&
            pair->stack->decl->type == PLV_CUR) {
            return finish_explicit_cursor_for_start(yyscanner, index_name, PLSQL_YYLVAL(yyscanner)->node, loc, for_line);
        }
    }
    OG_RETURN_IFERR(read_sql_expression_from_token(tok, DOT_DOT, yyscanner, &lower_src, &lower_node, &lower_loc));
    return finish_numeric_for_start(yyscanner, index_name, reverse, lower_src, lower_node, lower_loc, loc, for_line);
}

static key_wid_t dml_key_from_token(int token)
{
    switch (token) {
        case K_INSERT:
            return KEY_WORD_INSERT;
        case K_UPDATE:
            return KEY_WORD_UPDATE;
        case K_DELETE:
            return KEY_WORD_DELETE;
        case K_MERGE:
            return KEY_WORD_MERGE;
        default:
            return KEY_WORD_0_UNKNOWN;
    }
}

static status_t compile_forall_stmt(core_yyscan_t yyscanner, const char *index_name, text_t *lower_src,
    source_location_t loc)
{
    pl_line_for_t *line = NULL;
    pl_line_end_loop_t *end_line = NULL;
    pl_line_ctrl_t *pop_line = NULL;
    pl_line_sql_t *sql_line = NULL;
    expr_tree_t *lower = NULL;
    expr_tree_t *upper = NULL;
    text_t *upper_src = NULL;
    text_t *dml_src = NULL;
    text_t idx_name;
    int endtoken = 0;
    key_wid_t key_wid;
    source_location_t dml_loc;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    upper_src = read_sql_construct(K_INSERT, K_UPDATE, K_DELETE, K_MERGE, K_SAVE, 0, yyscanner, &endtoken);
    if (endtoken == K_SAVE) {
        endtoken = PLSQL_YYLEX(yyscanner);
        if (endtoken != K_EXCEPTIONS) {
            OG_SRC_THROW_ERROR(PLSQL_YYLLOC(yyscanner)->loc, ERR_PL_EXPECTED_FAIL_FMT, "EXCEPTIONS", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
            return OG_ERROR;
        }
        OG_SRC_THROW_ERROR(loc, ERR_PL_UNSUPPORT);
        return OG_ERROR;
    }
    key_wid = dml_key_from_token(endtoken);
    if (key_wid == KEY_WORD_0_UNKNOWN) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "DML statement", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_for_t), LINE_FOR, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->decls));
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&line->id));
    line->id->vid.block = (int16)compiler->stack.depth;
    line->id->vid.id = 0;
    line->id->type = PLV_VAR;
    line->id->variant.type.datatype = OG_TYPE_INTEGER;
    cm_str2text((char *)index_name, &idx_name);
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, &idx_name, &line->id->name));
    OG_RETURN_IFERR(get_valid_expr_tree(stmt, lower_src, &lower));
    OG_RETURN_IFERR(plc_verify_expr(compiler, lower));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &lower));
    OG_RETURN_IFERR(get_valid_expr_tree(stmt, upper_src, &upper));
    OG_RETURN_IFERR(plc_verify_expr(compiler, upper));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &upper));
    line->is_cur = OG_FALSE;
    line->is_push = OG_FALSE;
    line->reverse = OG_FALSE;
    line->lower_expr = lower;
    line->upper_expr = upper;
    line->name = NULL;
    /*
     * The legacy compiler does not have a dedicated executable FORALL line. The bison path
     * preserves the supported behavior by lowering a simple FORALL range to a numeric FOR loop
     * that executes the parsed DML once per index value.
     */
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));

    dml_loc = PLSQL_YYLLOC(yyscanner)->loc;
    dml_src = read_sql_construct_from(PLSQL_YYLLOC(yyscanner)->offset, ';', 0, 0, 0, 0, 0, yyscanner, &endtoken);
    if (endtoken != ';') {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", pl_token_text(endtoken, PLSQL_YYLVAL(yyscanner)));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL, (pl_line_ctrl_t **)&sql_line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &sql_line->input));
    OG_RETURN_IFERR(compile_static_sql_line(stmt, dml_src, key_wid, dml_loc, sql_line));

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_end_loop_t), LINE_END_LOOP,
        (pl_line_ctrl_t **)&end_line));
    OG_RETURN_IFERR(plc_pop(compiler, loc, PBE_END_LOOP, &pop_line));
    end_line->loop = pop_line;
    line->next = (pl_line_ctrl_t *)end_line;
    return OG_SUCCESS;
}

static status_t find_top_loop(pl_compiler_t *compiler, source_location_t loc, pl_line_ctrl_t **line)
{
    int32 i;

    for (i = (int32)compiler->control_stack.depth - 1; i >= 0; i--) {
        pl_line_type_t type = compiler->control_stack.items[i].entry->type;
        if (type == LINE_LOOP || type == LINE_WHILE || type == LINE_FOR) {
            *line = compiler->control_stack.items[i].entry;
            return OG_SUCCESS;
        }
    }

    *line = NULL;
    OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "not in loop statement");
    return OG_ERROR;
}

static status_t make_type_word(pl_compiler_t *compiler, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc, bool32 is_name_typemode, bool32 pl_type, bool32 pl_rowtype)
{
    if (sql_alloc_mem(compiler->stmt->context, sizeof(type_word_t), (void **)type) != OG_SUCCESS) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(*type, sizeof(type_word_t), 0, sizeof(type_word_t));
    knl_securec_check(ret);
    (*type)->str = str;
    (*type)->typemode = typemode;
    (*type)->is_name_typemode = is_name_typemode;
    (*type)->pl_type = pl_type;
    (*type)->pl_rowtype = pl_rowtype;
    (*type)->loc = loc;
    return OG_SUCCESS;
}

static char *pl_bison_identifier_at(core_yyscan_t yyscanner, int offset)
{
    core_yy_extra_type *extra = &og_yyget_extra(yyscanner)->core_yy_extra;
    sql_stmt_t *stmt = extra->stmt;
    uint32 start = (uint32)offset;
    uint32 end = start;
    char *name = NULL;

    if (start >= extra->scanbuflen) {
        return NULL;
    }

    while (end < extra->scanbuflen && pl_bison_is_ident_char(extra->scanbuf[end])) {
        end++;
    }
    if (end == start) {
        return NULL;
    }

    if (sql_alloc_mem(stmt->context, end - start + 1, (void **)&name) != OG_SUCCESS) {
        return NULL;
    }
    if (memcpy_s(name, end - start + 1, extra->scanbuf + start, end - start) != EOK) {
        return NULL;
    }
    name[end - start] = '\0';
    return name;
}

static bool32 pl_bison_word_ident_usable(const PLword *word)
{
    return (word != NULL && word->ident != NULL);
}

static char *pl_bison_word_name(core_yyscan_t yyscanner, const PLword *word, int offset)
{
    char *name = NULL;

    if (pl_bison_word_ident_usable(word) && word->quoted) {
        return word->ident;
    }

    name = pl_bison_identifier_at(yyscanner, offset);
    if (name != NULL) {
        return name;
    }

    if (pl_bison_word_ident_usable(word)) {
        return word->ident;
    }

    return NULL;
}

static text_t *read_sql_expression(int until, core_yyscan_t yyscanner)
{
    return read_sql_construct(until, 0, 0, 0, 0, 0, yyscanner, NULL);
}

static status_t read_sql_expression_from_token(int token, int until, core_yyscan_t yyscanner, text_t **expr_src,
    expr_node_t **datum_node, source_location_t *datum_loc)
{
    int tok = token;
    int begin = PLSQL_YYLLOC(yyscanner)->offset;
    uint32 token_count = 0;
    bool32 first_token_is_datum = (tok == T_DATUM);
    expr_node_t *first_datum = PLSQL_YYLVAL(yyscanner)->node;
    source_location_t first_loc = PLSQL_YYLLOC(yyscanner)->loc;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    char *first_name = NULL;

    *expr_src = NULL;
    if (tok != T_DATUM) {
        OG_RETURN_IFERR(pl_copy_ident_token_text(yyscanner, &first_name));
    }
    OG_RETURN_IFERR(read_sql_construct_core(begin, tok, until, 0, 0, 0, 0, 0, yyscanner, expr_src, NULL,
        &token_count));

    if (datum_node != NULL) {
        bool32 single_token = (token_count == 1);
        *datum_node = (first_token_is_datum && single_token) ? first_datum : NULL;
        if (*datum_node == NULL && single_token) {
            OG_RETURN_IFERR(try_create_pl_var_node_from_name(stmt, first_name, first_loc, datum_node));
        }
    }
    if (datum_loc != NULL && datum_node != NULL && *datum_node != NULL) {
        *datum_loc = first_loc;
    }

    return OG_SUCCESS;
}

static text_t *read_sql_expression2(int until, int until2, core_yyscan_t yyscanner, int *endtoken)
{
    return read_sql_construct(until, until2, 0, 0, 0, 0, yyscanner, endtoken);
}

static bool32 is_sql_construct_terminator(int token, int paren_depth, int until, int until2, int until3, int until4,
    int until5, int until6)
{
    if (token == YYEOF) {
        return OG_TRUE;
    }
    if (paren_depth != 0) {
        return OG_FALSE;
    }
    return (until != 0 && token == until) || (until2 != 0 && token == until2) ||
        (until3 != 0 && token == until3) || (until4 != 0 && token == until4) ||
        (until5 != 0 && token == until5) || (until6 != 0 && token == until6);
}

static void update_sql_construct_depth(int token, int *paren_depth)
{
    if (token == '(') {
        (*paren_depth)++;
        return;
    }
    if (token == ')' && *paren_depth > 0) {
        (*paren_depth)--;
    }
}

static status_t read_sql_construct_core(int start_offset, int token, int until, int until2, int until3, int until4,
    int until5, int until6, core_yyscan_t yyscanner, text_t **expr_src, int *endtoken, uint32 *token_count)
{
    int tok = token;
    int paren_depth = 0;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;

    if (token_count != NULL) {
        *token_count = 0;
    }
    OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(text_t), (void **)expr_src));
    for (;;) {
        if (is_sql_construct_terminator(tok, paren_depth, until, until2, until3, until4, until5, until6)) {
            break;
        }
        if (token_count != NULL) {
            (*token_count)++;
        }
        update_sql_construct_depth(tok, &paren_depth);
        tok = PLSQL_YYLEX(yyscanner);
    }

    if (endtoken != NULL) {
        *endtoken = tok;
    }

    (*expr_src)->str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + start_offset;
    (*expr_src)->len = PLSQL_YYLLOC(yyscanner)->offset - start_offset;
    return OG_SUCCESS;
}

static text_t *read_sql_construct_from(int start_offset,
                                   int until,
                                   int until2,
                                   int until3,
                                   int until4,
                                   int until5,
                                   int until6,
                                   core_yyscan_t yyscanner,
                                   int *endtoken)
{
    text_t *expr_src = NULL;
    int tok = PLSQL_YYLEX(yyscanner);

    if (read_sql_construct_core(start_offset, tok, until, until2, until3, until4, until5, until6, yyscanner,
        &expr_src, endtoken, NULL) != OG_SUCCESS) {
        return NULL;
    }
    return expr_src;
}

static text_t *read_sql_construct(int until,
                                   int until2,
                                   int until3,
                                   int until4,
                                   int until5,
                                   int until6,
                                   core_yyscan_t yyscanner,
                                   int *endtoken)
{
    text_t *expr_src = NULL;
    int tok = PLSQL_YYLEX(yyscanner);
    int begin = PLSQL_YYLLOC(yyscanner)->offset;

    if (read_sql_construct_core(begin, tok, until, until2, until3, until4, until5, until6, yyscanner,
        &expr_src, endtoken, NULL) != OG_SUCCESS) {
        return NULL;
    }
    return expr_src;
}
