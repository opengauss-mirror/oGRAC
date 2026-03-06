%{

#include "pl_compiler.h"
#include "ast_cl.h"
#include "typedef_cl.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "lines_cl.h"
#include "pl_udt.h"
#include "pl_gram.h"
#include "gramparse.h"
#include "dml_parser.h"
#include "pl_dc.h"

/* Location tracking support --- simpler than bison's default */

#define YYLLOC_DEFAULT(Current, Rhs, N) \
    do { \
        if (N) \
            (Current) = (Rhs)[1]; \
        else \
            (Current) = (Rhs)[0]; \
    } while (0)

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex (yyscanner)
#endif

#define parser_yyerror(msg)             \
do {                                    \
    plsql_yyerror(yyscanner, msg);      \
    YYABORT;                            \
} while (0)


#define MAX_SQL_LEN 1024

extern int plsql_yylex(core_yyscan_t yyscanner);
extern void plsql_push_back_token(int token, core_yyscan_t yyscanner);
static void plsql_yyerror(core_yyscan_t yyscanner, const char* message);
static status_t parse_expr_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line);
static status_t read_return_sql_construct(sql_stmt_t *stmt, text_t *src, pl_line_return_t *line);
static status_t make_type_word(pl_compiler_t *compiler, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc, bool32 pl_type, bool32 pl_rowtype);
static status_t check_sql_expr(sql_stmt_t *stmt, sql_text_t *sql, sql_select_t **select_ctx);
static status_t get_valid_expr_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr);
static status_t get_valid_cond_tree(sql_stmt_t *stmt, text_t *src, cond_tree_t **cond);
static bool tok_is_keyword(int token, union YYSTYPE *lval, int kw_token, const char *kw_str);
static text_t *read_sql_expression(int until, core_yyscan_t yyscanner);
static text_t *read_sql_expression2(int until, int until2, core_yyscan_t yyscanner, int *endtoken);
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

%expect 0
%name-prefix "plsql_yy"
%locations

%parse-param {core_yyscan_t yyscanner}
%lex-param   {core_yyscan_t yyscanner}

%union {
    core_YYSTYPE core_yystype;
    const char *keyword;
    PLword word;
    expr_tree_t *expr;
    expr_node_t *node;
    text_t *text;
    type_word_t *type;
    char *str;
    bool boolean;
    galist_t *list;
    record_attr_t *record_attr;
}

%type <keyword>	unreserved_keyword
%type <expr> decl_defval decl_rec_defval
%type <node> assign_var
%type <text> expr_until_semi expr_until_then decl_rec_defval_expr
%type <type> decl_datatype
%type <str> decl_varname
%type <boolean> decl_notnull
%type <list> record_attr_list
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
            pl_block
        ;

pl_block:
            declare_sect_b K_BEGIN
                {
                    /* todo: 支持label，参考plc_compile_label，openGauss见opt_block_label */
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    pl_line_begin_t *line = NULL;
                    text_t block_name = CM_NULL_TEXT;
                    plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&line);
                    plc_push(compiler, (pl_line_ctrl_t *)line, &block_name);
                    plc_convert_typedecl(compiler, compiler->decls);
                    line->decls = compiler->decls;
                    line->type_decls = compiler->type_decls;
                    line->name = NULL;
                    if (compiler->body == NULL) {
                        compiler->body = line;
                    }
                }
            proc_sect K_END T_WORD ';'
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (strncmp($6.ident, compiler->obj->name.str, compiler->obj->name.len) != 0) {
                        parser_yyerror("Undefined symbol");
                    }
                    pl_line_ctrl_t *line = NULL;
                    pl_line_begin_t *begin_line = (pl_line_begin_t *)plc_get_current_beginln(compiler);

                    plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END, (pl_line_ctrl_t **)&line);
                    begin_line->end = line;
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
            pl_block ';'
            | label_stmts
        ;

label_stmts:
            label_stmt
        ;

label_stmt:
            stmt_assign
            | stmt_return
            | stmt_if
                {
                    /* todo：g_plc_compile_lines_map里其余语句 */
                }
        ;

stmt_assign:
            assign_var COLON_EQUALS expr_until_semi
                {
                    pl_line_normal_t *line = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    pl_compiler_t *compiler = (pl_compiler_t*)stmt->pl_compiler;

                    plc_alloc_line(compiler, sizeof(pl_line_normal_t), LINE_SETVAL, (pl_line_ctrl_t **)&line);
                    line->left = $1;
                    parse_expr_from_sql(stmt, $3, line);
                    plc_clone_expr_node(compiler, &line->left);
                    plc_clone_expr_tree(compiler, &line->expr);
                    plc_clone_cond_tree(compiler, &line->cond);
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

                    plc_alloc_line(compiler, sizeof(pl_line_return_t), LINE_RETURN, (pl_line_ctrl_t **)&line);
                    read_return_sql_construct(stmt, $2, line);

                    decl = plc_find_param_by_id(compiler, ret_vid);
                    if (decl == NULL) {
                        parser_yyerror("Undefined symbol");
                    }
                    if (plc_verify_expr(compiler, line->expr) != OG_SUCCESS) {
                        parser_yyerror("verify expr failed");
                    }
                    if (plc_clone_expr_tree(compiler, &line->expr) != OG_SUCCESS) {
                        parser_yyerror("clone expr failed");
                    }
                    if (!sql_is_skipped_expr(line->expr)) {
                        plc_verify_stack_var_assign(compiler, decl, line->expr);
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

assign_var:
            T_DATUM
                {
                    $$ = yylval.node;
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
            decl_varname decl_datatype decl_defval
                {
                    /* todo: exception, sys_refcursor 参考plc_compile_decl */
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    galist_t *decls = compiler->decls;
                    plv_decl_t *decl = NULL;
                    type_word_t *type = $2;

                    cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl);
                    decl->vid.block = (int16)compiler->stack.depth;
                    decl->vid.id = (uint16)(decls->count - 1); // not overflow
                    cm_str2text($1, &decl->name);

                    if (type->pl_rowtype || type->pl_type) {
                        plattr_assist_t plattr_ass;
                        plattr_ass.type = DECL_INHERIT;
                        plattr_ass.decl = decl;
                        plattr_ass.decls = compiler->decls;
                        plattr_ass.is_args = OG_TRUE;
                        if (plc_bison_compile_plv_type(compiler, &plattr_ass, type) != OG_SUCCESS) {
                            parser_yyerror("compile pl type failed");
                        }
                        if (plc_check_decl_datatype(compiler, decl, OG_TRUE) != OG_SUCCESS) {
                            parser_yyerror("check pl type failed");
                        }
                    } else {
                        bool32 result = OG_FALSE;
                        /* check userdef type in block */
                        if (plc_bison_try_compile_local_type(compiler, decl, type, &result) != OG_SUCCESS) {
                            parser_yyerror("try compile local type failed");
                        }

                        /* todo：userdef global type */

                        if (!result) {
                            decl->type = PLV_VAR;
                            if (plc_bison_compile_type(compiler, PLC_PMODE(decl->drct), &decl->variant.type,
                                type) != OG_SUCCESS) {
                                parser_yyerror("compile type failed");
                            }
                            if (plc_check_datatype(compiler, &decl->variant.type, OG_TRUE) != OG_SUCCESS) {
                                parser_yyerror("check type failed");
                            }
                            if (decl->variant.type.is_array) {
                                decl->type = PLV_ARRAY;
                            }
                        }
                    }

                    if (plc_bison_compile_default_def(compiler, decl, $3) != OG_SUCCESS) {
                        parser_yyerror("verify default expr failed");
                    }
                }
            | K_TYPE decl_varname K_IS K_RECORD '(' record_attr_list ')' ';'
                {
                    /* todo：参考plc_compile_block_decls，实现pragma,cursor,type还有ref,varry,table */
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    if (plc_bison_compile_type_def(compiler, $2, $6, @1.loc, MATCH_RECORD) != OG_SUCCESS) {
                        parser_yyerror("parse record type failed");
                    }
                }
        ;

decl_notnull:   K_NOT K_NULL
                    { $$ = true; }
                | /* EMPTY */
                    { $$ = false; }
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
                    int tok = YYLEX;
                    source_location_t loc = yylloc.loc;
                    char *typename = NULL;
                    type_word_t *type = NULL;
                    bool32 pl_type = OG_FALSE;
                    bool32 pl_rowtype = OG_FALSE;
                    galist_t *typemode = NULL;
                    text_t *text = NULL;

                    typename = yylval.word.ident;

                    /* todo: 局部或全局的自定义类型、普通数据类型的typemode */
                    while ((tok = YYLEX) == '.') {
                        tok = YYLEX;
                        if (typemode == NULL) {
                            sql_create_list(stmt, &typemode);
                        }
                        cm_galist_new(typemode, sizeof(text_t), (pointer_t *)&text);
                        cm_str2text(yylval.word.ident, text);
                    }
                    if (tok == '%') {
                        tok = YYLEX;
                        if (tok_is_keyword(tok, &yylval, K_TYPE, "type")) {
                            pl_type = OG_TRUE;
                        } else if (tok_is_keyword(tok, &yylval, K_ROWTYPE, "rowtype")) {
                            pl_rowtype = OG_TRUE;
                        } else {
                            parser_yyerror("expected TYPE or ROWTYPE");
                        }
                    } else {
                        plsql_push_back_token(tok, yyscanner);
                    }

                    if (make_type_word(compiler, &type, typename, typemode, loc, pl_type, pl_rowtype) != OG_SUCCESS) {
                        parser_yyerror("make type failed");
                    }

                    $$ = type;
                }
        ;

decl_varname:
            T_WORD
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    text_t name;
                    cm_str2text($1.ident, &name);
                    bool32 result = OG_FALSE;
                    plc_check_duplicate(compiler->decls, (text_t *)&name, $1.quoted, &result);

                    if (result) {
                        parser_yyerror("duplicate varname");
                    }
                    $$ = $1.ident;
                }
            | unreserved_keyword
                {
                    pl_compiler_t *compiler = (pl_compiler_t*)og_yyget_extra(yyscanner)->core_yy_extra.stmt->pl_compiler;
                    char *tmp = strdup($1);
                    text_t name;
                    cm_str2text(tmp, &name);
                    bool32 result = OG_FALSE;
                    plc_check_duplicate(compiler->decls, (text_t *)&name, OG_FALSE, &result);

                    if (result) {
                        parser_yyerror("duplicate varname");
                    }
                    $$ = tmp;
                }
        ;

unreserved_keyword:
                            K_ABSOLUTE
                | K_ALIAS
                | K_ALTER
                | K_ARRAY
                | K_BACKWARD
                | K_CALL
                | K_CATALOG_NAME
                | K_CLASS_ORIGIN
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
                | K_FIRST
                | K_FORWARD
                | K_HINT
                | K_INDEX
                | K_INFO
                | K_INTERSECT
                | K_IS
                | K_LAST
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
                | K_PG_EXCEPTION_CONTEXT
                | K_PG_EXCEPTION_DETAIL
                | K_PG_EXCEPTION_HINT
                | K_PIPE
                | K_PRIOR
                | K_QUERY
                | K_RECORD
                | K_RELATIVE
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
                | K_SQLSTATE
                | K_STACKED
                | K_SUBCLASS_ORIGIN
                | K_SYS_REFCURSOR
                | K_TABLE
                | K_TABLE_NAME
                | K_UNION
                | K_USE_COLUMN
                | K_USE_VARIABLE
                | K_VARIABLE_CONFLICT
                | K_VARRAY
                | K_WARNING
                | K_WITH
        ;

%%

static void plsql_yyerror(core_yyscan_t yyscanner, const char* message)
{
    OG_SRC_THROW_ERROR(yylloc.loc, ERR_SQL_SYNTAX_ERROR, message);
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

static status_t get_valid_expr_tree(sql_stmt_t *stmt, text_t *src, expr_tree_t **expr)
{
    char str[MAX_SQL_LEN] = { 0 };
    text_t sql;
    sql.str = str;
    sql_select_t *select_ctx = NULL;

    status_t ret = snprintf_s(str, MAX_SQL_LEN, MAX_SQL_LEN - 1,
        "SELECT %.*s", (int)src->len, src->str);
    knl_securec_check_ss(ret);
    sql.len = strlen("SELECT ") + src->len;

    if (check_sql_expr(stmt, (sql_text_t*)&sql, &select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *expr = ((query_column_t*)cm_galist_get(select_ctx->first_query->columns, 0))->expr;

    return OG_SUCCESS;
}

static status_t get_valid_cond_tree(sql_stmt_t *stmt, text_t *src, cond_tree_t **cond)
{
    char str[MAX_SQL_LEN] = { 0 };
    text_t sql;
    sql.str = str;
    sql_select_t *select_ctx = NULL;

    status_t ret = snprintf_s(str, MAX_SQL_LEN, MAX_SQL_LEN - 1,
        "SELECT CASE WHEN %.*s THEN TRUE ELSE FALSE END", (int)src->len, src->str);
    knl_securec_check_ss(ret);
    sql.len = strlen("SELECT CASE WHEN  THEN TRUE ELSE FALSE END ") + src->len;
    
    if (check_sql_expr(stmt, (sql_text_t*)&sql, &select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    case_expr_t * case_expr = (case_expr_t*)(((query_column_t*)cm_galist_get(select_ctx->first_query->columns, 0))->expr->root->value.v_pointer);
    *cond = ((case_pair_t*)cm_galist_get(&case_expr->pairs, 0))->when_cond;
    
    return OG_SUCCESS;
}

static status_t read_return_sql_construct(sql_stmt_t *stmt, text_t *src, pl_line_return_t *line)
{
    return get_valid_expr_tree(stmt, src, &line->expr);
}

static status_t parse_expr_from_sql(sql_stmt_t *stmt, text_t *src, pl_line_normal_t *line)
{
    pl_compiler_t *compiler = stmt->pl_compiler;

    if (get_valid_expr_tree(stmt, src, &line->expr) == OG_SUCCESS) {
        OG_RETURN_IFERR(plc_verify_setval(compiler, line->left, line->expr));
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(get_valid_cond_tree(stmt, src, &line->cond));
    OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));

    return OG_SUCCESS;
}

static status_t check_sql_expr(sql_stmt_t *stmt, sql_text_t *sql, sql_select_t **select_ctx)
{
    if (raw_parser(stmt, sql, (void**)select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t make_type_word(pl_compiler_t *compiler, type_word_t **type, char *str,
    galist_t *typemode, source_location_t loc, bool32 pl_type, bool32 pl_rowtype)
{
    if (sql_alloc_mem(compiler->stmt->context, sizeof(type_word_t), (void **)type) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*type)->str = str;
    (*type)->typemode = typemode;
    (*type)->pl_type = pl_type;
    (*type)->pl_rowtype = pl_rowtype;
    (*type)->loc = loc;
    return OG_SUCCESS;
}

static text_t *read_sql_expression(int until, core_yyscan_t yyscanner)
{
    return read_sql_construct(until, 0, 0, 0, 0, 0, yyscanner, NULL);
}

static text_t *read_sql_expression2(int until, int until2, core_yyscan_t yyscanner, int *endtoken)
{
    return read_sql_construct(until, until2, 0, 0, 0, 0, yyscanner, endtoken);
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
    int	tok = YYLEX;
    int begin = yylloc.offset;
    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
    sql_stack_alloc(stmt, sizeof(text_t), (void**)&expr_src);

    for (;;) {
        if (tok == until) {
            break;
        }
        if (tok == until2) {
            break;
        }
        if (tok == until3) {
            break;
        }
        if (tok == until4) {
            break;
        }
        if (tok == until5) {
            break;
        }
        if (tok == until6) {
            break;
        }
        tok = YYLEX;
    }

    if (endtoken) {
        *endtoken = tok;
    }

    expr_src->str = og_yyget_extra(yyscanner)->core_yy_extra.scanbuf + begin;
    expr_src->len = yylloc.offset - begin;
    return expr_src;
}