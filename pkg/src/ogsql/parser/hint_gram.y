%{
#include "expr_parser.h"
#include "ogsql_hint_parser.h"

#include "gramparse.h"

#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-variable"

extern void yyerror(yyscan_t yyscanner, const char *msg);
extern void hint_scanner_yyerror(const char *msg, yyscan_t yyscanner);
extern void *yyalloc(size_t bytes, yyscan_t yyscanner);
extern void yyfree(void *ptr, yyscan_t yyscanner);

#define YYMALLOC(size) yyalloc(size, yyscanner)
#define YYFREE(ptr)   yyfree(ptr, yyscanner)

#define hint_parser_yyerror(msg)             \
do {                                    \
    hint_scanner_yyerror(msg, yyscanner);    \
    YYABORT;                            \
} while (0)

%}

%define api.pure
%expect 0

%parse-param {yyscan_t yyscanner}
%lex-param   {yyscan_t yyscanner}


%union
{
    int     	ival;
    char		*str;
    galist_t		*list;
    expr_tree_t         *expr;
    hint_item_t	*hint_item;
}


%type <list> join_hint_list hint_lst
%type <hint_item> join_hint_item
%type <expr> arg_list arg_item

%token <str>	IDENT FCONST SCONST
%token <ival>	ICONST HINT_KEY_WORD
%token          LEX_ERROR_TOKEN
%%
//yacc syntax start here  
hint_lst:
    join_hint_list
    {
        og_hint_yyget_extra(yyscanner)->hint_lst = $1;
    }
    ;

join_hint_list:
    join_hint_item
    {
        galist_t *hint_lst = NULL;
        if (sql_create_list(og_hint_yyget_extra(yyscanner)->stmt, &hint_lst) != OG_SUCCESS) {
            hint_parser_yyerror("create hint list failed.");
        }
        if (cm_galist_insert(hint_lst, $1)) {
            hint_parser_yyerror("insert hint list failed.");
        }
        $$ = hint_lst;
    }
    | join_hint_list join_hint_item
    {
        galist_t *hint_lst = $1;
        if (cm_galist_insert(hint_lst, $1)) {
            hint_parser_yyerror("insert hint list failed.");
        }
        $$ = hint_lst;
    }
    ;

join_hint_item:
    HINT_KEY_WORD '(' arg_list ')'
    {
        hint_item_t *hint = NULL;
        if (sql_alloc_mem(og_hint_yyget_extra(yyscanner)->stmt->context, sizeof(hint_item_t), (void **)&hint) != OG_SUCCESS) {
            hint_parser_yyerror("alloc hint item failed");
        }
        hint->id = $1;
        hint->args = $3;
        $$ = hint;
    }
    ;

arg_list:
    arg_item
    {
        $$ = $1;
    }
    | arg_list ',' arg_item
    {
        expr_tree_t *arg_tree = $1;
        expr_tree_t **temp = &arg_tree->next;
        while (*temp != NULL) {
            temp = &(*temp)->next;
        }
        *temp = $3;
        $$ = arg_tree;
    }
    | arg_list arg_item
    {
        expr_tree_t *arg_tree = $1;
        expr_tree_t **temp = &arg_tree->next;
        while (*temp != NULL) {
            temp = &(*temp)->next;
        }
        *temp = $2;
        $$ = arg_tree;
    }
    ;

arg_item:
    ICONST
    {
        expr_tree_t *expr = NULL;
        source_location_t loc = {.line = 0, .column = 0};
        if (sql_create_int_const_expr(og_hint_yyget_extra(yyscanner)->stmt, &expr, $1, loc) != OG_SUCCESS) {
            hint_parser_yyerror("init const expr failed");
        }
        $$ = expr;
    }
    | FCONST
    {
        expr_tree_t *expr = NULL;
        source_location_t loc = {.line = 0, .column = 0};
        if (sql_create_float_const_expr(og_hint_yyget_extra(yyscanner)->stmt, &expr, $1, loc) != OG_SUCCESS) {
            hint_parser_yyerror("init const expr failed");
        }
        $$ = expr;
    }
    | SCONST
    {
        expr_tree_t *expr = NULL;
        source_location_t loc = {.line = 0, .column = 0};
        if (sql_create_string_const_expr(og_hint_yyget_extra(yyscanner)->stmt, &expr, $1, loc) != OG_SUCCESS) {
            hint_parser_yyerror("init const expr failed");
        }
        $$ = expr;
    }
    | IDENT
    {
        expr_tree_t *expr = NULL;
        source_location_t loc = {.line = 0, .column = 0};
        if (sql_create_string_const_expr(og_hint_yyget_extra(yyscanner)->stmt, &expr, $1, loc) != OG_SUCCESS) {
            hint_parser_yyerror("init const expr failed");
        }
        $$ = expr;
    }
    | '='
    {
        expr_tree_t *expr = NULL;
        source_location_t loc = {.line = 0, .column = 0};
        if (sql_create_string_const_expr(og_hint_yyget_extra(yyscanner)->stmt, &expr, "=", loc) != OG_SUCCESS) {
            hint_parser_yyerror("init const expr failed");
        }
        $$ = expr;
    }
    ;
%%

void
 yyerror(yyscan_t yyscanner, const char *msg)
{
    hint_scanner_yyerror(msg, yyscanner);
    return;
}

#include "hint_scan.inc"

