/* -------------------------------------------------------------------------
 *
 * gramparse.h
 *		Shared definitions for the "raw" parser (flex and bison phases only)
 *
 * NOTE: this file is only meant to be included in the core parsing files,
 * ie, parser.c, gram.y, scan.l, and keywords.c.  Definitions that are needed
 * outside the core parser should be in parser.h.
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * pkg/src/ogsql/parser/gramparse.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef GRAMPARSE_H
#define GRAMPARSE_H

#include "scanner.h"
#include "scansup.h"
#include "ogsql_expr.h"
#include "func_parser.h"
#include "expr_parser.h"
#include "ogsql_cond.h"
#include "ogsql_json_utils.h"
#include "pivot_parser.h"
#include "persist_defs.h"

/*
 * NB: include gram.h only AFTER including scanner.h, because scanner.h
 * is what #defines YYLTYPE.
 */
#ifdef __HINT_PARSER_H__
#include "hint_gram.h"
#else
#include "gram.h"
#endif

/**
 * When dealing with some grammar, we must take more than one token lookahead.
 */
#define MAX_LOOKAHEAD_LEN 3

/**
 * States for the look ahead token.
 */
struct base_yy_lookahead {
    int token;
    core_YYSTYPE yylval;
    YYLTYPE yylloc;
    int yyleng;
    int prev_hold_char_loc;
    char prev_hold_char;
};

/**
 * The `YY_EXTRA` data that a flex scanner allows us to pass around. Private
 * state needed for raw parsing/lexing goes here.
 */
typedef struct base_yy_extra_type {
    /**
     * Fields used by the core scanner.
     */
    core_yy_extra_type core_yy_extra;

    /**
     * State variables for base_yylex().
     */
    int lookahead_len; /* Length of `lookaheads`. Max to `MAX_LOOKAHEAD_LEN` */
    struct base_yy_lookahead lookaheads[MAX_LOOKAHEAD_LEN];

    /**
     * State variables that belong to the grammar.
     */
    void* parsetree; /* Final parse result is delivered here */
} base_yy_extra_type;

typedef struct hint_yy_extra_type {
    /*
     * The string the scanner is physically scanning.  We keep this mainly so
     * that we can cheaply compute the offset of the current token (yytext).
     */
    char* scanbuf;
    size_t scanbuflen;

    sql_stmt_t *stmt;

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
    bool warn_on_first_escape;
    bool saw_non_ascii;
    bool ident_quoted;
    bool warnOnTruncateIdent;

    /* record the message need by multi-query. */
    // List* query_string_locationlist; /* record the end location of each single query */
    bool in_slash_proc_body;         /* check whether it's in a slash proc body */
    int paren_depth;                 /* record the current depth in	the '(' and ')' */
    bool is_createstmt;              /* check whether it's a create statement. */
    bool is_hint_str;                /* current identifier is in hint comment string */
    // List* parameter_list;            /* placeholder parameter list */
    galist_t *hint_lst;
} hint_yy_extra_type;

#define og_hint_yyget_extra(yyscanner) (*((hint_yy_extra_type**)(yyscanner)))

#ifdef __HINT_PARSER_H__
extern int yylex(YYSTYPE* lvalp, yyscan_t yyscanner);
extern int yyparse(yyscan_t yyscanner);
#else
/*
 * In principle we should use yyget_extra() to fetch the yyextra field
 * from a yyscanner struct.  However, flex always puts that field first,
 * and this is sufficiently performance-critical to make it seem worth
 * cheating a bit to use an inline macro.
 */
#define og_yyget_extra(yyscanner) (*((base_yy_extra_type**)(yyscanner)))

/* from parser.c */
extern int base_yylex(YYSTYPE* lvalp, YYLTYPE* llocp, core_yyscan_t yyscanner);

/* from gram.y */
extern void parser_init(base_yy_extra_type* yyext);
extern int base_yyparse(core_yyscan_t yyscanner);

#endif

typedef struct flex_mem_header {
    uint32 magic_number;
    size_t bytes;
} flex_mem_header;

#define FLEX_MEM_MAGIC_NUMBER 0xa1b2c3d4
#define FLEX_MEM_HEADER_SIZE CM_ALIGN8(sizeof(flex_mem_header))
#define FLEX_MEM_GET_HEADER(ptr) ((flex_mem_header*)(((char*)(ptr)) - FLEX_MEM_HEADER_SIZE))
#define FLEX_MEM_GET_POINTER(ptr) ((void*)(((char*)(ptr)) + FLEX_MEM_HEADER_SIZE))

#endif /* GRAMPARSE_H */
