%{
/* -------------------------------------------------------------------------
 *
 * scan.l
 *      lexical scanner for PostgreSQL
 *
 * NOTE NOTE NOTE:
 *
 * The rules in this file must be kept in sync with psql's lexer!!!
 *
 * The rules are designed so that the scanner never has to backtrack,
 * in the sense that there is always a rule that can match the input
 * consumed so far (the rule action may internally throw back some input
 * with yyless(), however).  As explained in the flex manual, this makes
 * for a useful speed increase --- about a third faster than a plain -CF
 * lexer, in simple testing.  The extra complexity is mostly in the rules
 * for handling float numbers and continued string literals.  If you change
 * the lexical rules, verify that you haven't broken the no-backtrack
 * property by running flex with the "-b" option and checking that the
 * resulting "lex.backup" file says that no backing up is needed.  (As of
 * Postgres 9.2, this check is made automatically by the Makefile.)
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *      src/backend/parser/scan.l
 *
 * -------------------------------------------------------------------------
 */


#include <ctype.h>
#include <unistd.h>

#include "scanner.h"
#include "scansup.h"
#include "ogsql_self_func.h"

#define OG_KEYWORD(kwname, value, category) value,

const uint16 ScanKeywordTokens[] = {
#include "kwlist.h"
};

#undef OG_KEYWORD

/*
 * Set the type of YYSTYPE.
 */
#define YYSTYPE core_YYSTYPE

/*
 * define core_yylex for flex >= 2.6
 */
#if FLEX_MAJOR_VERSION >= 2 && FLEX_MINOR_VERSION >= 6
#define YY_DECL int core_yylex \
               (YYSTYPE * yylval_param, YYLTYPE * yylloc_param , yyscan_t yyscanner)
#endif

/*
 * Set the type of yyextra.  All state variables used by the scanner should
 * be in yyextra, *not* statically allocated.
 */
#define YY_EXTRA_TYPE core_yy_extra_type *

#define YY_USER_INIT        \
do {                        \
    yylloc->loc.column = 1; \
    yylloc->loc.line = 1;   \
    yylloc->offset = 0;     \
} while (0)

/*
 * Each call to yylex must set yylloc to the location of the found token
 * (expressed as a byte offset from the start of the input text).
 * When we parse a token that requires multiple lexer rules to process,
 * this should be done in the first such rule, else yylloc will point
 * into the middle of the token.
 */
#define SET_YYLLOC()  update_current_location(yytext, yyextra->scanbuf, yylloc, yyextra->multi_line_sql)

#define COMMENT_NOT_IGNORED()  (yyextra->is_hint_str || yyextra->include_ora_comment)
/*
 * Advance yylloc by the given number of bytes.
 */
#define ADVANCE_YYLLOC(delta)       \
do {                                \
    yylloc->loc.column += (delta);  \
    yylloc->offset += (delta);      \
} while (0)

#define FLEX_MEM_STRDUP(dest, src)                                              \
do {                                                                            \
    size_t len = strlen(src) + 1;                                               \
    if (sql_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context,   \
        len, (void **)&dest) != OG_SUCCESS) {                                   \
        yyerror("alloc mem failed ");                                           \
    }                                                                           \
    errno_t ret = memcpy_s(dest, len, src, len - 1);                            \
    knl_securec_check(ret);                                                     \
    dest[len - 1] = '\0';                                                       \
} while (0)

#define FLEX_STACK_STRDUP(dest, src)                                            \
do {                                                                            \
    size_t len = strlen(src) + 1;                                               \
    if (sql_stack_alloc(og_yyget_extra(yyscanner)->core_yy_extra.stmt,          \
        len, (void **)&dest) != OG_SUCCESS) {                                   \
        yyerror("alloc mem failed ");                                           \
    }                                                                           \
    errno_t ret = memcpy_s(dest, len, src, len - 1);                            \
    knl_securec_check(ret);                                                     \
    dest[len - 1] = '\0';                                                       \
} while (0)

#define startlit()  ( yyextra->literallen = 0 )
static void addlit(char *ytext, int yleng, core_yyscan_t yyscanner);
static void addlitchar(unsigned char ychar, core_yyscan_t yyscanner);
static char *litbufdup(core_yyscan_t yyscanner);
static status_t litbuf_udeescape(unsigned char escape, core_yyscan_t yyscanner, char **res);
static unsigned char unescape_single_char(unsigned char c, core_yyscan_t yyscanner);
static int    process_integer_literal(const char *token, YYSTYPE *lval, core_yyscan_t yyscanner);
static bool is_utf16_surrogate_first(uint32 c);
static bool is_utf16_surrogate_second(uint32 c);
static uint32 surrogate_pair_to_codepoint(uint32 first, uint32 second);
static unsigned char* unicode_to_utf8(uint32 c, unsigned char* utf8string);
static status_t addunicode(uint32 c, yyscan_t yyscanner);
static int pg_mblen(const char* mbstr);
static status_t handle_float_overflow(char *token, core_yyscan_t yyscanner, char **result);
static void update_current_location(char *cur_pos, char *origin_str, lex_location_t *loc, bool8 multi_line_sql);
static void flex_alloc_mem(void *context, yy_size_t size, void **buf);
static bool32 need_ignore_for_func(sql_stmt_t *stmt, char* ident, int len);

#define yyerror(msg)                    \
do {                                    \
    scanner_yyerror(msg, yyscanner);    \
    return LEX_ERROR_TOKEN;             \
} while (0)

/*
 * Work around a bug in flex 2.5.35: it emits a couple of functions that
 * it forgets to emit declarations for.  Since we use -Wmissing-prototypes,
 * this would cause warnings.  Providing our own declarations should be
 * harmless even when the bug gets fixed.
 */
extern int    core_yyget_column(yyscan_t yyscanner);
extern void core_yyset_column(int column_no, yyscan_t yyscanner);

/* Some extensions, e.g., shark,
 * may include original PG lexer in addition to their own lexer.
 * This macro allows to add additional logics only at the beginning of PG lexer.
 * So you can undef the macro in your own lexer-related extension
 * to exclude the PG-specific logic.
 */
#define CT_YYLEX
%}

%option reentrant
%option bison-bridge
%option bison-locations
%option 8bit
%option never-interactive
%option nodefault
%option noinput
%option nounput
%option noyywrap
%option noyyalloc
%option noyyrealloc
%option noyyfree
%option warn
%option prefix="core_yy"

/*
 * OK, here is a short description of lex/flex rules behavior.
 * The longest pattern which matches an input string is always chosen.
 * For equal-length patterns, the first occurring in the rules list is chosen.
 * INITIAL is the starting state, to which all non-conditional rules apply.
 * Exclusive states change parsing rules while the state is active.  When in
 * an exclusive state, only those rules defined for that state apply.
 *
 * We use exclusive states for quoted strings, extended comments,
 * and to eliminate parsing troubles for numeric strings.
 * Exclusive states:
 *  <xc> extended C-style comments
 *  <xd> delimited identifiers (double-quoted identifiers)
 *  <xh> hexadecimal numeric string
 *  <xq> standard quoted strings
 *  <xe> extended quoted strings (support backslash escape sequences)
 *  <xdolq> $foo$ quoted strings
 *  <xui> quoted identifier with Unicode escapes
 *  <xus> quoted string with Unicode escapes
 *  <xeu> Unicode surrogate pair in extended quoted string
 */

%x xc
%x xd
%x xh
%x xe
%x xq
%x xdolq
%x xbq
%x xui
%x xus
%x xeu

/*
 * In order to make the world safe for Windows and Mac clients as well as
 * Unix ones, we accept either \n or \r as a newline.  A DOS-style \r\n
 * sequence will be seen as two successive newlines, but that doesn't cause
 * any problems.  Comments that start with -- and extend to the next
 * newline are treated as equivalent to a single whitespace character.
 *
 * NOTE a fine point: if there is no newline following --, we will absorb
 * everything to the end of the input as a comment.  This is correct.  Older
 * versions of Postgres failed to recognize -- as a comment if the input
 * did not end with a newline.
 *
 * XXX perhaps \f (formfeed) should be treated as a newline as well?
 *
 * XXX if you change the set of whitespace characters, fix scanner_isspace()
 * to agree, and see also the plpgsql lexer.
 */

space            [ \t\n\r\f]
horiz_space        [ \t\f]
newline            [\n\r]
non_newline        [^\n\r]
comment            ("--"{non_newline}*)

whitespace        ({space}+|{comment})
whitespace_only    ({space}+)

/*
 * SQL requires at least one newline in the whitespace separating
 * string literals that are to be concatenated.  Silly, but who are we
 * to argue?  Note that {whitespace_with_newline} should not have * after
 * it, whereas {whitespace} should generally have a * after it...
 */

special_whitespace        ({space}+|{comment}{newline})
horiz_whitespace        ({horiz_space}|{comment})
whitespace_with_newline    ({horiz_whitespace}*{newline}{special_whitespace}*)

/*
 * To ensure that {quotecontinue} can be scanned without having to back up
 * if the full pattern isn't matched, we include trailing whitespace in
 * {quotestop}.  This matches all cases where {quotecontinue} fails to match,
 * except for {quote} followed by whitespace and just one "-" (not two,
 * which would start a {comment}).  To cover that we have {quotefail}.
 * The actions for {quotestop} and {quotefail} must throw back characters
 * beyond the quote proper.
 */
quote            '
quotestop        {quote}{whitespace}*
quotecontinue    {quote}{whitespace_with_newline}{quote}
quotefail        {quote}{whitespace}*"-"

/* National character */
xnstart            [nN]{quote}

/* Quoted string that allows backslash escapes */
xestart            [eE]{quote}
xeinside        [^\\']+
xeescape        [\\][^0-7]
xeoctesc        [\\][0-7]{1,3}
xehexesc        [\\]x[0-9A-Fa-f]{1,2}
xeunicode        [\\](u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})
xeunicodefail    [\\](u[0-9A-Fa-f]{0,3}|U[0-9A-Fa-f]{0,7})

/* Extended quote
 * xqdouble implements embedded quote, ''''
 */
xqstart            {quote}
xqdouble        {quote}{quote}
xqinside        [^']+

/* Hexadecimal number */
xhstart			X{quote}
xhinside		[^']*
/* Hexadecimal number, start with 0x */
xhnumber		0x[0-9A-Fa-f]+

/* $foo$ style quotes ("dollar quoting")
 * The quoted string starts with $foo$ where "foo" is an optional string
 * in the form of an identifier, except that it may not contain "$",
 * and extends to the first occurrence of an identical string.
 * There is *no* processing of the quoted text.
 *
 * {dolqfailed} is an error rule to avoid scanner backup when {dolqdelim}
 * fails to match its trailing "$".
 */
dolq_start        [A-Za-z\200-\377_]
dolq_cont        [A-Za-z\200-\377_0-9]
dolqdelim        \$({dolq_start}{dolq_cont}*)?\$
dolqfailed        \${dolq_start}{dolq_cont}*
dolqinside        [^$]+

/* Double quote
 * Allows embedded spaces and other special characters into identifiers.
 */
dquote            \"
xdstart            {dquote}
xdstop            {dquote}
xddouble        {dquote}{dquote}
xdinside        [^"]+

/*
 * backquote quote
 * Allows embedded spaces and other special characters into identifiers.
 */
bquote			\`
xbqstart		{bquote}
xbqstop			{bquote}
xbqinside		[^`]+

/* Unicode escapes */
uescape            [uU][eE][sS][cC][aA][pP][eE]{whitespace}*{quote}[^']{quote}
/* error rule to avoid backup */
uescapefail        ("-"|[uU][eE][sS][cC][aA][pP][eE]{whitespace}*"-"|[uU][eE][sS][cC][aA][pP][eE]{whitespace}*{quote}[^']|[uU][eE][sS][cC][aA][pP][eE]{whitespace}*{quote}|[uU][eE][sS][cC][aA][pP][eE]{whitespace}*|[uU][eE][sS][cC][aA][pP]|[uU][eE][sS][cC][aA]|[uU][eE][sS][cC]|[uU][eE][sS]|[uU][eE]|[uU])

/* Quoted identifier with Unicode escapes */
xuistart        [uU]&{dquote}
xuistop1        {dquote}{whitespace}*{uescapefail}?
xuistop2        {dquote}{whitespace}*{uescape}

/* Quoted string with Unicode escapes */
xusstart        [uU]&{quote}
xusstop1        {quote}{whitespace}*{uescapefail}?
xusstop2        {quote}{whitespace}*{uescape}

/* error rule to avoid backup */
xufailed        [uU]&


/* C-style comments
 *
 * The "extended comment" syntax closely resembles allowable operator syntax.
 * The tricky part here is to get lex to recognize a string starting with
 * slash-star as a comment, when interpreting it as an operator would produce
 * a longer match --- remember lex will prefer a longer match!  Also, if we
 * have something like plus-slash-star, lex will think this is a 3-character
 * operator whereas we want to see it as a + operator and a comment start.
 * The solution is two-fold:
 * 1. append {op_chars}* to xcstart so that it matches as much text as
 *    {operator} would. Then the tie-breaker (first matching rule of same
 *    length) ensures xcstart wins.  We put back the extra stuff with yyless()
 *    in case it contains a star-slash that should terminate the comment.
 * 2. In the operator rule, check for slash-star within the operator, and
 *    if found throw it back with yyless().  This handles the plus-slash-star
 *    problem.
 * Dash-dash comments have similar interactions with the operator rule.
 */
xcstart            \/\*{op_chars}*
xcstop            \*+\/
xcinside        [^*/]+

digit            [0-9]
ident_start        [A-Za-z\200-\377_\#]
ident_cont        [A-Za-z\200-\377_0-9\$\#]

identifier        {ident_start}{ident_cont}*

typecast        "::"
plus_join        "(+)"
dot_dot            \.\.
colon_equals    ":="
para_equals    "=>"

set_ident_start    "@@"
set_ident_cont    [A-Za-z\200-\377_0-9\$\#]
set_identifier    {set_ident_start}{set_ident_cont}*

/*
 * "self" is the set of chars that should be returned as single-character
 * tokens.  "op_chars" is the set of chars that can make up "Op" tokens,
 * which can be one or more characters long (but if a single-char token
 * appears in the "self" set, it is not to be returned as an Op).  Note
 * that the sets overlap, but each has some chars that are not in the other.
 *
 * If you change either set, adjust the character lists appearing in the
 * rule for "operator"!
 */
self            [,()\[\].;\:\+\-\*\/\%\^\<\>\=\@\&\|]
op_chars        [\~\!\#\^\&\|\?\+\-\*\/\%\<\>\=\@]
operator        {op_chars}+

/* we no longer allow unary minus in numbers.
 * instead we pass it separately to parser. there it gets
 * coerced via doNegate() -- Leon aug 20 1999
 *
* {decimalfail} is used because we would like "1..10" to lex as 1, dot_dot, 10.
*
 * {realfail1} and {realfail2} are added to prevent the need for scanner
 * backup when the {real} rule fails to match completely.
 */

integer            {digit}+
decimal            (({digit}*\.{digit}+)|({digit}+\.{digit}*))
decimalfail        {digit}+\.\.
decimalf        ({integer}|{decimal})[fF]
decimald        ({integer}|{decimal})[dD]
real            ({integer}|{decimal})[Ee][-+]?{digit}+
realfail1        ({integer}|{decimal})[Ee]
realfail2        ({integer}|{decimal})[Ee][-+]
realf           ({real})[fF]
reald           ({real})[dD]

size_b           ({integer})[bB]
size_kb          ({integer})[kK]
size_mb          ({integer})[mM]
size_gb          ({integer})[gG]
size_tb          ({integer})[tT]
size_pb          ({integer})[pP]
size_eb          ({integer})[eE]

param            \${integer}

newParam        :({identifier}|{integer})

newArray        :({identifier}|{integer}){space}*\]

set_user_cont            [A-Za-z\377_0-9\$\.]
set_user_escape_quote        [^']
set_user_escape_dquote        [^"]
set_user_escape_bquote        [^`]    
setUserIdentifier        @(({set_user_cont}+)|(\'{set_user_escape_quote}+\')|(\"{set_user_escape_dquote}+\")|(\`{set_user_escape_bquote}+\`))

other            .

/*
 * Dollar quoted strings are totally opaque, and no escaping is done on them.
 * Other quoted strings must allow some special characters such as single-quote
 *  and newline.
 * Embedded single-quotes are implemented both in the SQL standard
 *  style of two adjacent single quotes "''" and in the Postgres/Java style
 *  of escaped-quote "\'".
 * Other embedded escaped characters are matched explicitly and the leading
 *  backslash is dropped from the string.
 * Note that xcstart must appear before operator, as explained above!
 *  Also whitespace (comment) must appear before operator.
 */

%%

{whitespace_only}    {
                    /* ignore */
                }

{comment}        {
                    if (yyextra->include_ora_comment)
                    {
                        SET_YYLLOC();
                        addlit(yytext, yyleng, yyscanner);
                        yylval->str = litbufdup(yyscanner);
                        return COMMENTSTRING;
                    }
                    /* ignore */
                }

{xcstart}    {
                    /* Set location in case of syntax error in comment */
                    SET_YYLLOC();
                    yyextra->xcdepth = 0;
                    BEGIN(xc);
                    /* Put back any characters past slash-star; see above */
                    yyless(2);
                    if (COMMENT_NOT_IGNORED())
                    {
                        startlit();
                        addlit(yytext, yyleng, yyscanner);
                    }
        }

<xc>{xcstart}    {
                    (yyextra->xcdepth)++;
                    /* Put back any characters past slash-star; see above */
                    yyless(2);
                    if (COMMENT_NOT_IGNORED())
                    {
                        addlit(yytext, yyleng, yyscanner);
                    }
        }

<xc>{xcstop}    {
                    if (yyextra->xcdepth <= 0)
                        BEGIN(INITIAL);
                    else
                        (yyextra->xcdepth)--;

                    if (COMMENT_NOT_IGNORED())
                    {    
                        addlit(yytext, yyleng, yyscanner);
                        yylval->str = litbufdup(yyscanner);
                        yyleng = yyextra->literallen;
                        yyextra->is_hint_str = false;
                        return COMMENTSTRING;
                    }
        }

<xc>{xcinside}    {
                    if (COMMENT_NOT_IGNORED())
                    {
                        addlit(yytext, yyleng, yyscanner);
                    }
        }

<xc>{op_chars}    {
                    if (COMMENT_NOT_IGNORED())
                    {
                        addlit(yytext, yyleng, yyscanner);
                    }
        }

<xc>\*+        {
                    if (COMMENT_NOT_IGNORED())
                    {
                        addlit(yytext, yyleng, yyscanner);
                    }
        }

<xc><<EOF>>        { yyerror("unterminated /* comment"); return 0;}

{xnstart}        {
                    /* National character.
                     * We will pass this along as a normal character string,
                     * but preceded with an internally-generated "NCHAR".
                     */
                    int kwnum;

                    SET_YYLLOC();
                    yyless(1);                /* eat only 'n' this time */

                    kwnum = ScanKeywordLookup("nchar",
                                              yyextra->keywordlist);
                    if (kwnum >= 0)
                    {
                        yyextra->is_hint_str = false;
                        yylval->keyword = GetScanKeyword(kwnum, yyextra->keywordlist);
                        return yyextra->keyword_tokens[kwnum];
                    }
                    else
                    {
                        /* If NCHAR isn't a keyword, just return "n" */
                        FLEX_MEM_STRDUP(yylval->str, "n");
                        yyextra->ident_quoted = false;
                        yyextra->is_hint_str = false;
                        yyextra->origin_str = NULL;
                        return IDENT;
                    }
                }

{xqstart}        {
                    yyextra->warn_on_first_escape = true;
                    yyextra->saw_non_ascii = false;
                    SET_YYLLOC();
                    BEGIN(xq);
                    startlit();
                }
{xestart}        {
                    yyextra->warn_on_first_escape = false;
                    yyextra->saw_non_ascii = false;
                    SET_YYLLOC();
                    BEGIN(xe);
                    startlit();
                }
{xusstart}        {
                    SET_YYLLOC();
                    BEGIN(xus);
                    startlit();
                }
<xq,xe>{quotestop}    |
<xq,xe>{quotefail} {
                    yyless(1);
                    BEGIN(INITIAL);
                    /*
                     * check that the data remains valid if it might have been
                     * made invalid by unescaping any chars.
                     */
                    yylval->str = litbufdup(yyscanner);
                    yyleng = yyextra->literallen + 2;
                    yyextra->is_hint_str = false;
                    return SCONST;
                }
<xus>{xusstop1} {
                    /* throw back all but the quote */
                    yyless(1);
                    BEGIN(INITIAL);
                    if (litbuf_udeescape('\\', yyscanner, &yylval->str) != OG_SUCCESS) {
                        yyerror("invalid Unicode character");
                    }
                    yyleng = yyextra->literallen + 3 + yyleng;
                    yyextra->is_hint_str = false;
                    return SCONST;
        }
<xus>{xusstop2} {
                    BEGIN(INITIAL);
                    if (litbuf_udeescape(yytext[yyleng-2], yyscanner, &yylval->str) != OG_SUCCESS) {
                        yyerror("invalid Unicode character");
                    }
                    yyleng = yyextra->literallen + 3 + yyleng;
                    yyextra->is_hint_str = false;
                    return SCONST;
        }
<xq,xe,xus>{xqdouble} {
                    addlitchar('\'', yyscanner);
                }
<xq,xus>{xqinside}  {
                    addlit(yytext, yyleng, yyscanner);
                }
<xe>{xeinside}  {
                    addlit(yytext, yyleng, yyscanner);
                }
<xe>{xeunicode} {
                    uint32 c = strtoul(yytext+2, NULL, 16);

                    if (is_utf16_surrogate_first(c))
                    {
                        yyextra->utf16_first_part = c;
                        BEGIN(xeu);
                    } else if (is_utf16_surrogate_second(c)) {
                        yyerror("invalid Unicode surrogate pair");
                    } else {
                        if (addunicode(c, yyscanner) != OG_SUCCESS) {
                            yyerror("invalid Unicode escape value");
                        }
                    }
                }
<xeu>{xeunicode} {
                    uint32 c = strtoul(yytext+2, NULL, 16);

                    if (!is_utf16_surrogate_second(c))
                        yyerror("invalid Unicode surrogate pair");

                    c = surrogate_pair_to_codepoint(yyextra->utf16_first_part, c);

                    if (addunicode(c, yyscanner) != OG_SUCCESS) {
                        yyerror("invalid Unicode escape value");
                    }

                    BEGIN(xe);
                }
<xeu>.            { yyerror("invalid Unicode surrogate pair"); }
<xeu>\n            { yyerror("invalid Unicode surrogate pair"); }
<xeu><<EOF>>    { yyerror("invalid Unicode surrogate pair"); }
<xe,xeu>{xeunicodefail}    {
                }
<xe>{xeescape}  {
                    addlitchar(unescape_single_char(yytext[1], yyscanner),
                               yyscanner);
                }
<xe>{xeoctesc}  {
                    unsigned char c = strtoul(yytext+1, NULL, 8);

                    addlitchar(c, yyscanner);
                    if (c == '\0' || IS_HIGHBIT_SET(c))
                        yyextra->saw_non_ascii = true;
                }
<xe>{xehexesc}  {
                    unsigned char c = strtoul(yytext+2, NULL, 16);

                    addlitchar(c, yyscanner);
                    if (c == '\0' || IS_HIGHBIT_SET(c))
                        yyextra->saw_non_ascii = true;
                }
<xq,xe,xus>{quotecontinue} {
                    /* ignore */
                }
<xe>.            {
                    /* This is only needed for \ just before EOF */
                    addlitchar(yytext[0], yyscanner);
                }
<xq,xe,xus><<EOF>>        { yyerror("unterminated quoted string"); return 0;}

<xh>{xhinside}  {
                    addlit(yytext, yyleng, yyscanner);
                }
<xh>{quotecontinue} {
                        /* ignore */
                    }
{xhstart}   {
                SET_YYLLOC();
                BEGIN(xh);
                startlit();
                addlit(yytext, yyleng, yyscanner);
            }
<xh>{quotestop} |
<xh>{quotefail} {
                    BEGIN(INITIAL);
                    addlitchar('\'', yyscanner);
                    yylval->str = litbufdup(yyscanner);
                    yyextra->is_hint_str = false;
                    return XCONST;
                }
<xh><<EOF>> { yyerror("unterminated hexadecimal string literal"); return 0;}
{dolqdelim}        {
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yyextra->dolqstart, yytext);
                    BEGIN(xdolq);
                    startlit();
                }
{dolqfailed}    {
                    SET_YYLLOC();
                    /* throw back all but the initial "$" */
                    yyless(1);
                    /* and treat it as {other} */
                    yyextra->is_hint_str = false;
                    return yytext[0];
                }
<xdolq>{dolqdelim} {
                    if (strcmp(yytext, yyextra->dolqstart) == 0)
                    {
                        free(yyextra->dolqstart);
                        yyextra->dolqstart = NULL;
                        BEGIN(INITIAL);
                        yylval->str = litbufdup(yyscanner);
                        yyextra->is_hint_str = false;
                        return SCONST;
                    }
                    else
                    {
                        /*
                         * When we fail to match $...$ to dolqstart, transfer
                         * the $... part to the output, but put back the final
                         * $ for rescanning.  Consider $delim$...$junk$delim$
                         */
                        addlit(yytext, yyleng-1, yyscanner);
                        yyless(yyleng-1);
                    }
                }
<xdolq>{dolqinside} {
                    addlit(yytext, yyleng, yyscanner);
                }
<xdolq>{dolqfailed} {
                    addlit(yytext, yyleng, yyscanner);
                }
<xdolq>.        {
                    /* This is only needed for $ inside the quoted text */
                    addlitchar(yytext[0], yyscanner);
                }
<xdolq><<EOF>>    { yyerror("unterminated dollar-quoted string"); return 0;}

{xdstart}        {
                    SET_YYLLOC();
                    BEGIN(xd);
                    startlit();
                }
{xuistart}        {
                    SET_YYLLOC();
                    BEGIN(xui);
                    startlit();
                }
{xbqstart}      {
                    SET_YYLLOC();
                    BEGIN(xbq);
                    startlit();
                }
<xd>{xdstop}    {
                    char           *ident;

                    BEGIN(INITIAL);
                    if (yyextra->literallen == 0)
                        yyerror("zero-length delimited identifier");
                    ident = litbufdup(yyscanner);
                    yylval->str = ident;
                    yyleng = yyextra->literallen + 2;
                    yyextra->ident_quoted = true;
                    yyextra->is_hint_str = false;
                    yyextra->origin_str = NULL;
                    return IDENT;
                }
<xui>{xuistop1}    {
                    char           *ident;

                    BEGIN(INITIAL);
                    if (yyextra->literallen == 0)
                        yyerror("zero-length delimited identifier");
                    if (litbuf_udeescape('\\', yyscanner, &ident) != OG_SUCCESS) {
                        yyerror("invalid Unicode character");
                    }
                    yylval->str = ident;
                    /* throw back all but the quote */
                    yyless(1);
                    yyleng = yyextra->literallen + 3 + yyleng;
                    yyextra->ident_quoted = false;
                    yyextra->is_hint_str = false;
                    yyextra->origin_str = NULL;
                    return IDENT;
                }
<xui>{xuistop2}    {
                    char           *ident;

                    BEGIN(INITIAL);
                    if (yyextra->literallen == 0)
                        yyerror("zero-length delimited identifier");
                    if (litbuf_udeescape(yytext[yyleng - 2], yyscanner, &ident) != OG_SUCCESS) {
                        yyerror("invalid Unicode character");
                    }
                    yylval->str = ident;
                    yyleng = yyextra->literallen + 3 + yyleng;
                    yyextra->ident_quoted = false;
                    yyextra->is_hint_str = false;
                    yyextra->origin_str = NULL;
                    return IDENT;
                }
<xbq>{xbqstop}  {
                BEGIN(INITIAL);
                if (yyextra->literallen == 0)
                    yyerror("zero-length delimited identifier");
                char *ident = litbufdup(yyscanner);
                yylval->str = ident;
                yyextra->ident_quoted = true;
                yyextra->is_hint_str = false;
                return IDENT;
            }
<xd,xui>{xddouble}    {
                    addlitchar('"', yyscanner);
                }
<xd,xui>{xdinside}    {
                    addlit(yytext, yyleng, yyscanner);
                }
<xbq>{xbqinside}    {
                        addlit(yytext, yyleng, yyscanner);
                    }
<xd,xui><<EOF>>        { yyerror("unterminated quoted identifier"); return 0;}

{xufailed}    {
                    char           *ident;

                    SET_YYLLOC();
                    /* throw back all but the initial u/U */
                    yyless(1);
                    /* and treat it as {identifier} */
                    ident = downcase_truncate_identifier(yytext, yyleng, yyextra->warnOnTruncateIdent);
                    yylval->str = ident;
                    yyextra->ident_quoted = false;
                    yyextra->is_hint_str = false;
                    yyextra->origin_str = NULL;
                    return IDENT;
                }

{typecast}        {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return TYPECAST;
                }

{plus_join}    {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return ORA_JOINOP;
                }

{dot_dot}        {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return DOT_DOT;
                }

{colon_equals}    {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return COLON_EQUALS;
                }

{para_equals}    {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return PARA_EQUALS;
                }

{self}            {
                    SET_YYLLOC();
                    /*
                     * Get the semicolon which is not in proc body nor in the '( )', treat it
                     * as end flag of a single query and store it in locationlist.
                     */
                    if (yyextra->dolqstart == NULL)
                    {
                        if (yytext[0] == '(')
                            yyextra->paren_depth++;
                        else if (yytext[0] == ')' && yyextra->paren_depth > 0)
                            yyextra->paren_depth--;
                    }
                    yyextra->is_hint_str = false;
                    return yytext[0];
                }

{operator}        {
                    /*
                     * Check for embedded slash-star or dash-dash; those
                     * are comment starts, so operator must stop there.
                     * Note that slash-star or dash-dash at the first
                     * character will match a prior rule, not this one.
                     */
                    int        nchars = yyleng;
                    char   *slashstar = strstr(yytext, "/*");
                    char   *dashdash = strstr(yytext, "--");

                    if (slashstar && dashdash)
                    {
                        /* if both appear, take the first one */
                        if (slashstar > dashdash)
                            slashstar = dashdash;
                    }
                    else if (!slashstar)
                        slashstar = dashdash;
                    if (slashstar)
                        nchars = slashstar - yytext;

                    char *qMark = strstr(yytext, "?");
                    if (qMark != NULL) {
                        if (nchars == 1) {
                            /* single ?, treat as param */
                            SET_YYLLOC();
                            yylval->ival = 1;
                            yyextra->is_hint_str = false;
                            return PARAM;
                        }

                        /* multibyte, get ? postition */
                        nchars = qMark - yytext;
                        if (nchars == 0) {
                            /* begin with ?, strip all char except fist ?, treat first ? as param */
                            yyless(1);
                            SET_YYLLOC();
                            yylval->ival = 1;
                            yyextra->is_hint_str = false;
                            return PARAM;
                        }
                        /*
                         * else not begin with ?, strip all char after ?, should do yyless(nchars).
                         * since it will be done in 'if (nchars < (int)yyleng)', so nothing to do here.
                         */
                    }

                    /*
                     * For SQL compatibility, '+' and '-' cannot be the
                     * last char of a multi-char operator unless the operator
                     * contains chars that are not in SQL operators.
                     * The idea is to lex '=-' as two operators, but not
                     * to forbid operator names like '?-' that could not be
                     * sequences of SQL operators.
                     */
                    while (nchars > 1 &&
                           (yytext[nchars-1] == '+' ||
                            yytext[nchars-1] == '-'))
                    {
                        int        ic;

                        for (ic = nchars-2; ic >= 0; ic--)
                        {
                            if (strchr("~!#^&|?%", yytext[ic]))
                                break;
                        }
                        if (ic >= 0)
                            break; /* found a char that makes it OK */
                        nchars--; /* else remove the +/-, and check again */
                    }

                    SET_YYLLOC();

                    if (nchars < (int)yyleng)
                    {
                        /* Strip the unwanted chars from the token */
                        yyless(nchars);
                        /*
                         * If what we have left is only one char, and it's
                         * one of the characters matching "self", then
                         * return it as a character token the same way
                         * that the "self" rule would have.
                         */
                        if (nchars == 1 &&
                            strchr(",()[].;:+-*/%^<>=@|&", yytext[0]))
                        {
                            yyextra->is_hint_str = false;
                            return yytext[0];
                        }
                    }

                    /*
                     * Complain if operator is too long.  Unlike the case
                     * for identifiers, we make this an error not a notice-
                     * and-truncate, because the odds are we are looking at
                     * a syntactic mistake anyway.
                     */
                    if (nchars >= NAMEDATALEN)
                        yyerror("operator too long");

                    /* Convert "!=" operator to "<>" for compatibility */
                    if (strcmp(yytext, "!=") == 0 || strcmp(yytext, "^=") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, "<>");
                        yyextra->is_hint_str = false;
                        return CmpOp;
                    }
                    else if (strcmp(yytext, ">=") == 0 || strcmp(yytext, "<=") == 0 || strcmp(yytext, "<>") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return CmpOp;
                    }
                    else if (strcmp(yytext, "||") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return OPER_CAT;
                    }
                    else if (strcmp(yytext, "<<") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return OPER_LSHIFT;
                    }
                    else if (strcmp(yytext, ">>") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return OPER_RSHIFT;
                    }
                    else
                    {
                        yyerror("invalid operator");
                    }
                }
{newArray}        {
                    yyless(1);
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return yytext[0];
                }
{param}            {
                    SET_YYLLOC();
                    yylval->ival = strlen(yytext);
                    yyextra->is_hint_str = false;
                    return PARAM;
                }
{newParam}        {
                    SET_YYLLOC();
                    yylval->ival = strlen(yytext);
                    yyextra->is_hint_str = false;
                    return PARAM;
                }
{xhnumber}  {
                SET_YYLLOC();
                yyextra->is_hint_str = false;
                FLEX_MEM_STRDUP(yylval->str, yytext);
                return XCONST;
            }
{integer}        {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return process_integer_literal(yytext, yylval, yyscanner);
                }
{decimal}        {
                    SET_YYLLOC();
                    char* val = NULL;
                    FLEX_STACK_STRDUP(val, yytext);
                    if (handle_float_overflow(val, yyscanner, &val) != OG_SUCCESS) {
                        yyerror("number overflow");
                    }
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{decimalfail}    {
                    /* throw back the .., and treat as integer */
                    yyless(yyleng-2);
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return process_integer_literal(yytext, yylval, yyscanner);
                }
{decimalf}        {
                    yyless(yyleng-1);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{realf}            {
                    yyless(yyleng-1);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{decimald}        {
                    yyless(yyleng-1);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{reald}            {
                    yyless(yyleng-1);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{real}            {
                    SET_YYLLOC();
                    char *val = NULL;
                    FLEX_STACK_STRDUP(val, yytext);
                    if (handle_float_overflow(val, yyscanner, &val) != OG_SUCCESS) {
                        yyerror("number overflow");
                    }
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{realfail1}        {
                    /*
                     * throw back the [Ee], and treat as {decimal}.  Note
                     * that it is possible the input is actually {integer},
                     * but since this case will almost certainly lead to a
                     * syntax error anyway, we don't bother to distinguish.
                     */
                    yyless(yyleng-1);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{realfail2}        {
                    /* throw back the [Ee][+-], and proceed as above */
                    yyless(yyleng-2);
                    SET_YYLLOC();
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return FCONST;
                }
{size_b}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_B;
                }
{size_kb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_KB;
                }
{size_mb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_MB;
                }
{size_gb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_GB;
                }
{size_tb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_TB;
                }
{size_pb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_PB;
                }
{size_eb}            {
                        SET_YYLLOC();
                        FLEX_STACK_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return SIZE_EB;
                }

{set_identifier} {
                    SET_YYLLOC();
                    yyless(2);
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return Op;
                }

{identifier}    {
                    int kwnum;
                    char *ident;

                    SET_YYLLOC();

                    /* Is it a keyword? */
                    kwnum = ScanKeywordLookup(yytext, yyextra->keywordlist);

                    yyextra->is_hint_str = false;
                    if (kwnum >= 0 && !need_ignore_for_func(yyextra->stmt, yytext, yyleng))
                    {
                        yylval->keyword = GetScanKeyword(kwnum, yyextra->keywordlist);
                        uint16 token = yyextra->keyword_tokens[kwnum];

                        /* Find the CREATE PROCEDURE syntax and set dolqstart. */
                        if (token == CREATE)
                        {
                            yyextra->is_createstmt = true;
                        }
                        else if (token == TRIGGER && yyextra->is_createstmt)
                        {
                            /* Create trigger don't need set dolqstart */
                            yyextra->is_createstmt = false;
                        }
                        if (token == SELECT || token == UPDATE || token == INSERT || token == DELETE_P ||
                            token == MERGE)
                        {
                            yyextra->is_hint_str = true;
                        }

                        return token;
                    }

                    /*
                     * No.  Convert the identifier to upper case, and truncate
                     * if necessary.
                     */
                    ident = upcase_truncate_identifier(yytext, yyleng, yyextra->warnOnTruncateIdent);
                    /* Is it _charset? */
                    yylval->str = ident;
                    yyextra->ident_quoted = false;
                    FLEX_MEM_STRDUP(yyextra->origin_str, yytext);
                    return IDENT;
                }

{setUserIdentifier}    {
                    SET_YYLLOC();
                    yyless(1);
                    FLEX_MEM_STRDUP(yylval->str, yytext);
                    yyextra->is_hint_str = false;
                    return yytext[0];
                }

{other}            {
                    SET_YYLLOC();
                    yyextra->is_hint_str = false;
                    return yytext[0];
                }

<<EOF>>            {
                    SET_YYLLOC();
                    yyterminate();
                }

%%

/*
 * Arrange access to yyextra for subroutines of the main yylex() function.
 * We expect each subroutine to have a yyscanner parameter.  Rather than
 * use the yyget_xxx functions, which might or might not get inlined by the
 * compiler, we cheat just a bit and cast yyscanner to the right type.
 */
#undef yyextra
#define yyextra  (((struct yyguts_t *) yyscanner)->yyextra_r)

/* Likewise for a couple of other things we need. */
#undef yylloc
#define yylloc  (((struct yyguts_t *) yyscanner)->yylloc_r)
#undef yyleng
#define yyleng  (((struct yyguts_t *) yyscanner)->yyleng_r)

/*
 * scanner_yyerror
 *        Report a lexer or grammar error.
 *
 * The message's cursor position is whatever YYLLOC was last set to,
 * ie, the start of the current token if called within yylex(), or the
 * most recently lexed token if called from the grammar.
 * This is OK for syntax error messages from the Bison parser, because Bison
 * parsers report error as soon as the first unparsable token is reached.
 * Beware of using yyerror for other purposes, as the cursor position might
 * be misleading!
 */
void
scanner_yyerror(const char *message, core_yyscan_t yyscanner)
{
    OG_SRC_THROW_ERROR(yylloc->loc, ERR_SQL_SYNTAX_ERROR, message);
    return;
}

/*
 * Called before any actual parsing is done
 */
static int ct_yylex_init(yyscan_t* ptr_yy_globals, sql_stmt_t *stmt)
{
    if (ptr_yy_globals == NULL){
        errno = EINVAL;
        return 1;
    }

    flex_alloc_mem(stmt->context, sizeof(struct yyguts_t), (void **)ptr_yy_globals);

    if (*ptr_yy_globals == NULL){
        errno = ENOMEM;
        return 1;
    }

    /* By setting to 0xAA, we expose bugs in yy_init_globals. Leave at 0x00 for releases. */
    memset(*ptr_yy_globals,0x00,sizeof(struct yyguts_t));

    return yy_init_globals(*ptr_yy_globals);
}


core_yyscan_t
scanner_init(const sql_text_t *sql,
             core_yy_extra_type *yyext,
             const ScanKeywordList *keywordlist,
             const uint16 *keyword_tokens,
             sql_stmt_t *stmt)
{
    size_t        slen = sql->len;
    const char *str = sql->str;
    yyscan_t    scanner;

    if (ct_yylex_init(&scanner, stmt) != 0) {
        return NULL;
    }

    core_yyset_extra(yyext, scanner);

    yyext->keywordlist = keywordlist;
    yyext->keyword_tokens = keyword_tokens;
    yyext->in_slash_proc_body = false;
    yyext->paren_depth = 0;
    //yyext->query_string_locationlist = NIL;
    yyext->is_createstmt = false;
    yyext->dolqstart = NULL;
    yyext->is_hint_str = false;
    //yyext->parameter_list = NIL;
    yyext->include_ora_comment = false;
    yyext->func_param_begin = 0;
    yyext->func_param_end = 0;
    yyext->return_pos_end = 0;

    /*
     * Make a scan buffer with special termination needed by flex.
     */
    if (sql_alloc_mem(stmt->context, slen + 2, (void **)&yyext->scanbuf) != OG_SUCCESS) {
        return NULL;
    }
    yyext->scanbuflen = slen;
    yyext->stmt = stmt;
    if (sql_create_array(stmt->context, &yyext->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS) != OG_SUCCESS) {
        return NULL;
    }
    memcpy(yyext->scanbuf, str, slen);
    yyext->scanbuf[slen] = yyext->scanbuf[slen + 1] = YY_END_OF_BUFFER_CHAR;
    yy_scan_buffer(yyext->scanbuf, slen + 2, scanner);

    /* initialize literal buffer to a reasonable but expansible size */
    yyext->literalalloc = 1024;
    if (sql_alloc_mem(stmt->context, yyext->literalalloc, (void **)&yyext->literalbuf) != OG_SUCCESS) {
        return NULL;
    }
    yyext->literallen = 0;
    yyext->warnOnTruncateIdent = true;

    /* plpgsql keyword params */
    yyext->isPlpgsqlKeyWord = false;
    //yyext->plKeywordValue = NULL;
    yyext->is_delimiter_name = false;
    yyext->is_last_colon = false;
    yyext->is_proc_end = false;
    yyext->multi_line_sql = strchr(str, '\n') != NULL;

    return scanner;
}


/*
 * Called after parsing is done to clean up after scanner_init()
 */
void
scanner_finish(core_yyscan_t yyscanner)
{
}


static void
addlit(char *ytext, int yleng, core_yyscan_t yyscanner)
{
    /* enlarge buffer if needed */
    if ((yyextra->literallen + yleng) >= yyextra->literalalloc)
    {
        do
        {
            yyextra->literalalloc *= 2;
        } while ((yyextra->literallen + yleng) >= yyextra->literalalloc);

        /*when yytext is larger than 512M, its double will exceed 1G, so we use repalloc_huge */
        yyextra->literalbuf = (char *) realloc(yyextra->literalbuf,
                                                yyextra->literalalloc);
    }
    /* append new data */
    memcpy(yyextra->literalbuf + yyextra->literallen, ytext, yleng);
    yyextra->literallen += yleng;
}


static void
addlitchar(unsigned char ychar, core_yyscan_t yyscanner)
{
    /* enlarge buffer if needed */
    if ((yyextra->literallen + 1) >= yyextra->literalalloc)
    {
        yyextra->literalalloc *= 2;
        yyextra->literalbuf = (char *) realloc(yyextra->literalbuf,
                                                yyextra->literalalloc);
    }
    /* append new data */
    yyextra->literalbuf[yyextra->literallen] = ychar;
    yyextra->literallen += 1;
}

/*
 * Create a palloc'd copy of literalbuf, adding a trailing null.
 */
static char *
litbufdup(core_yyscan_t yyscanner)
{
    int            llen = yyextra->literallen;
    char       *newm;

    newm = (char *)malloc(llen + 1);
    memcpy(newm, yyextra->literalbuf, llen);
    newm[llen] = '\0';
    return newm;
}

static int
process_integer_literal(const char *token, YYSTYPE *lval, core_yyscan_t yyscanner)
{
    int64        val;
    char       *endptr;

    errno = 0;
    val = strtol(token, &endptr, 10);
    if (*endptr != '\0' || errno == ERANGE
        /* if long > 32 bits, check for overflow of int4 */
        || val != (int64) ((int32) val)
        )
    {
        /* integer too large, treat it as a float */
        FLEX_MEM_STRDUP(lval->str, token);
        return FCONST;
    }
    lval->ival = val;
    return ICONST;
}

/* prejudge whether float const overflow */
status_t 
handle_float_overflow(char *token, core_yyscan_t yyscanner, char **result)
{

    double         val;
    char       *endptr;
    *result = token;

    errno = 0;
    val = strtod(*result, &endptr);

    if (errno == ERANGE) {
        if (val == 0.0 || val >= HUGE_VAL || val <= -HUGE_VAL) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static uint32
hexval(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 0xA;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 0xA;
    return 0; /* not reached */
}

static status_t 
check_unicode_value(uint32 c, const char *loc, core_yyscan_t yyscanner)
{
    if (c > 0x7F)
    {
        ADVANCE_YYLLOC(loc - yyextra->literalbuf + 3);   /* 3 for U&" */
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool
is_utf16_surrogate_first(uint32 c)
{
    return (c >= 0xD800 && c <= 0xDBFF);
}

static bool
is_utf16_surrogate_second(uint32 c)
{
    return (c >= 0xDC00 && c <= 0xDFFF);
}

static uint32
surrogate_pair_to_codepoint(uint32 first, uint32 second)
{
    return ((first & 0x3FF) << 10) + 0x10000 + (second & 0x3FF);
}

static unsigned char* unicode_to_utf8(uint32 c, unsigned char* utf8string)
{
    if (c <= 0x7F) {
        utf8string[0] = c;
    } else if (c <= 0x7FF) {
        utf8string[0] = 0xC0 | ((c >> 6) & 0x1F);
        utf8string[1] = 0x80 | (c & 0x3F);
    } else if (c <= 0xFFFF) {
        utf8string[0] = 0xE0 | ((c >> 12) & 0x0F);
        utf8string[1] = 0x80 | ((c >> 6) & 0x3F);
        utf8string[2] = 0x80 | (c & 0x3F);
    } else {
        utf8string[0] = 0xF0 | ((c >> 18) & 0x07);
        utf8string[1] = 0x80 | ((c >> 12) & 0x3F);
        utf8string[2] = 0x80 | ((c >> 6) & 0x3F);
        utf8string[3] = 0x80 | (c & 0x3F);
    }

    return utf8string;
}

static int pg_mblen(const char* mbstr)
{
    return 1;
}

static status_t addunicode(uint32 c, core_yyscan_t yyscanner)
{
    char buf[8];

    if (c == 0 || c > 0x10FFFF)  {
        return OG_ERROR;
    }
    if (c > 0x7F)
    {
        yyextra->saw_non_ascii = true;
    }
    unicode_to_utf8(c, (unsigned char *) buf);
    addlit(buf, pg_mblen(buf), yyscanner);
    return OG_SUCCESS;
}

static status_t litbuf_udeescape(unsigned char escape, core_yyscan_t yyscanner, char **res)
{
    char *litbuf, *in, *out;
    uint32 pair_first = 0;

    if (isxdigit(escape)
        || escape == '+'
        || escape == '\''
        || escape == '"'
        || scanner_isspace(escape))
    {
        ADVANCE_YYLLOC(yyextra->literallen + yyleng + 1);
        return OG_ERROR;
    }

    /* Make literalbuf null-terminated to simplify the scanning loop */
    litbuf = yyextra->literalbuf;
    litbuf[yyextra->literallen] = '\0';

    /*
     * This relies on the subtle assumption that a UTF-8 expansion
     * cannot be longer than its escaped representation.
     */
    *res = (char *)malloc(yyextra->literallen + 1);
    char *newm = *res;

    in = litbuf;
    out = newm;
    while (*in)
    {
        if (in[0] == escape)
        {
            if (in[1] == escape)
            {
                if (pair_first)
                {
                    ADVANCE_YYLLOC(in - litbuf + 3);   /* 3 for U&" */
                    return OG_ERROR;
                }
                *out++ = escape;
                in += 2;
            }
            else if (isxdigit((unsigned char) in[1]) &&
                     isxdigit((unsigned char) in[2]) &&
                     isxdigit((unsigned char) in[3]) &&
                     isxdigit((unsigned char) in[4]))
            {
                uint32 unicode;

                unicode = (hexval(in[1]) << 12) +
                    (hexval(in[2]) << 8) +
                    (hexval(in[3]) << 4) +
                    hexval(in[4]);
                if (check_unicode_value(unicode, in, yyscanner) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                if (pair_first)
                {
                    if (is_utf16_surrogate_second(unicode))
                    {
                        unicode = surrogate_pair_to_codepoint(pair_first, unicode);
                        pair_first = 0;
                    }
                    else
                    {
                        ADVANCE_YYLLOC(in - litbuf + 3);   /* 3 for U&" */
                        return OG_ERROR;
                    }
                }
                else if (is_utf16_surrogate_second(unicode))
                    return OG_ERROR;

                if (is_utf16_surrogate_first(unicode))
                    pair_first = unicode;
                else
                {
                    unicode_to_utf8(unicode, (unsigned char *) out);
                    out += pg_mblen(out);
                }
                in += 5;
            }
            else if (in[1] == '+' &&
                     isxdigit((unsigned char) in[2]) &&
                     isxdigit((unsigned char) in[3]) &&
                     isxdigit((unsigned char) in[4]) &&
                     isxdigit((unsigned char) in[5]) &&
                     isxdigit((unsigned char) in[6]) &&
                     isxdigit((unsigned char) in[7]))
            {
                uint32 unicode;

                unicode = (hexval(in[2]) << 20) +
                    (hexval(in[3]) << 16) +
                    (hexval(in[4]) << 12) +
                    (hexval(in[5]) << 8) +
                    (hexval(in[6]) << 4) +
                    hexval(in[7]);
                if (check_unicode_value(unicode, in, yyscanner) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                if (pair_first)
                {
                    if (is_utf16_surrogate_second(unicode))
                    {
                        unicode = surrogate_pair_to_codepoint(pair_first, unicode);
                        pair_first = 0;
                    }
                    else
                    {
                        ADVANCE_YYLLOC(in - litbuf + 3);   /* 3 for U&" */
                        return OG_ERROR;
                    }
                }
                else if (is_utf16_surrogate_second(unicode))
                    return OG_ERROR;

                if (is_utf16_surrogate_first(unicode))
                    pair_first = unicode;
                else
                {
                    unicode_to_utf8(unicode, (unsigned char *) out);
                    out += pg_mblen(out);
                }
                in += 8;
            }
            else
            {
                ADVANCE_YYLLOC(in - litbuf + 3);   /* 3 for U&" */
                return OG_ERROR;
            }
        }
        else
        {
            if (pair_first)
            {
                ADVANCE_YYLLOC(in - litbuf + 3);   /* 3 for U&" */
                return OG_ERROR;
            }
            *out++ = *in++;
        }
    }

    /* unfinished surrogate pair? */
    if (pair_first)
    {
        ADVANCE_YYLLOC(in - litbuf + 3);            /* 3 for U&" */
        return OG_ERROR;
    }

    *out = '\0';
    return OG_SUCCESS;
}

static unsigned char
unescape_single_char(unsigned char c, core_yyscan_t yyscanner)
{
    switch (c)
    {
        case 'b':
            return '\b';
        case 'f':
            return '\f';
        case 'n':
            return '\n';
        case 'r':
            return '\r';
        case 't':
            return '\t';
        default:
            /* check for backslash followed by non-7-bit-ASCII */
            if (c == '\0' || IS_HIGHBIT_SET(c))
                yyextra->saw_non_ascii = true;

            return c;
    }
}

/*
 * Interface functions to make flex use palloc() instead of malloc().
 * It'd be better to make these static, but flex insists otherwise.
 */

static void flex_alloc_mem(void *context, yy_size_t size, void **buf)
{
    void *ptr = NULL;
    yy_size_t len = size + FLEX_MEM_HEADER_SIZE;
    sql_alloc_mem(context, len, (void **)&ptr);

    flex_mem_header *header = (flex_mem_header*)ptr;
    header->magic_number = FLEX_MEM_MAGIC_NUMBER;
    header->bytes = size;

    *buf = FLEX_MEM_GET_POINTER(ptr);
}

void *
core_yyalloc(yy_size_t bytes, core_yyscan_t yyscanner)
{
    void *buf = NULL;
    flex_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, bytes, (void **)&buf);
    return buf;
}

void *
core_yyrealloc(void *ptr, yy_size_t bytes, core_yyscan_t yyscanner)
{
    void *buf = NULL;
    flex_alloc_mem(og_yyget_extra(yyscanner)->core_yy_extra.stmt->context, bytes, (void **)&buf);

    if (ptr) {
        flex_mem_header *old_header = FLEX_MEM_GET_HEADER(ptr);
        CM_ASSERT(old_header->magic_number == FLEX_MEM_MAGIC_NUMBER);

        errno_t err = memcpy_s(buf, bytes, ptr, old_header->bytes);
        if (err != EOK) {
            scanner_yyerror("realloc failed", yyscanner);
        }
    }
    return buf;
}

void
core_yyfree(void *ptr, core_yyscan_t yyscanner)
{
    return;
}

int ct_yyget_leng(core_yyscan_t yyscanner)
{
    return ((struct yyguts_t *) yyscanner)->yyleng_r;
}

static void update_current_location(char *cur_pos, char *origin_str, lex_location_t *loc, bool8 multi_line_sql)
{
    loc->offset = cur_pos - origin_str;
    /* quick check, origin string don't have '\n', so line num always 1, just need to update column num */
    if (!multi_line_sql) {
        loc->loc.line = 1;
        loc->loc.column = loc->offset + 1;
        return;
    }

    /* reset location, maybe we have better way to use last loction to speed calculate... */
    loc->loc.line = 1;
    loc->loc.column = 1;
    /* calculate current line and column num */
    while (origin_str < cur_pos) {
        if (*origin_str == '\n') {
            loc->loc.line++;
            loc->loc.column = 1;
        } else {
            loc->loc.column++;
        }
        origin_str++;
    }

    /* end of new line: 'insert into\n;' */
    if (*origin_str == '\0') {
        loc->loc.line++;
        loc->loc.column = 1;
    }
    return;
}

static bool32 need_ignore_for_func(sql_stmt_t *stmt, char* ident, int len)
{
    text_t user;
    user.str = stmt->session->db_user;
    user.len = (uint32)strlen(stmt->session->db_user);

    text_t name = { .str = ident, .len = len };
    return sql_self_func_configed(&user, &name);
}