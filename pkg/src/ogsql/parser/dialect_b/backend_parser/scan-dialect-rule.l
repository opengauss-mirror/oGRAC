%{
/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

	BEGIN(b_format);
%}

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
                    else if (strcmp(yytext, "<=>") == 0)
                    {
                        FLEX_MEM_STRDUP(yylval->str, yytext);
                        yyextra->is_hint_str = false;
                        return CmpOp;
                    }
                    else
                    {
                        yyerror(yytext);
                    }
                }
