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

                | func_name '(' a_expr DEFAULT a_expr ON CONVERSION_P ERROR_P ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_to_binary_fp_default_expr(
                            og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, $3, $5, NULL,
                            @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init binary floating-point default conversion expr failed");
                        }
                        $$ = expr;
                    }
                | func_name '(' a_expr DEFAULT a_expr ON CONVERSION_P ERROR_P ',' func_arg_list ')'
                    {
                        expr_tree_t *expr = NULL;
                        if (sql_create_to_binary_fp_default_expr(
                            og_yyget_extra(yyscanner)->core_yy_extra.stmt, &expr, $1, $3, $5, $10,
                            @1.loc) != OG_SUCCESS) {
                            parser_yyerror("init binary floating-point default conversion expr failed");
                        }
                        $$ = expr;
                    }
