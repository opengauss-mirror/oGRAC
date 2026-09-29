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
