stmtblock: DIALECT_B_FORMAT_SQL b_stmtmulti
            {
                og_yyget_extra(yyscanner)->parsetree = $2;
            }
        | BISON_PL_SOURCE DIALECT_B_FORMAT_SQL compileFunctionSource
            {
                og_yyget_extra(yyscanner)->parsetree = $3;
            }
        ;


B_CreateUserStmt:
            CREATE USER user_name IDENTIFIED BY user_password opt_encrypted opt_user_options
                {
                    knl_user_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_user(stmt, &def, $3, $6, @6.loc, $7, $8) != OG_SUCCESS) {
                        parser_yyerror("parse create user failed");
                    }
                    $$ = def;
                }
			| CREATE USER IF_P NOT EXISTS user_name IDENTIFIED BY user_password opt_encrypted opt_user_options
				{
				    knl_user_def_t *def = NULL;
                    sql_stmt_t *stmt = og_yyget_extra(yyscanner)->core_yy_extra.stmt;
                    
                    if (og_parse_create_user(stmt, &def, $6, $9, @9.loc, $10, $11) != OG_SUCCESS) {
                        parser_yyerror("parse create user failed");
                    }
                    $$ = def;			
				}
        ;

b_stmtmulti:
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
        | B_CreateUserStmt
        | CreateRoleStmt
        | CreateTenantStmt
        | AlterIndexStmt
        | CreateTablespaceStmt
        | CreateIndexStmt
        | CreateSequenceStmt
        | CreateViewStmt
        | CreateSynonymStmt
        | CreateProfileStmt
        | CreateDirectoryStmt
        | CreateLibraryStmt
        | CreateCtrlfileStmt
        | CreateTableStmt
        | CreateFunctionStmt
        | GrantStmt
        | RevokeStmt
        | /*EMPTY*/ { $$ = NULL; }
    ;
