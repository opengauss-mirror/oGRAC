stmtblock: DIALECT_A_FORMAT_SQL stmtmulti
            {
                og_yyget_extra(yyscanner)->parsetree = $2;
            }
        | BISON_PL_SOURCE DIALECT_A_FORMAT_SQL stored_pl_source
            {
                og_yyget_extra(yyscanner)->parsetree = $3;
            }
        ;
