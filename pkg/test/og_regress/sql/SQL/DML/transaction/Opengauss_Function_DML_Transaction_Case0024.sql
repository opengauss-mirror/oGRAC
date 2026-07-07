drop table if exists t_dml_transaction_case0024;create table t_dml_transaction_case0024 (sk integer,id tinyint,name smallint,sq_ft bigint);

declare
                          a integer;
                          b TINYINT;
                          c SMALLINT;
                          d BIGINT;
                        begin
                          a := 1;
                          b := 255;
                          c := 3000;
                          d := 9223372036854775807;
                          insert into t_dml_transaction_case0024 values (a,b,c,d);
                        end;
/

select * from t_dml_transaction_case0024;

drop table if exists t_dml_transaction_case0024;
