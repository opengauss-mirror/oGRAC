drop table if exists t_dml_transaction_case0026;create table t_dml_transaction_case0026 (sk boolean,sk1 boolean,sk2 boolean);

declare
                          a boolean;
                          b boolean;
                          c boolean;
                        begin
                          a := true;
                          b := false;
                          c := null;
                          insert into t_dml_transaction_case0026 values (a,b,c);
                        end;
/

select * from t_dml_transaction_case0026;

drop table if exists t_dml_transaction_case0026;
