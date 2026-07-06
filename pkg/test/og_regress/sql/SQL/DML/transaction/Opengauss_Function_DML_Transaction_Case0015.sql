drop table if exists t_dml_transaction_case0015;create table t_dml_transaction_case0015 (sk integer,id char(16),name varchar(20),sq_ft integer);

declare
                       i integer;
                       begin
                         for i in 1..10 loop
                           insert into t_dml_transaction_case0015 values(i,'sk1','tt',3332);
                         end loop;
                       end;
/

select * from t_dml_transaction_case0015;

drop table if exists t_dml_transaction_case0015;
