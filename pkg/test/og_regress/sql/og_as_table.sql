-- test create as table max col size
drop table if exists t_over_long_col_1;
drop table if exists t_over_long_col_2;
create table t_over_long_col_1(c1 varchar(8000));
insert into t_over_long_col_1 values(lpad('x', 8000, 'y'));
insert into t_over_long_col_1 values(lpad('x', 8000, 'y'));
desc -q select listagg(c1, ';') within group (order by rowid) as res_col from t_over_long_col_1;
-- except error
create table t_over_long_col_2(res_col) 
    as select listagg(c1, ';') within group (order by rowid) as res_col from t_over_long_col_1;
drop table if exists t_over_long_col_1;
drop table if exists t_over_long_col_2;

drop table if exists t_func_as_tbl_1;
create table t_func_as_tbl_1(id number(38,5));
insert into t_func_as_tbl_1 values (1.11);
insert into t_func_as_tbl_1 values (null);
commit;

CREATE OR REPLACE TYPE user_type_name IS TABLE OF number;
/

create or replace function my_func(var varchar) return user_type_name
is
var_table user_type_name;
begin
  select id BULK COLLECT INTO var_table from t_func_as_tbl_1 t1; 
  return var_table;
end;
/

drop table if exists t_func_as_tbl_2;
create table t_func_as_tbl_2 as select * from table(cast (my_func('1') as user_type_name));
select * from t_func_as_tbl_2;
desc t_func_as_tbl_2;
drop table if exists t_func_as_tbl_1;
drop table if exists t_func_as_tbl_2;
drop type user_type_name;