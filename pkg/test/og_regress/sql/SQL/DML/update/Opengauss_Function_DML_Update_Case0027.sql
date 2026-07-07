drop table if exists t_update01;
create table t_update01(id int,name varchar(10));
insert into t_update01 values(1,'hello'),(2,'world'),(3,'hello1');
update t_update01 t_update01$ set id = id + 1 where name = 'hello';
select * from t_update01;
update t_update01 as _update01$ set id = 50 where name = 'hello1';
update t_update01 as T_update01$ set id = 5 where name = 'world';
update t_update01 as "T_update01$" set id = 54 where name = 'world';
drop table t_update01;
