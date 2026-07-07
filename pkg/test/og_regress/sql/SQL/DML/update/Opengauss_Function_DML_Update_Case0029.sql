drop table if exists t_update01;
create table t_update01(id int,name varchar(10));
insert into t_update01 values(1,'hello'),(2,'world'),(3,'hello1');
update t_update01 as t set t.id = id + 1;
update t_update01 as t set t.name = upper(name);
select * from t_update01;
drop table t_update01;
