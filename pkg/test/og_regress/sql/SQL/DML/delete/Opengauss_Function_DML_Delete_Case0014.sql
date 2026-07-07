drop table if exists t_delete03;
create table t_delete03(id int,name varchar(10));
insert into t_delete03 values (1,'小明');
insert into t_delete03 values (2,'小李');
delete from t_delete03 where id < 1;
drop table t_delete03;
