drop table if exists t_delete03;
create table t_delete03(id int,name varchar(10));
insert into t_delete03 values (1,'小明');
insert into t_delete03 values (2,'小李');
drop table if exists t_delete04;
create table t_delete04(id int,t_num varchar(10));
insert into t_delete04 values (1,'小明');
insert into t_delete04 values (2,'小李');
delete from t_delete03 where id = 1 and exists (
  select 1 from t_delete04 where t_delete03.id = t_delete04.id
);
select * from t_delete03 order by id;
drop table t_delete03;
drop table t_delete04;