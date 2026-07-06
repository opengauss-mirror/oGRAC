drop table if exists t_insert02;
create table t_insert02(id int,name varchar(10));
insert into t_insert02 values (2,'小xiao明');
select id as new_id from t_insert02 where id = 2 and name = '小xiao明';
insert into t_insert02 values (2,'小名明');
select id, name as new_name from t_insert02 where id = 2 and name = '小名明';
drop table if exists t_insert02;