drop table if exists t_insert02;
create table t_insert02(id int,name varchar(10));
insert into t_insert02 values (2,'小明');
select * from t_insert02 where id = 2;
insert into t_insert02 values (3,'小明');
select id from t_insert02 where id = 3;
insert into t_insert02 values (4,'小明');
select id,name from t_insert02 where id = 4;
drop table if exists t_insert02;