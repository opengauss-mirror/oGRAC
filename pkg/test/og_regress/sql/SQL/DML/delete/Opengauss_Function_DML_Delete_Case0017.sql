drop table if exists t_delete05;
create table t_delete05(age int,salary numeric);
insert into t_delete05 values(25,8500);
insert into t_delete05 values(30,9500.50);
insert into t_delete05 values(45,6000);
delete FROM t_delete05 WHERE age in (SELECT AGE FROM t_delete05 WHERE SALARY > 6500);
drop table t_delete05;
