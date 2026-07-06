drop table if exists t3;
drop table if exists t2;
drop table if exists t1;
create table t1(a int);
insert into t1 values(1);
insert into t1 values(11);
alter table t1  add constraint ua unique (a);
alter table t1 modify a not null;
drop table if exists t1;
