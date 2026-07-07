drop table if exists t_delete02;
create table t_delete02(id int,name varchar(10));
insert into t_delete02 values (1,'小明');
insert into t_delete02 values (2,'小明');
insert into t_delete02 values (3,'小明');
insert into t_delete02 values (4,'小李');
insert into t_delete02 values (5,'小李');
insert into t_delete02 values (6,'小李');
insert into t_delete02 values (7,'小红');
insert into t_delete02 values (8,'小红');
delete from t_delete02 where exists (
  select 1 from t_delete02 b where t_delete02.id < b.id and t_delete02.name = b.name
);
select * from t_delete02 order by id;
drop table t_delete02;