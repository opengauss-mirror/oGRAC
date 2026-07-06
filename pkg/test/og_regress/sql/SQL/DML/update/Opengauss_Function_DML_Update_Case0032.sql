drop table if exists t_update003;
create table t_update003(c_x varchar(20), c_y int );
insert into t_update003 values('a',3);
insert into t_update003 values('c',2);
insert into t_update003 values('b',5);
insert into t_update003 values('a',1);
update t_update003  set (c_x,c_y) = (SELECT c_x, sum(c_y) FROM t_update003 GROUP BY c_x HAVING sum(c_y) > 4);
select * from t_update003;
drop table t_update003;
