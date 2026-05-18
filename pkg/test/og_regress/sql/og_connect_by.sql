drop table if exists t_cb_1;
drop table if exists t_cb_2;
drop table if exists t_cb_3;
create table t_cb_1(empno int, ename varchar(10), mgr int);
create table t_cb_2(empno int, ename varchar(10), mgr int);
insert into t_cb_1 values(5, 'B',3);
insert into t_cb_1 values(6, 'F', 4);
insert into t_cb_2 values(5, 'B',3);
insert into t_cb_2 values(6, 'F', 4);
commit;
explain select t_cb_1.empno, t_cb_2.mgr from t_cb_1 join t_cb_2 
on t_cb_1.ename != t_cb_2.ename start with  2 > 1 connect by nocycle prior t_cb_1.empno = t_cb_2.mgr;
select t_cb_1.empno, t_cb_2.mgr from t_cb_1 join t_cb_2 
on t_cb_1.ename != t_cb_2.ename start with  2 > 1 connect by nocycle prior t_cb_1.empno = t_cb_2.mgr order by 1,2;
create table t_cb_3 as select t_cb_1.empno, t_cb_2.mgr from t_cb_1 join t_cb_2 
on t_cb_1.ename != t_cb_2.ename start with  2 > 1 connect by nocycle prior t_cb_1.empno = t_cb_2.mgr;
select * from t_cb_3 order by 1,2;
drop table if exists t_cb_1;
drop table if exists t_cb_2;
drop table if exists t_cb_3;
