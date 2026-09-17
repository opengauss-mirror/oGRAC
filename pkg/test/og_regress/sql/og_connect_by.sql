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

-- Cache non-equality CONNECT BY matches over a joined NUMBER2 input.
drop table if exists t_hier_match_test;
create table t_hier_match_test(node_no number2);
begin
  for k in 1..200 loop
    insert into t_hier_match_test values(k);
  end loop;
  commit;
end;
/
analyze table t_hier_match_test compute statistics;
explain select count(*) hierarchy_rows
from t_hier_match_test a join t_hier_match_test b on a.node_no=b.node_no
connect by nocycle prior a.node_no between b.node_no and b.node_no+1 or prior b.node_no like a.node_no;
select count(*) hierarchy_rows
from t_hier_match_test a join t_hier_match_test b on a.node_no=b.node_no
connect by nocycle prior a.node_no between b.node_no and b.node_no+1 or prior b.node_no like a.node_no;
drop table t_hier_match_test;

-- Equal instants stored with different offsets retain both two-level paths.
create table t_cb_tz_cycle(id integer, ts timestamp with time zone);
insert into t_cb_tz_cycle values(1, from_tz(to_timestamp('2026-01-01 08:00:00','YYYY-MM-DD HH24:MI:SS'), '+08:00'));
insert into t_cb_tz_cycle values(2, from_tz(to_timestamp('2026-01-01 00:00:00','YYYY-MM-DD HH24:MI:SS'), '+00:00'));
commit;
select a.id, b.id from t_cb_tz_cycle a, t_cb_tz_cycle b where a.id=1 and b.id=2 and a.ts=b.ts;
select id, level as lv from t_cb_tz_cycle connect by nocycle prior ts<=ts order by id,lv;
select count(*) hierarchy_rows from t_cb_tz_cycle connect by nocycle prior ts<=ts;
select id, level as lv from t_cb_tz_cycle t_eq_on connect by nocycle prior ts=ts order by id,lv;
select id, level as lv, connect_by_iscycle as cyc from t_cb_tz_cycle t_root_on
start with id=1 connect by nocycle prior ts<=ts order by id,lv;
alter system set _connect_by_materialize=false scope=memory;
select id, level as lv from t_cb_tz_cycle t_off connect by nocycle prior ts<=ts order by id,lv;
select id, level as lv from t_cb_tz_cycle t_eq_off connect by nocycle prior ts=ts order by id,lv;
select id, level as lv, connect_by_iscycle as cyc from t_cb_tz_cycle t_root_off
start with id=1 connect by nocycle prior ts<=ts order by id,lv;
alter system set _connect_by_materialize=true scope=memory;
drop table t_cb_tz_cycle;

-- Close DOUBLE values have distinct PRIOR representations in both execution paths.
create table t_cb_real_cycle(id integer, val double);
insert into t_cb_real_cycle values(1, 1.0);
insert into t_cb_real_cycle values(2, 1.0000000000000004);
commit;
select id, level as lv from t_cb_real_cycle t_on connect by nocycle prior val<=val order by id,lv;
select id, level as lv from t_cb_real_cycle t_eq_on connect by nocycle prior val=val order by id,lv;
alter system set _connect_by_materialize=false scope=memory;
select id, level as lv from t_cb_real_cycle t_off connect by nocycle prior val<=val order by id,lv;
select id, level as lv from t_cb_real_cycle t_eq_off connect by nocycle prior val=val order by id,lv;
alter system set _connect_by_materialize=true scope=memory;
drop table t_cb_real_cycle;
