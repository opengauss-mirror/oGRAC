-- foreign key constraint self
drop table if exists t_emp;
create table t_emp (empno number(4), mgr number(4), ename varchar2(10));
alter table t_emp add constraint t_emp_pk primary key(empno);
alter table t_emp add constraint t_emp_fk foreign key(mgr) references t_emp(empno);
insert into t_emp values (0,null,'root');
insert into t_emp (empno,mgr) values (1,0);
insert into t_emp (empno,mgr) values (2,1);
insert into t_emp (empno,mgr) values (3,2);
commit;
-- insert error
insert into t_emp (empno,mgr) values (10,23);
insert into t_emp (empno,mgr) values (5,4);
-- update
update t_emp set mgr = 11 where empno = 3;   -- error
update t_emp set mgr = null where empno = 3; -- success
update t_emp set mgr = 3 where empno = 0;    -- success
commit;
insert into  t_emp values (-1,null,'oGRAC'); -- success
commit;
delete from t_emp where empno = 1; -- error
delete from t_emp where empno = -1; -- success
commit;
drop table t_emp;