drop table if exists test_merge_1;
drop table if exists test_merge_2;
create table test_merge_1 (f1 int, f2 int, f3 int);
create table test_merge_2 (f1 int, f2 int, f3 int);
insert into test_merge_1 values (1,4,4),(2,3,3),(3,2,2),(4,1,1);
insert into test_merge_2 values (1,4,4),(2,3,3),(3,2,2),(4,1,1);
commit;
-- ensure the dml executing in one Transaction
set autocommit off;
merge into test_merge_2 t2 using (select * from test_merge_1) t1
on (t1.f2 = t2.f1 or t1.f3 = t2.f1)
when not matched then insert (f1,f2,f3) values (5,5,5);
-- table lock and row lock status
select TYPE, LMODE, BLOCK from DV_LOCKS lt join DV_ME mt ON lt.sid = mt.sid order by type;
set autocommit on;

set autocommit off;
MERGE INTO test_merge_2 t2
USING (SELECT * FROM test_merge_1) t1
ON (t1.f2 = t2.f1 OR t1.f3 = t2.f1)
WHEN MATCHED THEN
    UPDATE SET t2.f2 = 1000, t2.f3 = 1000
WHEN NOT MATCHED THEN
    INSERT (f1, f2, f3) VALUES (t1.f1, t1.f2, t1.f3);
select TYPE, LMODE, BLOCK from DV_LOCKS lt join DV_ME mt ON lt.sid = mt.sid order by type;
commit;
-- after commit, release the lock
select TYPE, LMODE, BLOCK from DV_LOCKS lt join DV_ME mt ON lt.sid = mt.sid order by type;
set autocommit on;

drop table if exists test_merge_1;
drop table if exists test_merge_2;