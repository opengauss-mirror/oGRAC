drop table if exists explain_t1;
drop table if exists explain_t2;
create table explain_t1(a int, b int);
create table explain_t2(f1 int,f2 int);
explain plan for select a from explain_t1 where a not in (select f1 from explain_t2);
drop table explain_t1;
drop table explain_t2;
