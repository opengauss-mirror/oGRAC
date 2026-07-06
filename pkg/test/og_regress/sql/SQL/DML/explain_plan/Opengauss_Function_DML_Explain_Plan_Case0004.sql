drop table if exists explain_t004;
drop table if exists explain_t004_bak;
create table explain_t004(a int, b int);
create table explain_t004_bak(f1 int,f2 int);
explain plan for select * from explain_t004 where exists(select f1 from explain_t004_bak);
drop table explain_t004;
drop table explain_t004_bak;
