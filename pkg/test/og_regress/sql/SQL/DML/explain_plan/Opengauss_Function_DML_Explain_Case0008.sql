drop table if exists explain_t008;
drop table if exists explain_t008_bak;
create table explain_t008(a int, b int);
create table explain_t008_bak(f1 int,f2 int);
explain plan for  select * from explain_t008 where A = 1 + (select f1 from explain_t008_bak);
drop table explain_t008;
drop table explain_t008_bak;
