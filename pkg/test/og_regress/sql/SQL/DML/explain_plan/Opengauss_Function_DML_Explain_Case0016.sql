drop table if exists explain_t016;
drop table if exists explain_t016_bak;
create table explain_t016(a int, b int);
create table explain_t016_bak(f1 int,f2 int);
explain plan for update explain_t016 set a = 1 where b = (select f1 from explain_t016_bak where f1 = 1);
drop table explain_t016;
drop table explain_t016_bak;
