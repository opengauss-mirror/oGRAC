drop table if exists explain_t006;
drop table if exists explain_t006_bak;
create table explain_t006(a int, b int);
create table explain_t006_bak(f1 int,f2 int);
explain plan for select * from (select a from explain_t006 where b=(select f1 from explain_t006_bak));
explain plan for select a from explain_t006 where b=(select f1 from explain_t006_bak);
drop table explain_t006;
drop table explain_t006_bak;
