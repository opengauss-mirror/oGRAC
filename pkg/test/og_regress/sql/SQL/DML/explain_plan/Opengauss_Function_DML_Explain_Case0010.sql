drop table if exists explain_t010;
drop table if exists explain_t010_bak;
create table explain_t010(a int, b int);
create table explain_t010_bak(f1 int,f2 int);
explain plan for select t.a, (case when exists(select f1 from explain_t010_bak where f1 = 1) then 1 end) from explain_t010 t;
drop table explain_t010;
drop table explain_t010_bak;
