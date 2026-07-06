drop table if exists explain_t009;
drop table if exists explain_t009_bak;
create table explain_t009(a int, b int);
create table explain_t009_bak(f1 int,f2 int);
explain plan for select t.a, (select f1 from explain_t009_bak) from explain_t009 t;
drop table explain_t009;
drop table explain_t009_bak;
