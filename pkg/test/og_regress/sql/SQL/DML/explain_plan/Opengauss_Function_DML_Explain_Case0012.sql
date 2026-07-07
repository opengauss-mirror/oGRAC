drop table if exists explain_t012;
drop table if exists explain_t012_bak;
create table explain_t012(a int, b int);
create table explain_t012_bak(f1 int,f2 int);
explain plan for select t.a  from explain_t012 t where t.a = (select f1 from explain_t012_bak) - 1;
drop table explain_t012;
drop table explain_t012_bak;
