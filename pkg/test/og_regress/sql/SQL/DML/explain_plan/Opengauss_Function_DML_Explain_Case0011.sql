drop table if exists explain_t011;
drop table if exists explain_t011_bak;
create table explain_t011(a int, b int);
create table explain_t011_bak(f1 int,f2 int);
explain plan for select t.a  from explain_t011 t where t.b = (case when exists(select f1 from explain_t011_bak where f1 = 1) then 1 end);
drop table explain_t011;
drop table explain_t011_bak;
