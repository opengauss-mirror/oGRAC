drop table if exists testzl;
drop table if exists testzl1;
create table testzl (sk char(10));
create table testzl1 (sk integer);

drop function if exists get_transaction;
create or replace function get_transaction(i char) return char
as
begin
  return i;
end;
/

begin
  insert into testzl values (get_transaction('aa'));
end;
/
select * from testzl;

drop function if exists get_transaction;
create or replace function get_transaction(i integer) return integer
as
begin
  return i + 1;
end;
/

begin
  insert into testzl1 values (get_transaction(1));
end;
/
select * from testzl1;

drop table if exists testzl;
drop table if exists testzl1;
drop function if exists get_transaction;