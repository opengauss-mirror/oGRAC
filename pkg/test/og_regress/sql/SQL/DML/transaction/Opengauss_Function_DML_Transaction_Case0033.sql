drop table if exists testzl;
create table testzl (sk integer, id char(16), name varchar(20), sq_ft integer);

create or replace function get_transaction(i integer) return integer
as
begin
  return i + 1;
end;
/

begin
  insert into testzl values (get_transaction(1), 'rr', 'sk', 11);
end;
/

select count(*) from testzl;

drop table if exists testzl;
drop function if exists get_transaction;