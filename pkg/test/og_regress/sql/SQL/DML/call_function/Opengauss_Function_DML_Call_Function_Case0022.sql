drop function if exists fun_function_0022;
create or replace function fun_function_0022(c bigint:=1) return int
as
   b int := c;
begin
  for i in 1..c loop
    b := b + 1;
  end loop;
  return b;
end;
/
select fun_function_0022 from sys_dummy;
drop function if exists fun_function_0022;
