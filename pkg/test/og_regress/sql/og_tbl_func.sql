create or replace type def_og_number is table of number;
/
select * from table(cast(null::int[] as def_og_number));
select * from table(cast(null as def_og_number));
create or replace type def_og_integer is table of Integer;
/
select * from table (cast(null::int[] as def_og_integer));
drop type def_og_number;
drop type def_og_integer;