-- Dialect function IDs must be resolved before ORDER BY examines function metadata.
-- Both parsers cover direct expressions and existing aggregate/alias handling.
set feedback on;
set heading on;

alter system set use_bison_parser = false scope = memory;
prompt === native parser ===
prompt === direct dialect function ORDER BY expressions ===
select 1 as q01_cosh from sys.sys_dummy order by cosh(1);
select 1 as q02_sinh from sys.sys_dummy order by sinh(1);
select 1 as q03_initcap from sys.sys_dummy order by initcap('hello world');
select 1 as q04_nchr from sys.sys_dummy order by nchr(65);
select 1 as q05_nanvl from sys.sys_dummy order by nanvl(1, 7);
select 1 as q06_remainder from sys.sys_dummy order by remainder(11, 4);
select 1 as q07_binary_float from sys.sys_dummy order by to_binary_float('1.25');
select 1 as q08_binary_double from sys.sys_dummy order by to_binary_double('1.25');

prompt === multi-row dialect function sort keys ===
select id as q09_cosh_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by cosh(n);

select id as q10_sinh_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by sinh(n);

select id as q11_initcap_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by initcap(decode(n, 1, 'aAA', 2, 'bBB', 'cCC'));

select id as q12_nchr_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by nchr(65 + n);

select id as q13_nanvl_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by nanvl(n, 7);

select id as q14_remainder_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by remainder(n, 4);

select id as q15_binary_float_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by to_binary_float(to_char(n));

select id as q16_binary_double_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by to_binary_double(to_char(n));

prompt === nested expressions, aggregates, aliases and ordinals ===
select id as q17_arithmetic
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by cosh(abs(n)) + sinh(n);

select id as q18_outer_function
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by abs(remainder(n, 4)), id;

select id as q19_case
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by case when cosh(n) > cosh(2) then -n else sinh(n) end;

select id as q20_aggregate
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by sum(n), count(*) desc, id;

select remainder(n, 4) as q21_alias
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by q21_alias;

select id as q22_ordinal
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by 1 desc;

select id as q23_sum_cosh
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by sum(cosh(n)), id;

select id as q24_cosh_sum
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by cosh(sum(n)), id;

prompt === IF and LNNVL condition aliases ===
select id as q25_if
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by if(cosh(q25_if) > cosh(1), -q25_if, q25_if);

select id as q26_lnnvl
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by lnnvl(cosh(q26_lnnvl) > cosh(1)), q26_lnnvl;

prompt === unknown function must report an ordinary error ===
select 1 as q27_unknown_function from sys.sys_dummy order by order_by_no_such_func_a(1);

alter system set use_bison_parser = true scope = memory;
prompt === Bison parser ===
prompt === direct dialect function ORDER BY expressions ===
select 1 as q01_cosh from sys.sys_dummy order by cosh(1);
select 1 as q02_sinh from sys.sys_dummy order by sinh(1);
select 1 as q03_initcap from sys.sys_dummy order by initcap('hello world');
select 1 as q04_nchr from sys.sys_dummy order by nchr(65);
select 1 as q05_nanvl from sys.sys_dummy order by nanvl(1, 7);
select 1 as q06_remainder from sys.sys_dummy order by remainder(11, 4);
select 1 as q07_binary_float from sys.sys_dummy order by to_binary_float('1.25');
select 1 as q08_binary_double from sys.sys_dummy order by to_binary_double('1.25');

prompt === multi-row dialect function sort keys ===
select id as q09_cosh_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by cosh(n);

select id as q10_sinh_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by sinh(n);

select id as q11_initcap_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by initcap(decode(n, 1, 'aAA', 2, 'bBB', 'cCC'));

select id as q12_nchr_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by nchr(65 + n);

select id as q13_nanvl_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by nanvl(n, 7);

select id as q14_remainder_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by remainder(n, 4);

select id as q15_binary_float_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by to_binary_float(to_char(n));

select id as q16_binary_double_rows
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by to_binary_double(to_char(n));

prompt === nested expressions, aggregates, aliases and ordinals ===
select id as q17_arithmetic
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by cosh(abs(n)) + sinh(n);

select id as q18_outer_function
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by abs(remainder(n, 4)), id;

select id as q19_case
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by case when cosh(n) > cosh(2) then -n else sinh(n) end;

select id as q20_aggregate
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by sum(n), count(*) desc, id;

select remainder(n, 4) as q21_alias
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by q21_alias;

select id as q22_ordinal
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by 1 desc;

select id as q23_sum_cosh
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by sum(cosh(n)), id;

select id as q24_cosh_sum
from (select 1 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 5 from sys.sys_dummy
      union all select 3, 1 from sys.sys_dummy) t
group by id
order by cosh(sum(n)), id;

prompt === IF and LNNVL condition aliases ===
select id as q25_if
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by if(cosh(q25_if) > cosh(1), -q25_if, q25_if);

select id as q26_lnnvl
from (select 3 as id, 2 as n from sys.sys_dummy
      union all select 1, 3 from sys.sys_dummy
      union all select 2, 1 from sys.sys_dummy) t
order by lnnvl(cosh(q26_lnnvl) > cosh(1)), q26_lnnvl;

prompt === unknown function must report an ordinary error ===
select 1 as q27_unknown_function from sys.sys_dummy order by order_by_no_such_func_a(1);

-- Restore the regression suite's default parser mode.
alter system set use_bison_parser = false scope = memory;
