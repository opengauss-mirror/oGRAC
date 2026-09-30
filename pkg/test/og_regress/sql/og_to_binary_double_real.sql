-- Run on an A-compatible oGRAC instance.
-- Direct value output is diagnostic only; PASS equality checks are independent
-- of client default width.
alter system set use_bison_parser = true scope = memory;
set feedback on;
set heading on;

prompt === basic inputs and REAL return contract ===
select to_binary_double('123.456') as b01_text from sys.sys_dummy;
select to_binary_double(123.456) as b02_number from sys.sys_dummy;
select to_binary_double(true) as b03_true from sys.sys_dummy;
select to_binary_double(false) as b04_false from sys.sys_dummy;
select to_binary_double(null) as b05_null from sys.sys_dummy;
select to_binary_double(cast(9007199254740993 as number)) as b06_binary64_round from sys.sys_dummy;
desc -q select to_binary_double('1.25') as b07_result_type;
select to_binary_double('9007199254740992') + 1 as b08_real_add from sys.sys_dummy;

prompt === binary64 boundaries and special values ===
select to_binary_double('9007199254740992') as r01_exact_integer from sys.sys_dummy;
select to_binary_double('9007199254740993') as r02_round_even from sys.sys_dummy;
select to_binary_double('9007199254740994') as r03_next_integer from sys.sys_dummy;
select to_binary_double('1.7976931348623157E308') as r04_max_finite from sys.sys_dummy;
select to_binary_double('1.8E308') as r05_overflow from sys.sys_dummy;
select to_binary_double('-1E400') as r06_negative_overflow from sys.sys_dummy;
select to_binary_double('2.2250738585072014E-308') as r07_min_normal from sys.sys_dummy;
select to_binary_double('4.9406564584124654E-324') as r08_min_subnormal from sys.sys_dummy;
select to_binary_double('1E-400') as r09_underflow from sys.sys_dummy;
select to_binary_double('NaN') as r10_nan from sys.sys_dummy;
select to_binary_double('Inf') as r11_inf from sys.sys_dummy;
select to_binary_double('-Infinity') as r12_negative_inf from sys.sys_dummy;
select to_binary_double('-0') as r13_zero_normalized from sys.sys_dummy;
select case when to_binary_double('-0') = to_binary_double('0')
       then 'PASS' else 'FAIL' end as r13a_zero_normalized from sys.sys_dummy;
select case when to_binary_double('9007199254740993') = to_binary_double('9007199254740992')
       then 'PASS' else 'FAIL' end as r14_round_check from sys.sys_dummy;
select case when to_binary_double('123.456') =
                      to_binary_double('123.4560000000000030695446184836328125')
       then 'PASS' else 'FAIL' end as r15_exact_binary64 from sys.sys_dummy;
-- Known scope difference: OG_TYPE_REAL does not implement Oracle BINARY_DOUBLE Inf ordering.
select case when to_binary_double('1.7976931348623157E308') < to_binary_double('Inf')
       then 'FAIL' else 'PASS' end as r16_real_inf_order_scope from sys.sys_dummy;
select case when to_binary_double('4.9406564584124654E-324') > 0
       then 'PASS' else 'FAIL' end as r17_subnormal_nonzero from sys.sys_dummy;
select case when to_binary_double('1E-400') = 0
       then 'PASS' else 'FAIL' end as r18_underflow_zero from sys.sys_dummy;
-- Known scope difference: OG_TYPE_REAL keeps the existing NaN comparison semantics.
select case when to_binary_double('NaN') = to_binary_double('NaN')
       then 'FAIL' else 'PASS' end as r19_real_nan_scope from sys.sys_dummy;

prompt === fmt, NLS and DEFAULT reuse ===
select to_binary_double('0007', '0000') as f01_zero from sys.sys_dummy;
select to_binary_double('123', 'FM999') as f02_fm from sys.sys_dummy;
select to_binary_double('1,234,567.8', '9G999G999D9',
       'NLS_NUMERIC_CHARACTERS=''.,''') as f03_nls from sys.sys_dummy;
select to_binary_double('1.25E+2', '9D99EEEE',
       'NLS_NUMERIC_CHARACTERS=''.,''') as f04_scientific from sys.sys_dummy;
select to_binary_double('bad' default 0 on conversion error) as d01_default_number from sys.sys_dummy;
select to_binary_double('bad' default '2.5' on conversion error) as d02_default_text from sys.sys_dummy;
select to_binary_double('1.25' default 0 on conversion error) as d03_no_default from sys.sys_dummy;
select to_binary_double('1E400' default 9 on conversion error) as d04_overflow_no_default from sys.sys_dummy;
select to_binary_double(
       'bad' default '1,234.5' on conversion error,
       '9G999D9', 'NLS_NUMERIC_CHARACTERS=''.,''') as d05_default_fmt from sys.sys_dummy;

prompt === expected errors and explicitly unsupported scope ===
select to_binary_double('abc') as e01_invalid_text from sys.sys_dummy;
select to_binary_double('1.2.3') as e02_multiple_decimal from sys.sys_dummy;
select to_binary_double('1', '9D9D9') as e03_invalid_fmt from sys.sys_dummy;
select to_binary_double('1', '9D9', 'NLS_NUMERIC_CHARACTERS=''..''') as e04_invalid_nls from sys.sys_dummy;
select to_binary_double(1, '999') as e05_numeric_with_fmt from sys.sys_dummy;
select to_binary_double('bad' default 'still_bad' on conversion error) as e06_bad_default from sys.sys_dummy;
select to_binary_double(1 / 0 default 0 on conversion error) as e07_expr_error from sys.sys_dummy;
select to_binary_double('bad' default (1 + 1) on conversion error) as e08_complex_default from sys.sys_dummy;
select to_binary_double(date '2026-08-28') as e09_date from sys.sys_dummy;
select to_binary_double('123-', '999S') as u01_trailing_sign from sys.sys_dummy;
select to_binary_double('$123', '$999') as u02_currency from sys.sys_dummy;
select to_binary_double('00FF', 'XXXX') as u03_hex from sys.sys_dummy;

-- Function indexes must distinguish DEFAULT values from format arguments.
create table t_bd_default_idx (id integer, txt varchar(40));
insert into t_bd_default_idx values (1, 'bad');
insert into t_bd_default_idx values (2, '9');
insert into t_bd_default_idx values (3, '11');
commit;
create index ix_bd_default on t_bd_default_idx (
    to_binary_double(txt default '9' on conversion error));
analyze table t_bd_default_idx compute statistics;
select /*+ INDEX(t ix_bd_default) */ case when count(*) = 2
    then 'PASS' else 'FAIL' end as i01_default_index
from t_bd_default_idx t
where to_binary_double(txt default '9' on conversion error) = to_binary_double('9');
-- Both queries must raise a conversion error instead of reusing DEFAULT index keys.
select /*+ INDEX(t ix_bd_default) */ id from t_bd_default_idx t
where to_binary_double(txt, '9') = to_binary_double('9') order by id;
select /*+ FULL(t) */ id from t_bd_default_idx t
where to_binary_double(txt, '9') = to_binary_double('9') order by id;

drop index ix_bd_default;
delete from t_bd_default_idx where id <> 2;
commit;
-- Reversing the expressions must not make them duplicate index columns.
create index ix_bd_format_default on t_bd_default_idx (
    to_binary_double(txt, '9'), to_binary_double(txt default '9' on conversion error));
analyze table t_bd_default_idx compute statistics;
select /*+ INDEX(t ix_bd_format_default) */ case when count(*) = 1
    then 'PASS' else 'FAIL' end as i02_format_index
from t_bd_default_idx t
where to_binary_double(txt, '9') = to_binary_double('9');
drop table t_bd_default_idx purge;
alter system set use_bison_parser = false scope = memory;
