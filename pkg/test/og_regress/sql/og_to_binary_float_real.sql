-- TO_BINARY_FLOAT minimal A-compatibility design verification.
-- The function performs one binary32 quantization and returns OG_TYPE_REAL.
-- Direct value output is diagnostic only; PASS equality checks are used for
-- Oracle comparison because ogsql and SQL*Plus use different default widths.
alter system set use_bison_parser = true scope = memory;

set pagesize 200
set linesize 240

-- Basic input coverage.
select to_binary_float('123.456') as p01_text;
select to_binary_float(123.456) as p02_number;
select to_binary_float(true) as p03_true;
select to_binary_float(false) as p04_false;
select to_binary_float(null) as p05_null;
select to_binary_float('') as p06_empty;
select to_binary_float(cast(16777217 as bigint)) as p07_bigint_round;
select to_binary_float(cast(123.456 as number)) as p08_number_cast;
select to_binary_float(cast('1.25' as nchar(4))) as p09_nchar;
select to_binary_float(cast(7 as tinyint)) as p10_tinyint;
select to_binary_float(cast(8 as smallint)) as p11_smallint;
select to_binary_float(cast('9.25' as decimal)) as p12_decimal;
select to_binary_float(cast('10.5' as char(4))) as p13_char;
select to_binary_float(cast('11.5' as varchar(4))) as p14_varchar;
select to_binary_float(cast('12.5' as nvarchar(4))) as p15_nvarchar;
select to_binary_float(cast(13.5 as real)) as p16_real;

-- Return type and downstream REAL semantics.
desc -q select to_binary_float('1.25') as u01_result_type;
select to_binary_float('16777216') + 1 as u06_real_add;
select to_binary_float('16777216') + cast(1 as number) as u05_mixed_add;
select to_binary_float('1') / 0 as u07_real_div_zero;

-- binary32 rounding and range.
select to_binary_float('3.14159265') as r01_pi;
select to_binary_float('16777216') as r02_exact_integer;
select to_binary_float('16777217') as r03_round_even;
select to_binary_float('16777218') as r04_next_integer;
select to_binary_float('3.4028234663852886E38') as r05_max_finite;
select to_binary_float('3.4028235E38') as r06_round_to_max;
select to_binary_float('3.4028236E38') as r07_overflow;
select to_binary_float('-1E100') as r08_negative_overflow;
select to_binary_float('1.1754943508222875E-38') as r09_min_normal;
select to_binary_float('1.401298464324817E-45') as r10_min_subnormal;
select to_binary_float('7.006493E-46') as r11_round_to_subnormal;
select to_binary_float('7.006492321624085E-46') as r12_half_to_zero;
select to_binary_float('1E-50') as r13_underflow;
select case when to_binary_float('16777217') = to_binary_float('16777216')
    then 'PASS' else 'FAIL' end as r14_rounding_equal;

-- BIGINT inputs must round directly to binary32, without an intermediate binary64 rounding.
select case when to_binary_float(cast('18014399583223809' as bigint)) =
                      to_binary_float('18014399583223809')
    and to_binary_float(cast('18014399583223809' as bigint)) =
        to_binary_float(cast('18014399583223809' as number))
    then 'PASS' else 'FAIL' end as r15_bigint_direct;
select case when to_binary_float(cast('-18014399583223809' as bigint)) =
                      to_binary_float('-18014399583223809')
    and to_binary_float(cast('-18014399583223809' as bigint)) =
        to_binary_float(cast('-18014399583223809' as number))
    then 'PASS' else 'FAIL' end as r16_negative_bigint;
-- At halfway, choose the even binary32 neighbor; retain the side of nearby integers.
select case when to_binary_float(cast('18014399583223807' as bigint)) =
                      to_binary_double('18014398509481984')
    and to_binary_float(cast('18014399583223808' as bigint)) =
        to_binary_double('18014398509481984')
    then 'PASS' else 'FAIL' end as r17_halfway_down;
select case when to_binary_float(cast('18014401730707455' as bigint)) =
                      to_binary_double('18014400656965632')
    and to_binary_float(cast('18014401730707456' as bigint)) =
        to_binary_double('18014402804449280')
    and to_binary_float(cast('18014401730707457' as bigint)) =
        to_binary_double('18014402804449280')
    then 'PASS' else 'FAIL' end as r18_halfway_up;
-- The binary64 conversion path keeps its existing rounding.
select case when to_binary_double(cast('18014399583223809' as bigint)) =
                      to_binary_double('18014399583223809')
    and to_binary_double(cast('-18014399583223809' as bigint)) =
        to_binary_double('-18014399583223809')
    then 'PASS' else 'FAIL' end as r19_bigint_double;

-- Special values. Comparison results intentionally follow existing REAL semantics.
select to_binary_float('NaN') as s01_nan;
select to_binary_float('Inf') as s02_inf;
select to_binary_float('-Infinity') as s03_negative_inf;
select to_binary_float('-0') as s04_zero_normalized;
select case when to_binary_float('-0') = to_binary_float('0')
    then 'PASS' else 'FAIL' end as s05_zero_normalized;
select case when to_binary_float('123.456') =
                      to_binary_double('123.45600128173828125')
    then 'PASS' else 'FAIL' end as c01_binary32_exact;
select case when to_binary_float('3.4028234663852886E38') =
                      to_binary_double('3.4028234663852886E38')
    then 'PASS' else 'FAIL' end as c02_max_finite_exact;
select case when to_binary_float('NaN') = to_binary_float('NaN')
    then 'TRUE' else 'FALSE' end as u08_nan_equal;
select case when to_binary_float('NaN') > to_binary_float('Inf')
    then 'TRUE' else 'FALSE' end as u09_nan_greater;

-- Supported common format subset and function-level NLS.
select to_binary_float('0007', '0000') as f01_zero;
select to_binary_float('123', 'FM999') as f02_fm;
select to_binary_float('1.25', '9.99') as f03_literal_decimal;
select to_binary_float('1,234', '9,999') as f04_literal_group;
select to_binary_float('1,234,567.8', '9G999G999D9',
    'NLS_NUMERIC_CHARACTERS=''.,''') as f05_multi_group;
select to_binary_float('1.234,5', '9G999D9',
    'NLS_NUMERIC_CHARACTERS='',.''') as f06_nls_eu;
select to_binary_float('1.25E+2', '9D99EEEE',
    'NLS_NUMERIC_CHARACTERS=''.,''') as f07_scientific;
select to_binary_float('-123', 'S999') as f08_leading_sign;
select case when to_binary_float('1.25', null) is null
    then 'PASS' else 'FAIL' end as f09_null_fmt;
select case when to_binary_float('1.25', '9D99', null) is null
    then 'PASS' else 'FAIL' end as f10_null_nls;

-- DEFAULT ON CONVERSION ERROR.
select to_binary_float('bad' default 0 on conversion error) as d01_default_number;
select to_binary_float('bad' default '2.5' on conversion error) as d02_default_text;
select to_binary_float('1.25' default 0 on conversion error) as d03_no_default;
select to_binary_float('3.5E38' default 0 on conversion error) as d04_overflow_no_default;
select to_binary_float('1E-100' default 9 on conversion error) as d05_underflow_no_default;
select to_binary_float(
    'bad' default '1,234.5' on conversion error,
    '9G999D9',
    'NLS_NUMERIC_CHARACTERS=''.,'''
) as d06_default_fmt;

-- Existing baseline behavior outside the function.
select cast(16777217 as binary_float) as u03_cast_binary_float;
select 16777217F as u04_f_literal;
select binary_float_infinity as u13_predefined_constant;

-- Companion A-only conversion function; detailed coverage is in og_to_binary_double_real.sql.
select to_binary_double('1.25') as u14_to_binary_double;

-- Unsupported format elements: all must fail explicitly, not half-work.
select to_binary_float('123-', '999S') as u15_trailing_sign;
select to_binary_float('123-', '999MI') as u16_mi;
select to_binary_float('<123>', '999PR') as u17_pr;
select to_binary_float('$123', '$999') as u18_currency;
select to_binary_float('00FF', 'XXXX') as u19_hex;

-- Expected conversion, type, NLS and parser errors.
select to_binary_float('abc') as e01_invalid_text;
select to_binary_float('1.2.3') as e02_multiple_decimal;
select to_binary_float('1E+') as e03_incomplete_exponent;
select to_binary_float('--1') as e04_double_sign;
select to_binary_float('1.0F') as e05_suffix;
select to_binary_float('1', '9D9D9') as e06_invalid_fmt;
select to_binary_float('1', '9D9', 'NLS_NUMERIC_CHARACTERS=''..''') as e07_invalid_nls;
select to_binary_float('1', '9D9', 'NLS_DATE_LANGUAGE=''AMERICAN''') as e08_invalid_nls_key;
select to_binary_float(1, '999') as e09_numeric_with_fmt;
select to_binary_float('bad' default 'still_bad' on conversion error) as e10_bad_default;
select to_binary_float(1 / 0 default 0 on conversion error) as e11_expr_error;
select to_binary_float('bad' default (1 + 1) on conversion error) as e12_complex_default;
select to_binary_float(date '2026-08-27') as e13_date;
select to_number('bad' default 0 on conversion error) as e14_other_function_default_syntax;

-- TO_CHAR limitations are expected differences, not conversion failures.
select to_char(to_binary_float('123.456'), 'FM9.99999999EEEE') as u20_to_char_eeee;
select to_char(to_binary_float('123.456'), 'FM9.99999999EEEE',
    'NLS_NUMERIC_CHARACTERS=''.,''') as u21_to_char_three_args;

-- Function indexes must distinguish DEFAULT values from format arguments.
create table t_bf_default_idx (id integer, txt varchar(40));
insert into t_bf_default_idx values (1, 'bad');
insert into t_bf_default_idx values (2, '9');
insert into t_bf_default_idx values (3, '11');
commit;
create index ix_bf_default on t_bf_default_idx (
    to_binary_float(txt default '9' on conversion error));
analyze table t_bf_default_idx compute statistics;
select /*+ INDEX(t ix_bf_default) */ case when count(*) = 2
    then 'PASS' else 'FAIL' end as i01_default_index
from t_bf_default_idx t
where to_binary_float(txt default '9' on conversion error) = to_binary_float('9');
-- Both queries must raise a conversion error instead of reusing DEFAULT index keys.
select /*+ INDEX(t ix_bf_default) */ id from t_bf_default_idx t
where to_binary_float(txt, '9') = to_binary_float('9') order by id;
select /*+ FULL(t) */ id from t_bf_default_idx t
where to_binary_float(txt, '9') = to_binary_float('9') order by id;

drop index ix_bf_default;
delete from t_bf_default_idx where id <> 2;
commit;
-- Reversing the expressions must not make them duplicate index columns.
create index ix_bf_format_default on t_bf_default_idx (
    to_binary_float(txt, '9'), to_binary_float(txt default '9' on conversion error));
analyze table t_bf_default_idx compute statistics;
select /*+ INDEX(t ix_bf_format_default) */ case when count(*) = 1
    then 'PASS' else 'FAIL' end as i02_format_index
from t_bf_default_idx t
where to_binary_float(txt, '9') = to_binary_float('9');
drop table t_bf_default_idx purge;
alter system set use_bison_parser = false scope = memory;
