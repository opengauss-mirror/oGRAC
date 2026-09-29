-- COSH/SINH A-compatible function verification.
-- Functions support both parsers; this regression uses Bison for stable diagnostics.
-- Direct output is diagnostic; canonical TO_CHAR and error assertions are the
-- Oracle comparison result.
alter system set use_bison_parser = true scope = memory;
set feedback on;
set heading on;

prompt === basic NUMBER inputs ===
select cosh(0) as c01_zero from sys.sys_dummy;
select sinh(0) as s01_zero from sys.sys_dummy;
select cosh(1) as c02_one from sys.sys_dummy;
select sinh(1) as s02_one from sys.sys_dummy;
select cosh(-1) as c03_minus_one from sys.sys_dummy;
select sinh(-1) as s03_minus_one from sys.sys_dummy;
select cosh('1') as c04_text from sys.sys_dummy;
select sinh('1') as s04_text from sys.sys_dummy;
select cosh(true) as c05_true from sys.sys_dummy;
select sinh(false) as s05_false from sys.sys_dummy;
select cosh(null) as c06_null from sys.sys_dummy;
select sinh('') as s06_empty from sys.sys_dummy;

prompt === width-independent canonical NUMBER text ===
select to_char(cosh(1), 'FM9.99999999999999999999999999999999999999') as c09_canonical
from sys.sys_dummy;
select to_char(sinh(1), 'FM9.99999999999999999999999999999999999999') as s09_canonical
from sys.sys_dummy;

prompt === return type contract ===
desc -q select cosh(1) as c07_number_type from sys.sys_dummy;
desc -q select sinh('1') as s07_number_type from sys.sys_dummy;
desc -q select cosh(to_binary_double('1')) as c08_real_type from sys.sys_dummy;
desc -q select sinh(to_binary_float('1')) as s08_real_type from sys.sys_dummy;

prompt === identities and precision checks ===
select case when cosh(-1) = cosh(1) then 'PASS' else 'FAIL' end as p01_cosh_even
from sys.sys_dummy;
select case when sinh(-1) = -sinh(1) then 'PASS' else 'FAIL' end as p02_sinh_odd
from sys.sys_dummy;
select case when abs(cosh(1) - 1.5430806348152437784779056207570616826) < 1e-37
       then 'PASS' else 'FAIL' end as p03_cosh_number from sys.sys_dummy;
select case when abs(sinh(1) - 1.17520119364380145688238185059560081516) < 1e-37
       then 'PASS' else 'FAIL' end as p04_sinh_number from sys.sys_dummy;
select case when sinh(1e-100) = 1e-100 then 'PASS' else 'FAIL' end as p05_small_sinh
from sys.sys_dummy;
select case when cosh(1e-30) = 1 then 'PASS' else 'FAIL' end as p06_small_cosh
from sys.sys_dummy;
select case when abs(cosh(2) - 3.76219569108363145956221347777374610831) < 1e-37
       then 'PASS' else 'FAIL' end as p07_cosh_exp_path from sys.sys_dummy;
select case when abs(sinh(2) - 3.62686040784701876766821398280126170488) < 1e-37
       then 'PASS' else 'FAIL' end as p08_sinh_exp_path from sys.sys_dummy;
select case when abs(cosh(10) * cosh(10) - sinh(10) * sinh(10) - 1) < 1e-28
       then 'PASS' else 'FAIL' end as p09_identity from sys.sys_dummy;
select case when cosh(-10) >= 1 and cosh(0) = 1 and cosh(10) >= 1
       then 'PASS' else 'FAIL' end as p10_cosh_value_range from sys.sys_dummy;
select case when sinh(-10) < 0 and sinh(0) = 0 and sinh(10) > 0
       then 'PASS' else 'FAIL' end as p11_sinh_value_range from sys.sys_dummy;

prompt === Oracle NUMBER range boundary ===
select cosh(282.57858863455690819872393985054486897) as r01_cosh_number_max from sys.sys_dummy;
select cosh(-282.57858863455690819872393985054486897) as r02_cosh_number_min from sys.sys_dummy;
select sinh(282.58006617333443970665056803202391465) as r03_sinh_number_max from sys.sys_dummy;
select sinh(-282.58006617333443970665056803202391465) as r04_sinh_number_min from sys.sys_dummy;
select cosh(282.57858863455690819872393985054486898) as r05_cosh_positive_overflow from sys.sys_dummy;
select cosh(-282.57858863455690819872393985054486898) as r06_cosh_negative_overflow from sys.sys_dummy;
select sinh(282.58006617333443970665056803202391466) as r07_sinh_positive_overflow from sys.sys_dummy;
select sinh(-282.58006617333443970665056803202391466) as r08_sinh_negative_overflow from sys.sys_dummy;

prompt === REAL path and IEEE special values ===
select cosh(to_binary_double('1')) as f01_cosh_double from sys.sys_dummy;
select sinh(to_binary_double('1')) as f02_sinh_double from sys.sys_dummy;
select cosh(to_binary_float('1')) as f03_cosh_float_promoted from sys.sys_dummy;
select sinh(to_binary_float('1')) as f04_sinh_float_promoted from sys.sys_dummy;
select cosh(to_binary_double('711')) as f05_cosh_overflow_inf from sys.sys_dummy;
select sinh(to_binary_double('-711')) as f06_sinh_overflow_ninf from sys.sys_dummy;
select cosh(to_binary_double('NaN')) as f07_cosh_nan from sys.sys_dummy;
select sinh(to_binary_double('NaN')) as f08_sinh_nan from sys.sys_dummy;
select cosh(to_binary_double('Inf')) as f09_cosh_inf from sys.sys_dummy;
select cosh(to_binary_double('-Inf')) as f10_cosh_ninf from sys.sys_dummy;
select sinh(to_binary_double('Inf')) as f11_sinh_inf from sys.sys_dummy;
select sinh(to_binary_double('-Inf')) as f12_sinh_ninf from sys.sys_dummy;
select sinh(to_binary_double('-0')) as f13_sinh_zero_normalized from sys.sys_dummy;
select case when sinh(to_binary_double('-0')) = to_binary_double('0')
       then 'PASS' else 'FAIL' end as f13a_sinh_zero_normalized from sys.sys_dummy;
select case when abs(cosh(to_binary_double('1')) - to_binary_double('1.5430806348152437')) <
                      to_binary_double('1E-15')
       then 'PASS' else 'FAIL' end as f14_cosh_real_precision from sys.sys_dummy;
select case when abs(sinh(to_binary_double('1')) - to_binary_double('1.1752011936438014')) <
                      to_binary_double('1E-15')
       then 'PASS' else 'FAIL' end as f15_sinh_real_precision from sys.sys_dummy;
select case when abs(cosh(to_binary_double('710')) /
                          to_binary_double('1.1169973830808557E+308') - to_binary_double('1')) <
                      to_binary_double('1E-14')
       then 'PASS' else 'FAIL' end as f16_cosh_710_finite from sys.sys_dummy;
select case when abs(sinh(to_binary_double('710')) /
                          to_binary_double('1.1169973830808557E+308') - to_binary_double('1')) <
                      to_binary_double('1E-14')
       then 'PASS' else 'FAIL' end as f17_sinh_710_finite from sys.sys_dummy;

prompt === expected errors ===
select cosh('abc') as e01_invalid_text from sys.sys_dummy;
select sinh(date '2026-08-29') as e02_date from sys.sys_dummy;
select cosh() as e03_no_argument from sys.sys_dummy;
select sinh(1, 2) as e04_too_many_arguments from sys.sys_dummy;

alter system set use_bison_parser = false scope = memory;
