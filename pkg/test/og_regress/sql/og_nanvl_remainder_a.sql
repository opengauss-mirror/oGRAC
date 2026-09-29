-- NANVL/REMAINDER A-compatible function verification.
-- Direct output is diagnostic; width-independent PASS assertions are used for
-- Oracle comparison.
alter system set use_bison_parser = true scope = memory;
set feedback on;
set heading on;

prompt === NANVL basic and type behavior ===
select nanvl(12.5, 0) as n01_number from sys.sys_dummy;
select nanvl(to_binary_double('NaN'), 0) as n02_double_nan from sys.sys_dummy;
select nanvl(to_binary_float('NaN'), 0) as n03_float_nan from sys.sys_dummy;
select nanvl(to_binary_double('1.25'), 0) as n04_double_value from sys.sys_dummy;
select nanvl(null, 0) as n05_null from sys.sys_dummy;
select nanvl(to_binary_double('NaN'), null) as n06_nan_null from sys.sys_dummy;
select nanvl(10, null) as n07_value_null from sys.sys_dummy;
select nanvl(to_binary_double('Inf'), 0) as n08_inf from sys.sys_dummy;
select nanvl('12.5', 0) as n09_text from sys.sys_dummy;
select nanvl(true, 0) as n10_boolean from sys.sys_dummy;
select nanvl('NaN', to_binary_double('2')) as n11_text_nan_real from sys.sys_dummy;

desc -q select nanvl(12.5, 0) as n12_number_type from sys.sys_dummy;
desc -q select nanvl(12.5, to_binary_double('0')) as n13_real_type from sys.sys_dummy;
desc -q select nanvl(to_binary_float('NaN'), 0) as n14_float_real_type from sys.sys_dummy;

prompt === NANVL lazy replacement evaluation ===
select nanvl(10, to_number('bad')) as n15_lazy_value from sys.sys_dummy;
select nanvl(cast(null as number), to_number('bad')) as n16_lazy_null from sys.sys_dummy;

prompt === width-independent NANVL value checks ===
select case when nanvl(12.5,0)=12.5
                  and nanvl(to_binary_double('NaN'),0)=0
                  and nanvl(to_binary_double('1.25'),0)=to_binary_double('1.25')
                  and nanvl('NaN',to_binary_double('2'))=to_binary_double('2')
       then 'PASS' else 'FAIL' end as p01_nanvl_values from sys.sys_dummy;

prompt === REMAINDER NUMBER and ties-to-even ===
select remainder(11, 4) as r01_11_4 from sys.sys_dummy;
select remainder(7, 2) as r02_7_2 from sys.sys_dummy;
select remainder(5, 2) as r03_5_2 from sys.sys_dummy;
select remainder(-11, 4) as r04_n11_4 from sys.sys_dummy;
select remainder(11, -4) as r05_11_n4 from sys.sys_dummy;
select remainder(6, 4) as r06_6_4 from sys.sys_dummy;
select remainder(2, 4) as r07_2_4 from sys.sys_dummy;
select remainder(-6, 4) as r08_n6_4 from sys.sys_dummy;
select remainder(-2, 4) as r09_n2_4 from sys.sys_dummy;
select remainder(0.75, 0.5) as r10_decimal_tie_odd from sys.sys_dummy;
select remainder(1.25, 0.5) as r11_decimal_tie_even from sys.sys_dummy;
select remainder(12345678901234567890123456789012345675, 10) as r12_large_tie from sys.sys_dummy;
select remainder('11', '4') as r13_text from sys.sys_dummy;
select remainder(true, 2) as r14_boolean from sys.sys_dummy;
select remainder(cast(null as number), to_number('bad')) as r15_lazy_null from sys.sys_dummy;
select remainder(1e125, 3) as r15a_maxexp_three from sys.sys_dummy;
select remainder(1e125, 7) as r15b_maxexp_seven from sys.sys_dummy;

select case when remainder(11, 4) = -1 then 'PASS' else 'FAIL' end as p01_nearest
from sys.sys_dummy;
select case when remainder(7, 2) = -1 and remainder(5, 2) = 1 then 'PASS' else 'FAIL' end as p02_ties_even
from sys.sys_dummy;
select case when remainder(-6, 4) = 2 and remainder(-2, 4) = -2 then 'PASS' else 'FAIL' end as p03_sign
from sys.sys_dummy;
select case when remainder(1e125, 3) = 1e86 and remainder(1e125, 7) = -1e86
       then 'PASS' else 'FAIL' end as p04_number_guard_precision from sys.sys_dummy;

prompt === REMAINDER dynamic text lifetime ===
select remainder(to_char(10 + rownum), to_char(4)) as r24_dynamic_text from sys.sys_dummy;
select case when remainder(concat('1', to_char(rownum)), concat('0', to_char(3 + rownum))) = -1
       then 'PASS' else 'FAIL' end as p09_dynamic_concat from sys.sys_dummy;
select case when remainder(to_char(10 + rownum), to_binary_double(to_char(3 + rownum))) = to_binary_double('-1')
       then 'PASS' else 'FAIL' end as p10_dynamic_real from sys.sys_dummy;
select case when count(*) = 5 then 'PASS' else 'FAIL' end as p11_dynamic_rows
from (select 1 as n from sys.sys_dummy union all select 2 from sys.sys_dummy
      union all select 3 from sys.sys_dummy union all select 4 from sys.sys_dummy
      union all select 5 from sys.sys_dummy) t
where remainder(to_char(10 + n), to_char(4)) = remainder(10 + n, 4);
select case when remainder(concat('bad', to_char(rownum)), cast(null as number)) is null
       then 'PASS' else 'FAIL' end as p12_null_divisor from sys.sys_dummy;

prompt === REMAINDER REAL and IEEE values ===
select remainder(to_binary_double('11'), to_binary_double('4')) as r16_real from sys.sys_dummy;
select remainder(to_binary_float('11'), 4) as r17_float_real from sys.sys_dummy;
select remainder(to_binary_double('5'), to_binary_double('0')) as r18_real_zero from sys.sys_dummy;
select remainder(to_binary_double('Inf'), to_binary_double('2')) as r19_inf_dividend from sys.sys_dummy;
select remainder(to_binary_double('5'), to_binary_double('Inf')) as r20_inf_divisor from sys.sys_dummy;
select remainder(to_binary_double('NaN'), to_binary_double('2')) as r21_nan from sys.sys_dummy;
select remainder(to_binary_double('-4'), to_binary_double('2')) as r21a_zero_normalized from sys.sys_dummy;
select case when remainder(to_binary_double('-4'), to_binary_double('2')) = to_binary_double('0')
       then 'PASS' else 'FAIL' end as r21b_zero_normalized from sys.sys_dummy;

desc -q select remainder(11, 4) as r22_number_type from sys.sys_dummy;
desc -q select remainder(11, to_binary_double('4')) as r23_real_type from sys.sys_dummy;

prompt === width-independent REMAINDER value checks ===
select case when remainder(11,4)=-1 and remainder(7,2)=-1 and remainder(5,2)=1
                  and remainder(0.75,0.5)=-0.25 and remainder(1.25,0.5)=0.25
       then 'PASS' else 'FAIL' end as p05_remainder_number from sys.sys_dummy;
select case when remainder(to_binary_double('11'),to_binary_double('4'))=to_binary_double('-1')
                  and remainder(to_binary_double('5.3'),to_binary_double('2'))=
                      to_binary_double('-0.7000000000000002')
       then 'PASS' else 'FAIL' end as p07_remainder_real from sys.sys_dummy;
select case when nanvl(remainder(to_binary_double('Inf'),to_binary_double('2')),999)=999
                  and nanvl(remainder(to_binary_double('5'),to_binary_double('0')),999)=999
       then 'PASS' else 'FAIL' end as p08_remainder_nan_category from sys.sys_dummy;

prompt === dynamic binding regression ===
-- USING supplies real bind parameters; do not cast :1/:2 in the dynamic SQL.
set serveroutput on;
declare
    v_real real;
    v_real_null real := null;
    v_number number := 5;
    v_zero number := 0;
    v_status varchar(4);
    v_result real;
begin
    v_real := to_binary_double('NaN');
    execute immediate 'select case when nanvl(:1, 7) = 7 then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B01_NANVL_REAL_NAN: ' || v_status);

    v_real := 1.25;
    execute immediate 'select case when nanvl(:1, 7) = 1.25 then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B02_NANVL_REAL_FINITE: ' || v_status);

    v_real := 5;
    execute immediate 'select case when nanvl(remainder(:1, 0), 999) = 999 ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B03_REMAINDER_REAL_ZERO: ' || v_status);

    v_real := 11;
    execute immediate 'select case when remainder(:1, 4) = -1 then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B04_REMAINDER_REAL_FINITE: ' || v_status);

    v_real := to_binary_double('NaN');
    execute immediate 'select case when nanvl(remainder(:1, 4), 999) = 999 ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B05_REMAINDER_REAL_NAN: ' || v_status);

    execute immediate 'select case when nanvl(:1, 7) is null then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real_null;
    dbe_output.print_line('B06_NANVL_REAL_NULL: ' || v_status);

    execute immediate 'select case when remainder(:1, 4) is null then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real_null;
    dbe_output.print_line('B07_REMAINDER_REAL_NULL: ' || v_status);

    execute immediate 'select case when nanvl(:1, :2) = 5 then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_number, in v_real_null;
    dbe_output.print_line('B08_NANVL_NULL_REPLACEMENT: ' || v_status);

    execute immediate 'select case when remainder(11, :1) is null then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real_null;
    dbe_output.print_line('B09_REMAINDER_NULL_DIVISOR: ' || v_status);

    v_real := 1.25;
    execute immediate 'select case when nanvl(:1, 1 / :2) = 1.25 then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real, in v_zero;
    dbe_output.print_line('B10_NANVL_LAZY_REPLACEMENT: ' || v_status);

    execute immediate 'select case when nanvl(:1, 1 / :2) is null ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real_null, in v_zero;
    dbe_output.print_line('B11_NANVL_NULL_SHORT_CIRCUIT: ' || v_status);

    execute immediate 'select case when remainder(:1, 1 / :2) is null ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real_null, in v_zero;
    dbe_output.print_line('B12_REMAINDER_NULL_SHORT_CIRCUIT: ' || v_status);

    v_real := 0;
    execute immediate 'select case when nanvl(remainder(:1, :2), 999) = 999 ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_number, in v_real;
    dbe_output.print_line('B13_REMAINDER_SECOND_REAL: ' || v_status);

    v_real := to_binary_double('NaN');
    execute immediate 'select case when v = 7 then ''PASS'' else ''FAIL'' end ' ||
        'from (select nanvl(:1, 7) v from sys.sys_dummy) t'
        into v_status using in v_real;
    dbe_output.print_line('B14_NANVL_BOUND_SUBQUERY: ' || v_status);

    begin
        execute immediate 'select remainder(:1, 0) from sys.sys_dummy'
            into v_result using in v_number;
        dbe_output.print_line('B15_REMAINDER_NUMBER_ZERO: FAIL');
    exception
        when zero_divide then
            dbe_output.print_line('B15_REMAINDER_NUMBER_ZERO: PASS');
    end;

    begin
        execute immediate 'select nanvl(:1, 1 / :2) from sys.sys_dummy'
            into v_result using in v_real, in v_zero;
        dbe_output.print_line('B16_NANVL_USED_REPLACEMENT: FAIL');
    exception
        when zero_divide then
            dbe_output.print_line('B16_NANVL_USED_REPLACEMENT: PASS');
    end;

    execute immediate 'select case when nanvl(:1, :2) is null then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real, in v_real_null;
    dbe_output.print_line('B17_NANVL_NAN_NULL_REPLACEMENT: ' || v_status);

    execute immediate 'select case when (select nanvl(:1, 7) from sys.sys_dummy where 1 = 0) is null ' ||
        'then ''PASS'' else ''FAIL'' end from sys.sys_dummy'
        into v_status using in v_real;
    dbe_output.print_line('B18_NANVL_EMPTY_SCALAR: ' || v_status);
end;
/
set serveroutput off;

prompt === expected errors ===
select nanvl(to_binary_double('NaN'), to_number('bad')) as e01_nanvl_used_bad_replacement from sys.sys_dummy;
select nanvl(date '2026-08-31', 0) as e02_nanvl_date from sys.sys_dummy;
select nanvl(1) as e03_nanvl_arg_count from sys.sys_dummy;
select remainder(5, 0) as e04_number_zero from sys.sys_dummy;
select remainder(11, to_number('bad')) as e05_remainder_bad_divisor from sys.sys_dummy;
select remainder(date '2026-08-31', 2) as e06_remainder_date from sys.sys_dummy;
select remainder(1) as e07_remainder_arg_count from sys.sys_dummy;

alter system set use_bison_parser = false scope = memory;
