-- A-compatible downstream contract after TO_BINARY_FLOAT/DOUBLE return OG_TYPE_REAL.
-- Differences from Oracle independent BINARY_FLOAT/BINARY_DOUBLE types are intentional.
-- The F-suffixed literal requires Bison; preceding schedule cases may disable it.
alter system set use_bison_parser = true scope = memory;
set pagesize 200
set linesize 240

prompt === result descriptor and physical width ===
desc -q select to_binary_float('1.25') as bf_result;
desc -q select to_binary_double('1.25') as bd_result;
select vsize(to_binary_float('1.25')) as bf_expr_size,
       vsize(to_binary_double('1.25')) as bd_expr_size
from sys.sys_dummy;

prompt === downstream arithmetic uses existing REAL ===
-- Oracle BINARY_FLOAT re-quantizes this addition to 16777216; oGRAC REAL returns 16777217.
select to_binary_float('16777216') + 1 as bf_add_one from sys.sys_dummy;
select case when to_binary_float('16777216') + 1 = 16777217
       then 'PASS' else 'FAIL' end as bf_add_real_check from sys.sys_dummy;
-- Both use binary64 here; 2^53 + 1 rounds back to 2^53.
select to_binary_double('9007199254740992') + 1 as bd_add_one from sys.sys_dummy;
select case when to_binary_double('9007199254740992') + 1 =
                      to_binary_double('9007199254740992')
       then 'PASS' else 'FAIL' end as bd_add_binary64_check from sys.sys_dummy;
-- oGRAC REAL division raises OG-00637; Oracle binary floating-point division returns Inf.
select to_binary_float('1') / 0 as bf_div_zero from sys.sys_dummy;
select to_binary_double('1') / 0 as bd_div_zero from sys.sys_dummy;

prompt === downstream comparisons use existing REAL comparator ===
select case when to_binary_float('1') < to_binary_float('Inf')
       then 'TRUE' else 'FALSE' end as bf_finite_lt_inf from sys.sys_dummy;
select case when to_binary_float('Inf') = to_binary_float('Inf')
       then 'TRUE' else 'FALSE' end as bf_inf_equal from sys.sys_dummy;
select case when to_binary_float('NaN') = to_binary_float('NaN')
       then 'TRUE' else 'FALSE' end as bf_nan_equal from sys.sys_dummy;
select case when to_binary_float('NaN') > to_binary_float('Inf')
       then 'TRUE' else 'FALSE' end as bf_nan_gt_inf from sys.sys_dummy;

select case when to_binary_double('1') < to_binary_double('Inf')
       then 'TRUE' else 'FALSE' end as bd_finite_lt_inf from sys.sys_dummy;
select case when to_binary_double('Inf') = to_binary_double('Inf')
       then 'TRUE' else 'FALSE' end as bd_inf_equal from sys.sys_dummy;
select case when to_binary_double('NaN') = to_binary_double('NaN')
       then 'TRUE' else 'FALSE' end as bd_nan_equal from sys.sys_dummy;
select case when to_binary_double('NaN') > to_binary_double('Inf')
       then 'TRUE' else 'FALSE' end as bd_nan_gt_inf from sys.sys_dummy;

prompt === existing BINARY_* DDL keywords still map to REAL storage ===
create table t_binary_fp_real_contract (
    id integer,
    bf_value binary_float,
    bd_value binary_double
);
desc t_binary_fp_real_contract;
insert into t_binary_fp_real_contract values (
    1, to_binary_float('1.25'), to_binary_double('1.25')
);
select vsize(bf_value) as bf_stored_size,
       vsize(bd_value) as bd_stored_size
from t_binary_fp_real_contract;

prompt === indexes are ordinary REAL indexes ===
create index idx_binary_fp_real_bf on t_binary_fp_real_contract(bf_value);
create index idx_binary_fp_real_bd on t_binary_fp_real_contract(bd_value);
select count(*) as bf_index_match
from t_binary_fp_real_contract
where bf_value = to_binary_float('1.25');
select count(*) as bd_index_match
from t_binary_fp_real_contract
where bd_value = to_binary_double('1.25');
drop table t_binary_fp_real_contract;

prompt === existing cast and literal behavior is not changed by the functions ===
select cast(16777217 as binary_float) as cast_bf_baseline from sys.sys_dummy;
select 16777217F as f_literal_baseline from sys.sys_dummy;
select cast(9007199254740993 as binary_double) as cast_bd_baseline from sys.sys_dummy;

-- Restore the regression suite's native parser default without changing the config file.
alter system set use_bison_parser = false scope = memory;
