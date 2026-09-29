-- INITCAP/NCHR A-compatible function verification.
-- Text assertions and RAWTOHEX are used so client locale/display does not
-- affect the Oracle/oGRAC comparison.
alter system set use_bison_parser = true scope = memory;
set feedback on;
set heading on;

prompt === INITCAP basic and word boundaries ===
select initcap('the soap') as i01_basic from sys.sys_dummy;
select initcap('hello-world_sql') as i02_punctuation from sys.sys_dummy;
select initcap('oracle''s') as i03_apostrophe from sys.sys_dummy;
select initcap('abc123DEF 99BOTTLES x9-y2') as i04_alnum from sys.sys_dummy;
select initcap('  MIXED  case') as i05_spaces from sys.sys_dummy;
select initcap(123.45) as i06_numeric from sys.sys_dummy;
select case when initcap('') is null and initcap(null) is null
       then 'PASS' else 'FAIL' end as i07_nulls from sys.sys_dummy;

prompt === INITCAP deterministic multibyte mapping ===
select case when initcap('élÈVE') = 'Élève' then 'PASS' else 'FAIL' end as i08_accent
from sys.sys_dummy;
select case when initcap('straße') = 'Straße' then 'PASS' else 'FAIL' end as i09_sharp_s
from sys.sys_dummy;
select case when initcap('你hELLO 世WORLD') = '你hello 世world' then 'PASS' else 'FAIL' end as i10_cjk
from sys.sys_dummy;

prompt === INITCAP return type contract ===
desc -q select initcap(cast('a' as char(5))) as i11_char, initcap(cast('a' as varchar(5))) as i12_varchar from sys.sys_dummy;
select '[' || initcap(cast('a' as char(5))) || ']' as i13_char_padding from sys.sys_dummy;

prompt === INITCAP multibyte CTAS length inference ===
-- Use table columns so constant folding cannot hide an undersized result type.
create table t_initcap_length_src (id integer, b varchar(2 byte), c varchar(1 char));
insert into t_initcap_length_src values (1, 'ȿ', 'ȿ');
insert into t_initcap_length_src values (2, 'a', 'a');
insert into t_initcap_length_src values (3, null, null);
commit;
create table t_initcap_length_dst as
select id, initcap(b) as b, initcap(c) as c from t_initcap_length_src;
select case when rawtohex(b) = 'E2B1BE' and lengthb(b) = 3
       then 'PASS' else 'FAIL' end as i14_byte_ctas
from t_initcap_length_dst where id = 1;
select case when rawtohex(c) = 'E2B1BE' and length(c) = 1 and lengthb(c) = 3
       then 'PASS' else 'FAIL' end as i15_char_ctas
from t_initcap_length_dst where id = 1;
select case when b = 'A' and c = 'A' and lengthb(b) = 1 and lengthb(c) = 1
       then 'PASS' else 'FAIL' end as i16_ascii_ctas
from t_initcap_length_dst where id = 2;
select case when b is null and c is null then 'PASS' else 'FAIL' end as i17_null_ctas
from t_initcap_length_dst where id = 3;
drop table t_initcap_length_dst purge;
drop table t_initcap_length_src purge;

prompt === NCHR valid code units and conversion ===
select rawtohex(nchr(65)) as n01_ascii,
       rawtohex(nchr(233)) as n02_accent,
       rawtohex(nchr(20320)) as n03_cjk,
       rawtohex(nchr(8364)) as n04_euro
from sys.sys_dummy;
select rawtohex(nchr(65.1)) as n05_trunc_low,
       rawtohex(nchr(65.9)) as n06_trunc_high,
       rawtohex(nchr('65')) as n07_text,
       rawtohex(nchr(true)) as n08_boolean
from sys.sys_dummy;
select rawtohex(nchr(65535)) as n09_ffff,
       rawtohex(nchr(65536)) as n10_wrap_zero,
       rawtohex(nchr(65537)) as n11_wrap_one,
       rawtohex(nchr(4294967295)) as n12_max_u32
from sys.sys_dummy;
select length(nchr(0)) as n13_nul_chars,
       lengthb(nchr(0)) as n14_nul_bytes,
       rawtohex(nchr(0)) as n15_nul_hex
from sys.sys_dummy;
select case when nchr(null) is null then 'PASS' else 'FAIL' end as n16_null
from sys.sys_dummy;

prompt === NCHR return type contract ===
desc -q select nchr(65) as n17_type from sys.sys_dummy;

prompt === expected errors and explicit contractions ===
select initcap() as e01_initcap_no_arg from sys.sys_dummy;
select initcap('a', 'b') as e02_initcap_many_args from sys.sys_dummy;
select nchr() as e03_nchr_no_arg from sys.sys_dummy;
select nchr(1, 2) as e04_nchr_many_args from sys.sys_dummy;
select nchr(-1) as e05_nchr_negative from sys.sys_dummy;
select nchr(4294967296) as e06_nchr_too_large from sys.sys_dummy;
select nchr(55296) as e07_high_surrogate from sys.sys_dummy;
select nchr(57343) as e08_low_surrogate from sys.sys_dummy;
select nchr(date '2026-08-31') as e09_nchr_date from sys.sys_dummy;

alter system set use_bison_parser = false scope = memory;
