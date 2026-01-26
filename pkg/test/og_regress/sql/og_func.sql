SELECT TIMESTAMPADD (WEEK, 2, '2025-11-25');
SELECT TIMESTAMPADD (DAY, MOD(1,20), '2025-11-25 14:14:14');
SELECT CURRENT_TIMESTAMP(-1);
SELECT TO_NUMBER('10E+128');
SELECT IF(concat_ws('-', 'a', 'b', 'c'), 'cond is true', 'cond is false');
SELECT IF(concat_ws('-', 'a', 'b', 'c') = 'a-b-c', 'cond is true', 'cond is false');
drop table if exists t_null_if;
create table t_null_if(a int, b blob, c clob);
select nullif(b, to_blob('')) from t_null_if;
drop table if exists t_null_if;

-- array_length test
select array_length(null) from SYS_DUMMY;
select array_length(rownum) from SYS_DUMMY;

-- listagg size
desc -q select distinct listagg('aa', '|') within group (order by 1) over (partition by 2);

-- nullif function
select nullif('oGRAC','  oGRAC');
select nullif('   ','   ');
select nullif(to_blob('oGRAC'), to_blob('oGRAC'));
select nullif(to_blob('oGRAC'), to_clob('oGRAC'));
select nullif('100', 100);
select nullif(cast(100 as int), cast(100.00 as float));
select nullif(cast(100 as int), cast(100.00 as decimal(7,2)));
select nullif(cast(100 as real), cast(100.00 as decimal(7,2)));
select nullif(to_blob('oGRAC'), null);
select nullif(to_clob('oGRAC'), null);
select nullif('100', null);
select nullif(100, null);

drop table if exists t1;
create table t1(c1 clob, c2 clob, b1 clob, b2 clob, i1 int, v1 varchar(10));
insert into t1 values('oGRAC', 'oGRAC', '111', '111', 111, '111');
select nullif(c1, c2) from t1;
select nullif(b1, b2) from t1;
select nullif(c1, i1) from t1;
select nullif(i1, b1) from t1;
select nullif(v1, b1) from t1;
drop table t1;
drop table if exists t2;
create table t2 (a int, b blob, c clob);
select nullif(b, to_blob('')) from t2;
select nullif(c, to_clob('')) from t2;
select nullif(to_blob('aa'), to_blob('')) from t2;
select nullif(to_blob('aa'), null) from t2;
select nullif('abc', b) from t2;
drop table t2;

drop table if exists t3;
create table t3(c1 char(30), c2 varchar(20));
insert into t3 values('oGRAC', 'oGRAC');
insert into t3 values('数据', '数据');
insert into t3 values(null, 'engine');
select * from t3 where c1 = nullif('oGRAC', 'oGRAC');
select * from t3 where c1 = nullif('数据', '数据');
select * from t3 where c1 = nullif('oGRAC', 'engine');
select * from t3 where c1 = nullif('数据', 'oGRAC');
drop table t3;

-- test enable_permissive_unicode
drop table if exists t_hex_trim_func_1;
drop table if exists t_hex_trim_func_2;
create table t_hex_trim_func_1(c1 varchar(32 byte));
create table t_hex_trim_func_2(c1 varchar(32 byte));
insert into t_hex_trim_func_1 values(0xffffffffffffffffffffffffffffffff);
select HEX(c1) from t_hex_trim_func_1;
alter system set enable_permissive_unicode = FALSE;
insert into t_hex_trim_func_2 select ltrim(rtrim(c1)) from t_hex_trim_func_1;
alter system set enable_permissive_unicode = TRUE;
insert into t_hex_trim_func_2 select ltrim(rtrim(c1)) from t_hex_trim_func_1;
select HEX(c1) from t_hex_trim_func_2;
select hex(CONCAT(tab1.c1, tab2.c1)) from t_hex_trim_func_1 tab1, t_hex_trim_func_2 tab2;
drop table t_hex_trim_func_1;
drop table t_hex_trim_func_2;

-- test bool datatype support window func
drop table if exists bool_func_t;
create table bool_func_t (f1 bool, f2 int, f3 int);
insert into bool_func_t values(TRUE,1,1),(TRUE,2,1),(FALSE,3,2),(FALSE,4,2),(FALSE,5,3),(TRUE,6,3);
select f1, f2, f3, lag(f1, '2', 0) over (order by f1) res from bool_func_t order by f1;
select f1, f2, f3, lag(f1, '2', 0) over (partition by f3 order by f2) res from bool_func_t order by f1;
select min(f1) over (partition by f3 order by f2) from bool_func_t order by f1;
select max(f1) over (partition by f3 order by f2) from bool_func_t order by f1;
select f1, f2, f3, last_value(f1) over (partition by f3 order by f2) res from bool_func_t order by f1;
drop table bool_func_t;

-- test translate
select translate('100000','\12345','\');
select length(translate('100000','\12345','\'));
select translate('100000','\1234567890','\');
select length(translate('100000','\1234567890','\'));
select translate('100000','1234567890','S');
select translate('100000','91234567890','S');
select translate('cantian','INNODB','MYSQL');
-- when empty_string_as_null is true, the '' as null
select nvl2(translate('100000','\1234567890','\'), 'IS NOT NULL', 'IS NULL') as res from SYS_DUMMY;
select nvl2(translate('','',''), 'IS NOT NULL', 'IS NULL') as res from SYS_DUMMY;
select nvl2(translate('100000','1234567890',''), 'IS NOT NULL', 'IS NULL') as res from SYS_DUMMY;

-- support the to_int, to_bigint
desc -q select to_int(2.00) as val;
select to_int(to_char('123')) as val;
desc -q select to_bigint(2.00) as val;
select to_bigint(to_char('123')) as val;