drop table if exists t_expl_0;
create table t_expl_0(f_int1 int, f_int2 int);
insert into t_expl_0(f_int1, f_int2) values(1, 11);
explain plan for select * from t_expl_0;
explain plan for xselect * from t_expl_0;
drop table if exists t_expl_0;
-- ------------------ test [not]like convert to [not]equal --------------------------
-- prepare
drop table if exists like_optm_t;
create table like_optm_t (id int, a varchar(20), b varchar(20), c clob, d raw(50), e char(5));
insert into like_optm_t values (1, 'storage','aaa','11111','123456789','12345');
insert into like_optm_t values (2, 'mysql','bbb','22222','987654321','abcde');
insert into like_optm_t values (3, 'openGauss','ccc','33333','20250715','ABCDE');
insert into like_optm_t values (4, 'cantian','ddd','44444','19980804','QWERF');
insert into like_optm_t values (5, null,'',null,'','A');
insert into like_optm_t values (6, 'Innodb','2025-07-15 00:00:00','66666','19980804','AAA');
insert into like_optm_t values (7, 'mysql%','b_bb','22_22%2','123456789','12345');
commit;

--  like --> equal
explain select * from like_optm_t where a like 'mysql';
explain select * from like_optm_t where b like 'cc_'; -- no convert
explain select * from like_optm_t where c not like '11111';
explain select * from like_optm_t where d like '20250715';
select count(*) from like_optm_t where d like '20250715';

-- const val or bind param in the left no optim
explain select * from like_optm_t where 'cantian' like a;
explain select * from like_optm_t where '19980804' like d;
explain select * from like_optm_t where '44444' like c;

-- = null or != null 当前不存在转换
explain select * from like_optm_t where a like '';
explain select * from like_optm_t where b not like '';

-- 'like null' or 'not like null' no optim 
explain select * from like_optm_t where c not like null; -- reversed type 不进行优化
explain select * from like_optm_t where d like null;

-- when bind param no convert
explain select * from like_optm_t where c like ?;
explain select * from like_optm_t where d not like :val;
explain select * from like_optm_t where ? like a;
explain select * from like_optm_t where ? like b;

-- char(n) test
explain select * from like_optm_t where e like '12345';
explain select * from like_optm_t where e like 'AAA';
select count(*) from like_optm_t where e like 'AAA%';
explain select * from like_optm_t where e like upper('abcde');
explain select * from like_optm_t where e like to_char('A    ');
select id from like_optm_t where e like to_char('A    ');
explain select * from like_optm_t where e like cast('A' as char(5));
select id from like_optm_t where e like cast('A' as char(5));

-- func test
explain select * from like_optm_t where c like bin2hex('0x26');
explain select * from like_optm_t where id like char_length('mysql');
select id from like_optm_t where id like char_length('mysql');
explain select * from like_optm_t where d like hextoraw('19980804');
select count(*) from like_optm_t where d like hextoraw('19980804');
explain select * from like_optm_t where lower(a) like 'cantian';
select id from like_optm_t where lower(a) like 'cantian';
explain select * from like_optm_t where b like to_date('2025-07-15', 'yyyy-mm-dd');
select id from like_optm_t where b like to_date('2025-07-15', 'yyyy-mm-dd');
explain select * from like_optm_t where a like cast('openGauss' as char(9));
select id from like_optm_t where a like cast('openGauss' as char(9));
explain select * from like_optm_t where a like concat('Inn','odb'); -- right no const val
select id from like_optm_t where a like concat('Inn','odb');

-- test \% \_
explain select * from like_optm_t where a like 'mysql\%' escape '\';
select a from like_optm_t where a like 'mysql\%' escape '\';
select a from like_optm_t where a = 'mysql%';

explain select * from like_optm_t where b like 'b\_bb' escape '\';
select b from like_optm_t where b like 'b\_bb' escape '\';
select b from like_optm_t where b = 'b_bb';

explain select * from like_optm_t where c like '22\_22\%2' escape '\';
select c from like_optm_t where c like '22\_22\%2' escape '\';
select c from like_optm_t where c = '22_22%2';

drop table if exists like_optm_t;

-- test
drop table if exists t1;
drop table if exists t2;
create table t1(id int, location int);
create table t2(id int, revenue int);
explain select t2.id, sum(revenue) from t1, t2 where t2.id = t1.id group by t2.id having sum(revenue) >=2;
drop table if exists t1;
drop table if exists t2;

--- test explain const node
create table t1(c1 varchar(20));
explain select * from t1 where c1 in (lpad('1',4090,'0'));
explain select * from t1 where c1 in (lpad('1',101,'0'));
explain select * from t1 where c1 in (lpad('1',100,'0'));
explain select * from t1 where c1 in (lpad('1',99,'0'));
explain select * from t1 where c1 in (lpad('1',0,'0'));
drop table t1;

--- test explain connect by
EXPLAIN PLAN FOR SELECT level, MOD(level,2) AS parity, POWER(level,2) AS squared FROM SYS_DUMMY CONNECT BY level <= 10;
EXPLAIN PLAN FOR SELECT level, MOD(level,2) AS parity, POWER(level,2) AS squared FROM 
    (SELECT 1 AS seed FROM SYS_DUMMY) START WITH seed = 1 CONNECT BY PRIOR seed = seed AND LEVEL <= 10;

