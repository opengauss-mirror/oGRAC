alter system set use_bison_parser = true;

create tablespace tmp_tablespace extents 4K datafile 'tmp_tablespace.dbf' size 10M;
drop tablespace tmp_tablespace;
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M;
drop tablespace tmp_tablespace;
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M all in memory; --error
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M nologging all in memory; --error
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M encryption; --error
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M nologging;
drop tablespace tmp_tablespace;
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M autooffline on;
drop tablespace tmp_tablespace;
create tablespace tmp_tablespace datafile 'tmp_tablespace.dbf' size 10M autooffline on extent autoallocate;
drop tablespace tmp_tablespace;
create tablespace tmp_tablespace extents 4K datafile 'tmp_tablespace.dbf' size 10M autooffline on extent autoallocate; --error

drop table if exists bison_t1;
create table bison_t1 (a int, b int, c int);
create index bison_t1_idx1 on bison_t1(a);
create index sys.bison_t1_idx2 on sys.bison_t1(b);
create index bison_t1_idx3 on bison_t1(abs(a));
create index bison_t1_idx4 on bison_t1(case when a = 1 then 1 else 0 end);
create index bison_t1_idx5 on bison_t1(a, b) initrans 50 pctfree 50 crmode page parallel 5 reverse nologging;
create index bison_t1_idx6 on bison_t1(c) initrans 50 pctfree 50 crmode page reverse nologging;
drop table if exists bison_desc_idx_t;
create table bison_desc_idx_t(a int primary key, b int);
create index bison_desc_idx1 on bison_desc_idx_t(a desc);
create index bison_desc_idx2 on bison_desc_idx_t(a desc); --error
drop table if exists bison_desc_idx_t;

drop table if exists bison_part_t1;
create table bison_part_t1(f1 number2, f2 number2)
PARTITION BY hash(f1) SUBPARTITION BY RANGE(f2)
(
PARTITION p1
(
SUBPARTITION PART_11 VALUES LESS THAN(20),
SUBPARTITION PART_13 VALUES LESS THAN(MAXVALUE)
),
PARTITION p2
(
SUBPARTITION PART_21 VALUES LESS THAN(1E-5),
SUBPARTITION PART_23 VALUES LESS THAN(MAXVALUE)
)
);
create index bison_part_t1_idx1 on bison_part_t1(f1) local
(partition p1, partition p2 (subpartition p21, subpartition p22)); --error
create index bison_part_t1_idx1 on bison_part_t1(f1) local (
partition p1 initrans 50 pctfree 50 storage (initial 64K next 5K maxsize 1024K)
    compress for all operations format csf
    (subpartition p11, subpartition p12),
partition p2 (subpartition p21, subpartition p22)); --error

create index bison_part_t1_idx1 on bison_part_t1(f1) local (
partition p1 initrans 50 pctfree 50 storage (initial 64K next 5K maxsize 1024K)
    compress for all operations (subpartition p11, subpartition p12),
partition p2 (subpartition p21, subpartition p22));

-- ============================================
-- CREATE SEQUENCE test cases
-- ============================================

-- Basic and schema qualified
drop sequence if exists seq_basic;
create sequence seq_basic;
drop sequence if exists seq_basic;

drop sequence if exists sys.seq_schema;
create sequence sys.seq_schema;
drop sequence if exists sys.seq_schema;

-- Single options
drop sequence if exists seq1;
create sequence seq1 increment by 2;
drop sequence if exists seq1;

drop sequence if exists seq2;
create sequence seq2 increment by -1;
drop sequence if exists seq2;

drop sequence if exists seq3;
create sequence seq3 minvalue 1 maxvalue 100;
drop sequence if exists seq3;

drop sequence if exists seq4;
create sequence seq4 nominvalue nomaxvalue;
drop sequence if exists seq4;

drop sequence if exists seq5;
create sequence seq5 start with 10;
drop sequence if exists seq5;

drop sequence if exists seq6;
create sequence seq6 cache 20;
drop sequence if exists seq6;

drop sequence if exists seq7;
create sequence seq7 nocache;
drop sequence if exists seq7;

drop sequence if exists seq8;
create sequence seq8 cycle; -- error
drop sequence if exists seq8;

drop sequence if exists seq9;
create sequence seq9 nocycle;
drop sequence if exists seq9;

drop sequence if exists seq10;
create sequence seq10 order;
drop sequence if exists seq10;

drop sequence if exists seq11;
create sequence seq11 noorder;
drop sequence if exists seq11;

-- Combined options
drop sequence if exists seq12;
create sequence seq12 increment by 2 minvalue 1 maxvalue 100 start with 10;
drop sequence if exists seq12;

drop sequence if exists seq13;
create sequence seq13 increment by 1 minvalue 1 maxvalue 100 cache 20 cycle;
drop sequence if exists seq13;

drop sequence if exists seq14;
create sequence seq14 increment by -1 minvalue -1000 maxvalue -1 start with -100;
drop sequence if exists seq14;

drop sequence if exists seq15;
create sequence seq15 increment by 1 nominvalue nomaxvalue nocache nocycle noorder;
drop sequence if exists seq15;

-- All options combined
drop sequence if exists seq16;
create sequence seq16 increment by 2 minvalue 1 maxvalue 100 start with 10 cache 20 cycle order;
drop sequence if exists seq16;

-- Option order variations
drop sequence if exists seq17;
create sequence seq17 start with 10 increment by 2 minvalue 1 maxvalue 100 cache 20;
drop sequence if exists seq17;

drop sequence if exists seq18;
create sequence seq18 cycle minvalue 1 maxvalue 100 increment by 1 cache 15 order;
drop sequence if exists seq18;

-- ============================================
-- CREATE VIEW test cases
-- ============================================

-- Basic view
drop view if exists view_basic;
create view view_basic as select 1 as col1;
drop view if exists view_basic;

-- View with schema
drop view if exists sys.view_schema;
create view sys.view_schema as select 1 as col1;
drop view if exists sys.view_schema;

-- View with column list
drop view if exists view_cols;
create view view_cols(col1, col2) as select 1, 2;
drop view if exists view_cols;

-- View from table
drop table if exists t_view1;
create table t_view1(id int, name varchar(100));
drop view if exists view_t1;
create view view_t1 as select id, name from t_view1;
drop view if exists view_t1;
drop table if exists t_view1;

-- OR REPLACE
drop view if exists view_replace;
create view view_replace as select 1 as col1;
create or replace view view_replace as select 2 as col1;
drop view if exists view_replace;

-- FORCE
drop view if exists view_force;
create or replace view view_force(a, b) as select a, b from t_view1;
create or replace force view view_force(a, b) as select a, b from t_view1;
drop view if exists view_force;

-- View with complex select
drop table if exists t_view2;
create table t_view2(id int, name varchar(100), age int);
drop view if exists view_complex;
create view view_complex as select id, name from t_view2 where age > 18;
drop view if exists view_complex;
drop table if exists t_view2;

-- View with join
drop table if exists t_view3;
drop table if exists t_view4;
create table t_view3(id int, name varchar(100));
create table t_view4(id int, addr varchar(100));
drop view if exists view_join;
create view view_join as select t3.id, t3.name, t4.addr from t_view3 t3 join t_view4 t4 on t3.id = t4.id;
drop view if exists view_join;
drop table if exists t_view3;
drop table if exists t_view4;

-- ============================================
-- CREATE SYNONYM test cases
-- ============================================

-- Basic synonym
drop table if exists t_syn1;
create table t_syn1(id int, name varchar(100));
drop synonym if exists syn1;
create synonym syn1 for t_syn1;
drop synonym if exists syn1;
drop table if exists t_syn1;

-- Synonym with schema
drop table if exists sys.t_syn2;
create table sys.t_syn2(id int);
drop synonym if exists sys.syn2;
create synonym sys.syn2 for sys.t_syn2;
drop synonym if exists sys.syn2;
drop table if exists sys.t_syn2;

-- OR REPLACE
drop table if exists t_syn3;
create table t_syn3(id int);
drop synonym if exists syn3;
create synonym syn3 for t_syn3;
create or replace synonym syn3 for t_syn3;
drop synonym if exists syn3;
drop table if exists t_syn3;

-- PUBLIC synonym
drop table if exists t_syn4;
create table t_syn4(id int);
drop public synonym if exists syn4;
create public synonym syn4 for t_syn4;
drop public synonym if exists syn4;
drop table if exists t_syn4;

-- OR REPLACE PUBLIC
drop table if exists t_syn5;
create table t_syn5(id int);
drop public synonym if exists syn5;
create or replace public synonym syn5 for t_syn5;
drop public synonym if exists syn5;
drop table if exists t_syn5;

-- ============================================
-- CREATE PROFILE test cases
-- ============================================

-- Basic profile
create profile profile_basic limit sessions_per_user 10;
drop profile profile_basic;

-- OR REPLACE
create profile profile_replace limit sessions_per_user 5;
create or replace profile profile_replace limit sessions_per_user 10;
drop profile profile_replace;

create profile profile_replace limit sessions_per_user unlimited;
drop profile profile_replace;

create profile profile_replace limit failed_login_attempts default;
drop profile profile_replace;

create profile profile_replace limit failed_login_attempts default failed_login_attempts unlimited; --error

-- ============================================
-- CREATE DIRECTORY test cases
-- ============================================

-- Basic directory
create directory dir_basic as 'data';
drop directory dir_basic;

-- OR REPLACE
create directory dir_replace as 'data';
create or replace directory dir_replace as 'install';
drop directory dir_replace;

-- ============================================
-- CREATE LIBRARY test cases
-- ============================================

-- Basic library
create library lib_basic as '/usr/lib/lib1.so';

-- OR REPLACE
create or replace library lib_replace as '/usr/lib/lib2.so';

-- Library with schema
create library sys.lib_schema as '/usr/lib/lib1.so';

-- Library with IS
create library lib_is is '/usr/lib/lib1.so';

drop table if exists bison_t2;
drop table if exists bison_t1;
create table bison_t1 (a int unique, b int default 2 on update 5, c char(5) not null collate 'UTF8_BIN', d int check (d > 0) comment 'gt 0',
    constraint p_key3 primary key (b) enable initially immediate rely parallel 2 validate);
create table bison_t2 (a int auto_increment, b int references bison_t1(b) on delete cascade, c char(5) constraint null_c null,
    primary key (a) using index reverse) initrans 50 maxtrans 80 pctfree 10 crmode page format csf
    storage (initial 64K next 5K maxsize 1024K) auto_increment 5
    default charset 'UTF8' collate = 'UTF8_BIN' cache logging nocompress;

alter system set LOCAL_TEMPORARY_TABLE_ENABLED = true;
drop table if exists bison_t2;
create temporary table bison_t2 (a int, b int, primary key (b)) on commit preserve rows; --error
create temporary table #bison_t2 (a int, b int, primary key (b)) on commit preserve rows;
drop temporary table #bison_t2;

create global table #bison_t2 (a int, b int, primary key (b)) on commit preserve rows; --error
create global temporary table bison_t2 (a int, b int, primary key (b)) on commit preserve rows;
drop table bison_t2;
alter system set LOCAL_TEMPORARY_TABLE_ENABLED = false;

drop table if exists bison_t3;
create table bison_t3 (a int, b blob) lob (b) store as;
drop table if exists bison_t3;
create table bison_t3 (a int, b blob) lob (b) store as clob_bison_t1 (enable storage in row);

drop table if exists bison_t3;
create table bison_t3 (a int, b blob, c blob) lob (b, c) store as appendonly;

drop table if exists bison_t3;
create table bison_t3 (a int, b default 'c'); --error
create table bison_t3 (a int, b default 'c') as select 1, 'd'; --error, cannot specify datatype
create table bison_t3 (a, b default 'c') as select 1, 'd';

drop table if exists bison_t3;
create table bison_t3 as select 1, 'd'; --error
create table bison_t3 as select 1 as a, 'd' as b;

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by range (c_number)
(
 partition p1 values less than (-1) initrans 40,
 partition p4 values less than (maxvalue)
);

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by hash (c_number)
(
 partition p1,
 partition p4
);

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by list (c_number, c_int)
(
 partition p1 values ((5, 5), (10, 10)),
 partition p4 values (default)
);

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by range (c_number) subpartition by hash(c_int)
(
 partition p1 values less than (-1) initrans 40 (subpartition p11, subpartition p12),
 partition p4 values less than (1000000) (subpartition p41, subpartition p42)
);

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by range (c_number) subpartition by hash(c_int) subpartitions 3
(
 partition p1 values less than (-1) initrans 40,
 partition p4 values less than (1000000)
);

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by hash (c_number) subpartition by hash(c_int) partitions 3 subpartitions 2;

drop table if exists bison_t3;
create table bison_t3
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by range (c_number) subpartition by hash(c_int) partitions 3 subpartitions 2; --error

create directory tmp_directory as './';
drop table if exists bison_t3;
create table bison_t3 (a int, b char(10)) organization external
(type loader directory tmp_directory access parameters (records delimited by newline fields terminated by ',') location '/home/ogracdba');

drop table if exists bison_t3;
create table bison_t3 (a int, b char(10)) organization external
(type loader directory tmp_directory access parameters (records delimited by 'a') location '/home/ogracdba'); --error

drop table if exists bison_t3;
create table bison_t3 (a int, b char(10)) organization external
(type loader directory tmp_directory location '/home/ogracdba');
drop directory tmp_directory;

drop table if exists bison_t1;
create table bison_t1 (a int, b int);
alter table bison_t1 add constraint p_key primary key (b) enable disable using index (create unique index idx1 on bison_t1(b));

CREATE USER "XBIN" IDENTIFIED BY Huawei123;
create role role1;
create directory tmp_directory as './';
grant alter, insert on table bison_t1 to xbin with grant option;
grant ON COMMIT REFRESH, GRANT ANY ROLE to xbin;
grant alter node to xbin;
grant inherit privileges on user xbin to xbin;
grant read on directory tmp_directory to xbin;
grant read on directory tmp_directory to public, xbin;
grant write, read on directory tmp_directory to xbin; --error

grant role1, alter any index to xbin with admin option;
grant role1, alter any index to xbin with grant option; --error

revoke alter, insert on table bison_t1 from xbin cascade constraints;
revoke on commit refresh, grant any role from xbin;
revoke alter node from xbin;
revoke inherit privileges on user xbin from xbin;
revoke read on directory tmp_directory from xbin;
revoke write, read on directory tmp_directory from xbin; --error
revoke role1, alter any index from xbin cascade constraints; --error

drop role role1;
drop user xbin;
drop directory tmp_directory;

CREATE OR REPLACE FUNCTION convert1 (
    p_num1 NUMBER,
    p_num2 NUMBER
)
RETURN NUMBER IS
    v_result NUMBER;
BEGIN
    v_result := p_num1 + p_num2;
    RETURN v_result;
END convert1;
/

select convert1(1,1);
drop function convert1;

DROP TRIGGER IF EXISTS insert_readonly_view;
DROP TRIGGER IF EXISTS update_readonly_view;
DROP TRIGGER IF EXISTS delete_readonly_view;

DROP VIEW IF EXISTS read_only_view;

DROP TABLE IF EXISTS test_table;

CREATE TABLE test_table (
                            id INT PRIMARY KEY,
                            name VARCHAR(50),
                            age INT
);

INSERT INTO test_table VALUES (1, '张三', 25);
INSERT INTO test_table VALUES (2, '李四', 30);
INSERT INTO test_table VALUES (3, '王五', 28);

CREATE VIEW read_only_view WITH READ ONLY AS
SELECT id, name, age FROM test_table;

SELECT * FROM read_only_view;

INSERT INTO read_only_view VALUES (5, '钱七', 40);

UPDATE read_only_view SET age = 31 WHERE id = 2;

DELETE FROM read_only_view WHERE id = 2;

SELECT * FROM test_table;

DROP VIEW read_only_view;

DROP TABLE test_table;

alter system set use_bison_parser = false;
drop table if exists native_desc_idx_t;
create table native_desc_idx_t(a int primary key, b int);
create index native_desc_idx1 on native_desc_idx_t(a desc);
create index native_desc_idx2 on native_desc_idx_t(a desc); --error
drop table if exists native_desc_idx_t;
