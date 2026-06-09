alter system set use_bison_parser = true;

select n'abcd';
select N'abcd';
select n'1234';
select N'1234';
select N'1234', n'3456';
select N'1234' as col1, n'1234' as col2, '1234' as col3;

drop table if exists test1;
create table test1(id varchar(10));
insert into test1 values('abcd');
insert into test1 values(n'abcd');
insert into test1 values(N'abcd');
insert into test1 values('1234');
insert into test1 values(n'1234');
insert into test1 values(N'1234');
select * from test1;

drop table if exists test2;
create table test2(id varchar(10) default '1234', id1 varchar(10) default '1234', id2 int);
insert into test2(id2) values(1);
select * from test2;

create table test3(id varchar(10) default N'1234', id1 varchar(10) default '1234', id2 int);
insert into test3(id2) values(1);
select * from test3;

create table test_clob(c1 clob, c2 nclob);
insert into test_clob values('abcdefg', 'abcdefg');
select * from test_clob;

create table test_clob2(c1 clob not null);
create table test_clob3(c1 nclob not null);

create index index2 on test_clob(c1); --error
create index index2 on test_clob(c2); --error

select 'abcdefg'::clob; --error
select 'abcdefg'::nclob; --error

create table test_clob_array(c1 clob[]); --error
create table test_clob_array(c1 clob[]); --error

create table test_clob4(c1 clob(10));
insert into test_clob4 values('0123456789');
insert into test_clob4 values('0123456789000');
insert into test_clob4 values('01234567890000000000000000000000000');
select * from test_clob4;

create table test_clob5(c1 nclob(10));
insert into test_clob5 values('0123456789');
insert into test_clob5 values('0123456789000');
select * from test_clob5;

create table test_text(c1 text(10));
insert into test_text values('0123456789');
insert into test_text values('0123456789000');
select * from test_text;

-- char, nchar default value 1
create table test_char1(
    c1 char,
    c2 char(10),
    c3 char(10 byte),
    c4 char(10 char),
    c5 nchar,
    c6 nchar(10)
);
show create table test_char1;

create table test_char2(
    c1 varchar(10),
    c2 varchar(10 byte),
    c3 varchar(10 char),
    c4 varchar2(10),
    c5 varchar2(10 byte),
    c6 varchar2(10 char),
    c7 nvarchar(10),
    c8 nvarchar2(10)
);
show create table test_char2;

-- varchar, varchar2, nvarchar, nvarchar2, the column size must be specified
create table test_char3(
    c1 varchar,
    c2 varchar2,
    c3 nvarchar,
    c4 nvarchar2
); --error

create table test_char3(
    c1 national character varying(10),
    c2 national char varying(10),
    c3 nchar varying(10)
);
show create table test_char3;

create table test_char3(
    c1 national character varying,
    c2 national char varying,
    c3 nchar varying
); --error

create table test_char4(
    c1 national character,
    c2 national char,
    c3 nchar
);
show create table test_char4;

create table test_char5(
    c1 national character(10),
    c2 national char(10),
    c3 nchar(10)
);
show create table test_char5;

select '1234'::char;
select '1234'::char(5);
select '1234'::char(5 char);
select '1234'::char(5 byte);

select '1234'::nchar;
select '1234'::nchar(5);
select '1234'::nchar(5 char); --error
select '1234'::nchar(5 byte); --error

select '1234'::varchar; --error
select '1234'::varchar(5);
select '1234'::varchar(5 char);
select '1234'::varchar(5 byte);

select '1234'::varchar2; --error
select '1234'::varchar2(5);
select '1234'::varchar2(5 char);
select '1234'::varchar2(5 byte);

select '1234'::nvarchar; --error
select '1234'::nvarchar(5);
select '1234'::nvarchar(5 char); --error
select '1234'::nvarchar(5 byte); --error

select '1234'::nvarchar2; --error
select '1234'::nvarchar2(5);
select '1234'::nvarchar2(5 char); --error
select '1234'::nvarchar2(5 byte); --error

select '1234'::national character;
select '1234'::national character(5);
select '1234'::national character(5 char); --error
select '1234'::national character(5 byte); --error

select '1234'::national char;
select '1234'::national char(5);
select '1234'::national char(5 char); --error
select '1234'::national char(5 byte); --error

select '1234'::national character varying; --error
select '1234'::national character varying(5);
select '1234'::national character varying(5 char); --error
select '1234'::national character varying(5 byte); --error

select '1234'::national char varying; --error
select '1234'::national char varying(5);
select '1234'::national char varying(5 char); --error
select '1234'::national char varying(5 byte); --error

select '1234'::nchar varying; --error
select '1234'::nchar varying(5);
select '1234'::nchar varying(5 char); --error
select '1234'::nchar varying(5 byte); --error

create table char_test (char_col nvarchar2(50));
insert into char_test values (N'一二三四');	
insert into char_test values (N'こんにちは');	
insert into char_test values (N'Hello World');	
insert into char_test values (N' ograc ');	
insert into char_test values (N'Hello!');	
insert into char_test values (N'');	
insert into char_test values (N'L1' || CHR(10) || N'L2');
select * from char_test;
drop table char_test;

create table char_test(char_col nchar(50));
insert into char_test values (N'一二三四');	
insert into char_test values (N'こんにちは');	
insert into char_test values (N'Hello World');	
insert into char_test values (N' ograc ');	
insert into char_test values (N'Hello!');	
insert into char_test values (N'');	
insert into char_test values (N'L1' || CHR(10) || N'L2');
drop table char_test;

create table t_national_character(c1 national character(5));
drop table t_national_character;
create table test_table(col1 national character(1));
drop table test_table;
create table test_table(col1 national character(10));
drop table test_table;
create table test_table(col1 national character(1000));
drop table test_table;
create table test_table (col1 national character varying(1));
drop table test_table;
create table test_table (col1 national character varying(10));
drop table test_table;
create table test_table (col1 national character varying(2000));
drop table test_table;
create table t_national_char(c1 national char(5));
drop table t_national_char;
create table test_table (col1 national char(1));
drop table test_table;
create table test_table (col1 national char(10));
drop table test_table;
create table test_table (col1 national char(1000));
drop table test_table;
create table t_national_character_varying(c1 national character varying(5));
drop table t_national_character_varying;
create table t_national_char_varying(c1 national char varying(5));
drop table t_national_char_varying;
create table test_table (col1 national char varying(1));
drop table test_table;
create table test_table (col1 national char varying(10));
drop table test_table;
create table test_table (col1 national char varying(2000));
drop table test_table;
create table t_nchar_varying(c1 nchar varying(5));
drop table t_nchar_varying;
create table test_tables(col1 nchar varying(1));
drop table test_tables;
create table test_tables(col1 nchar varying(10));
drop table test_tables;
create table test_tables(col1 nchar varying(1000));
drop table test_tables;

create table c_nclob_1(c1 nclob);
drop table c_nclob_1;

create table nclob_table(id number, nclob_col nclob);
insert into nclob_table(id, nclob_col) values (1, N'测试用的NCLOB数据'); -- NCLOB value in Chinese characters
select nclob_col from nclob_table WHERE id = 1;
drop table nclob_table;
