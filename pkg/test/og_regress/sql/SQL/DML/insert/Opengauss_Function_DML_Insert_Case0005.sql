drop table if exists tbl_hash;
create table tbl_hash(
col_int int,
col_integer integer,
col_BINARY_INTEGER BINARY_INTEGER,
col_smallint smallint default '7',
col_bigint bigint not null default '3',
col_real real,
col_float float,
col_BINARY_DOUBLE BINARY_DOUBLE,
col_decimal decimal,
col_number1 number,
col_number2 number(38),
col_number5 number(38,7),
col_numeric numeric,
col_char1 char(100),
col_char2 char(8000),
col_nchar1 nchar(100),
col_nchar2 nchar(8000),
col_varchar_1 varchar(100),
col_varchar_2 varchar(8000) default 'aaaabbbb',
col_varchar2_1 varchar2(100) not null default 'aaaabbbb',
col_varchar2_2 varchar2(8000),
col_nvarchar2_1 nvarchar2(100),
col_nvarchar2_2 nvarchar2(8000),
col_clob clob,
col_text text,
col_binary1 varchar2(100),
col_binary2 varchar2(8000),
col_varbinary1 varchar2(100),
col_varbinary2 varchar2(8000),
col_raw1 raw(100),
col_raw2 raw(8000),
col_blob blob,
col_date date not null default '2018-01-07 08:08:08',
col_timestamp1 timestamp ,
col_timestamp2 timestamp(6),
col_bool bool,
col_boolean boolean,
col_interval1 INTERVAL YEAR TO MONTH,
col_interval2 INTERVAL DAY TO SECOND
);
drop index if exists idx_tbl_hash_5;
create unique index idx_tbl_hash_5 on tbl_hash(col_int,col_float,col_real,col_smallint);
insert into tbl_hash(col_int,col_float,col_smallint,col_real)
select 2,1.11111111,1.2222222,444444 from sys_dummy
union all select 1,1.11111111,1.2222222,444444 from sys_dummy
union all select 3,1.11111111,1.2222222,444444 from sys_dummy
union all select 4,1.11111111,1.2222222,444444 from sys_dummy
union all select 5,null,1.2222222,444444 from sys_dummy
union all select 6,null,1.2222222,444444 from sys_dummy
union all select 7,null,null,null from sys_dummy
union all select 8,null,null,null from sys_dummy
union all select 9,null,null,null from sys_dummy order by 1,2,3 nulls first;
select col_int,col_float,col_real,col_smallint from tbl_hash order by 1,2,3;
drop table if exists tbl_hash;
