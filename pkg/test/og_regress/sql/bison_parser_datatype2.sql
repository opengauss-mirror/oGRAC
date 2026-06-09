show parameter use_bison_parser;
alter system set use_bison_parser = true;

create table test_table(v binary_double);
insert into test_table values(1.17549E-38F);
insert into test_table values(3.40282E+38F);
insert into test_table values(1.79E+308F);
insert into test_table values(1E+308F);
SELECT * FROM test_table;
drop table test_table;

create table test_table(v real);
insert into test_table values(1.17549E-38F);
insert into test_table values(3.40282E+38F);
insert into test_table values(1.79E+308F);
insert into test_table values(1E+308F);
SELECT * FROM test_table;
drop table test_table;

create table test_table(v number);
insert into test_table values(1.23f);
insert into test_table values(4.56d);
select * from test_table;
drop table test_table;

create table test_table(v decimal);
insert into test_table values(1.23f);
insert into test_table values(4.56d);
select * from test_table;
drop table test_table;

create table test_table(v float);
insert into test_table values(1.23f);
insert into test_table values(4.56d);
select * from test_table;
drop table test_table;

create table test_table(v real);
insert into test_table values(1.23f);
insert into test_table values(4.56d);
select * from test_table;
drop table test_table;

create table test_table(v double precision);
insert into test_table values(1.23f);
insert into test_table values(4.56d);
select * from test_table;
drop table test_table;

create table test_table(v binary_float);
insert into test_table values(1.17549E-38F);
insert into test_table values(3.40282E+38F);
select * from test_table;
drop table test_table;

create table test_table(v binary_double);
insert into test_table values(1.17549E-38F);
insert into test_table values(3.40282E+38F);
select * from test_table;
drop table test_table;

select 1.2;
select 1.2f;
select 1.2F;
select 1.2d;
select 1.2D;
select 1.23d, 1.24f;

select 1.79E+308;
select 1.79E+308f;
select 1.79E+308F;
select 1.79E+308d;
select 1.79E+308D;
select -1.79E+308;
select -1.79E+308f;
select -1.79E+308F;
select -1.79E+308d;
select -1.79E+308D;

select 1.79E+309; --error
select 1.79E+309f; --error
select 1.79E+309F; --error
select 1.79E+309d; --error
select 1.79E+309D; --error
select -1.79E+309; --error
select -1.79E+309f; --error
select -1.79E+309F; --error
select -1.79E+309d; --error
select -1.79E+309D; --error
select 1.2E3E4; --error
select -1.2E3E4; --error

create table testfd(id float);
insert into testfd values(1.2);
insert into testfd values(1.2f);
insert into testfd values(1.2F);
insert into testfd values(1.2d);
insert into testfd values(1.2D);
select * from testfd;

drop table if exists test2;
create table test2(id float default 1.23f, id1 float default 1.23, id2 int);
insert into test2(id2) values(1);
select * from test2;

select 1.17549E-38;
select 1.17549E-38F;
select 1.17549E-38f;
select 1.17549E-38D;
select 1.17549E-38d;

select 1.17549E+38;
select 1.17549E+38F;
select 1.17549E+38f;
select 1.17549E+38D;
select 1.17549E+38d;

select 1.23 + 2.4;
select 1.23f + 2.4d;
select 1.23d + 2.4d;
select 1.23f + 2.4f;
select 1.23d + 2.4f;

drop table if exists test1;
create table test1(id binary_double, id2 binary_float);
show create table test1;
insert into test1 values(1.79E+308, 1.79E+308);
insert into test1 values(-1.79E+308, -1.79E+308);
insert into test1 values(1.79E+309, 1.79E+309); --error
insert into test1 values(-1.79E+309, -1.79E+309); --error
insert into test1 values(1.79E+308f, 1.79E+308f);
insert into test1 values(1.79E+308F, 1.79E+308F);
insert into test1 values(1.79E+308d, 1.79E+308d);
insert into test1 values(1.79E+308D, 1.79E+308D);
insert into test1 values(1.79E+309f, 1.79E+309f); --error
insert into test1 values(1.79E+309F, 1.79E+309F); --error
insert into test1 values(1.79E+309d, 1.79E+309d); --error
insert into test1 values(1.79E+309D, 1.79E+309D); --error
select * from test1;
drop table test1;
drop table if exists bison_rowid_datatype_t;
create table bison_rowid_datatype_t(a rowid);
drop table if exists bison_rowid_datatype_t;
