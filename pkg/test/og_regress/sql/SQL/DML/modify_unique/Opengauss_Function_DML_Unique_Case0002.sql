drop table if exists tab2;
create table tab2(
c_id int, c_integer integer,
c_real real,c_float float, c_cdouble binary_integer,
c_decimal decimal(38),c_decimal1 decimal,
c_number number(38),c_number1 number,c_number2 number(20,10),c_numeric numeric(38),
c_char char(50) default null, c_varchar varchar(20), c_varchar2 varchar2(4000),
c_clob clob,
c_raw raw(20),c_blob blob
);
alter table tab2  add constraint un2 unique (c_real);
drop table if exists tab2;
