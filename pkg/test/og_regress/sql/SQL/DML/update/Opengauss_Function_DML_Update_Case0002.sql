drop table if exists all_datatype_tbl;
create table all_datatype_tbl(c_integer integer, c_varchar varchar(50));
insert into all_datatype_tbl values(2,'aaaaa');
update all_datatype_tbl t1 set (c_integer,c_varchar) = (select distinct c1,c2 from (select c_integer c1,c_varchar c2 from all_datatype_tbl union select c_integer c1,c_varchar c2 from all_datatype_tbl where t1.c_integer=c_integer) where rownum=1);
drop table all_datatype_tbl;
