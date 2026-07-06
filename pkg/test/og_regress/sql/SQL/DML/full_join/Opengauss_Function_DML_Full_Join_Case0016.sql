drop table if exists all_datatype_table;
create table all_datatype_table(id int not null,c_intger integer,c_char char(10))
PARTITION BY RANGE (c_intger)
(
partition P_20180121 values less than (2018),
partition P_20190122 values less than (2019),
partition P_20200123 values less than (2020),
partition P_max values less than (2050)
);
insert into all_datatype_table values(1,1000,1000);
insert into all_datatype_table values(2,2000,1000);
insert into all_datatype_table values(3,2001,null);
insert into all_datatype_table values(4,2002,'a');
select * from all_datatype_table t1 right join all_datatype_table t2 on t1.id=t2.id where t1.id<10;
drop table if exists all_datatype_table;
