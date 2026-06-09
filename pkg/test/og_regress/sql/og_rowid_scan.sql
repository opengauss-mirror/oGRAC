alter system set use_bison_parser = true;
create table table1(a int, b int, c varchar(100));
create table table2(a int, b int, c varchar(100));

insert into table1 values(1,2,'123124');
insert into table1 values(1,2,'123124');
insert into table1 values(1,2,'123124');

insert into table2 values(1,2,'123124');
insert into table2 values(1,2,'123124');
insert into table2 values(1,2,'123124');
insert into table2 values(1,2,'123124');
insert into table2 values(1,2,'123124');


ANALYZE TABLE table1 COMPUTE STATISTICS;
ANALYZE TABLE table2 COMPUTE STATISTICS;

explain select * from table1, table2 where table2.rowid= table1.rowid;

explain select * from table1, table2 where table1.rowid= table2.rowid;

explain select * from table1,table2 where table1.rowid=21312;

explain select * from table1  where table1.rowid in ('000000000020680000', '000000000020680001');

explain select * from table1 where table1.rowid = '000000000020680000';

drop table table1;

drop table table2;

commit;
