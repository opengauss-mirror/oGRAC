---  subquery to table
alter system set _OPTIM_SUBQUERY_REWRITE=true;
alter system set _OPTIM_SEMI2INNER=true;
drop table if exists subquery_to_table_t1;
drop table if exists subquery_to_table_t2;
create table subquery_to_table_t1 (a int, b int, c int);
create table subquery_to_table_t2 (a int, b int, c int);
insert into subquery_to_table_t1 values(1, 2, 3);
insert into subquery_to_table_t1 values(2, 3, 4);
insert into subquery_to_table_t1 values(3, 4, 5);
insert into subquery_to_table_t2 values(3, 2, 1);
insert into subquery_to_table_t2 values(3, 5, 7);
insert into subquery_to_table_t2 values(5, 9, 7);
commit;
select * from subquery_to_table_t1 t1 where a in (select a from subquery_to_table_t2 limit 1);
drop table if exists subquery_to_table_t1;
drop table if exists subquery_to_table_t2;