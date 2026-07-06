drop table if exists upsert1;
create table upsert1(id int primary key,age int,count int);
insert into upsert1 values (1,1,1),(4,4,4);
select * from upsert1 order by id;

insert into upsert1 values(1,2,3),(2,3,4) ON DUPLICATE key update age=2,count=3;
select * from upsert1 order by id;
delete from upsert1 ;
insert into upsert1 values (1,1,1),(4,4,4);

insert into upsert1 values(1,2,3),(2,3,4) on DUPLICATE key update age=3,count=4;
select * from upsert1 order by id;
drop table upsert1;
