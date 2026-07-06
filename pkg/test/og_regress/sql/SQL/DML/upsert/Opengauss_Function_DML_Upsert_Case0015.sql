drop table if exists upsert1;
create table upsert1(id int primary key,age int,count int);
insert into upsert1 values (1,1,1),(4,4,4);
select * from upsert1;
insert into upsert1 values(1,2,3),(1,2,3) ON DUPLICATE key update  age=2,count=3;
drop table upsert1;
