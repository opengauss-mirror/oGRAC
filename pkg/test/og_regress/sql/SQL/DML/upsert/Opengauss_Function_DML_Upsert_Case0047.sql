drop table if exists upsert2;
create table upsert2(id int primary key,age int,count int);
insert into upsert2 values (1,1,1),(4,4,4);
select * from upsert2 order by id;

insert into upsert2 values(2,1,1),(3,4,4) ON DUPLICATE key update age=1,count=1;
select * from upsert2 order by id;
delete from upsert2;
insert into upsert2 values (1,1,1),(4,4,4);

insert into upsert2 values(2,1,1),(3,4,4) ON DUPLICATE key update age=4,count=4;
select * from upsert2 order by id;
drop table upsert2;
