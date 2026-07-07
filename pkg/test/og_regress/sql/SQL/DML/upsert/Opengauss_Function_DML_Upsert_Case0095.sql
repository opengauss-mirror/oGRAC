drop table if exists mykey_2e;
create table mykey_2e
(
   name nvarchar2(20) ,
   id number  ,
   address nvarchar2(50)
) ;
insert into mykey_2e values('dacong',2,'guangdong') on DUPLICATE KEY UPDATE  address='guangdong';
select * from mykey_2e;
alter table mykey_2e add constraint unique_id unique(id);
insert into mykey_2e values('wangyun',3,'chongqing');
select * from mykey_2e;
insert into mykey_2e values('lisa1',2,'yunnan') on DUPLICATE KEY UPDATE  name='lisa1',address='yunnan';
select * from mykey_2e;
drop table mykey_2e;
