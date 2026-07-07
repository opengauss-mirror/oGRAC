drop table if exists mykey_2b;
create table mykey_2b
(
   name nvarchar2(20) unique,
   id number unique ,
   address nvarchar2(50)
) ;
insert into mykey_2b values ('dacong',2,'shandong'),('liuhua',3,'qingdao');
select * from mykey_2b;
insert into mykey_2b values('dacong',2,'guangdong'),('liuhua',3,'jilin') on DUPLICATE KEY UPDATE  address='guangdong';
select * from mykey_2b;
drop table mykey_2b;
