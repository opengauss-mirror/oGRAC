drop table if exists mykey_0d;
create table mykey_0d
(
   name nvarchar2(20),
   id number unique ,
   address nvarchar2(50)
) ;
insert into mykey_0d values('lihua',1,'shenzhen'),('lihua1',2,'shenzhen');
select * from mykey_0d;
drop table mykey_0d;
