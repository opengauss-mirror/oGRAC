drop table if exists mykey_0f;
create table mykey_0f
(
   name nvarchar2(20),
   id number unique ,
   address nvarchar2(50)
) ;
insert into mykey_0f values('bibly',null,'shenzhen');
select * from mykey_0f;
insert into mykey_0f(name,address) values('lihua1','shenzhen');
select * from mykey_0f;
drop table mykey_0f;
