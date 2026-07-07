drop table if exists mykey_4a;
create table mykey_4a
(
   name nvarchar2(20) unique ,
   id number primary key ,
   address nvarchar2(50)
) ;

insert into mykey_4a values('tiya',99,'daqing'),('tiya1',100,'beijing');
select * from mykey_4a;
 insert into mykey_4a values('tiya',99,'yunnan')on DUPLICATE KEY UPDATE address='yunnan';
 select * from mykey_4a;
 drop table mykey_4a;
