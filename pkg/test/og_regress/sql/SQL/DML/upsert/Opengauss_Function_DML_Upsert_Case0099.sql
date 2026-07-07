drop table if exists mykey_3f;
create table mykey_3f
(
   name nvarchar2(20) ,
   id number primary key ,
   address nvarchar2(50)
) ;
insert into mykey_3f values('lisa10',2,'yunnan'),('tom',2,'tianjin') on DUPLICATE KEY UPDATE name='lisa1',address='yunnan';
select * from mykey_3f;
drop table  mykey_3f;
