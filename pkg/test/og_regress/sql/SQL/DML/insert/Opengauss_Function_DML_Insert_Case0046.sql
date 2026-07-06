create table t_insert_0046_01(id int,name varchar(20),grade int);
insert into t_insert_0046_01 values(1,'jim',7),(2,'tom',8),(3,'cake',9);

create table t_insert_0046_02(stu_id int,subject varchar(20),score int);
insert into t_insert_0046_02 values(1,'math',78),(2,'math',83),(3,'physics',90);

select * from (select * from  t_insert_0046_01 where grade = 7) s left join (select * from t_insert_0046_02 where subject = 'math') t on s.id=t.stu_id;

select * from (select * from  t_insert_0046_01 where grade = 7) s left join (select * from t_insert_0046_02 where subject = 'math') t on s.id=t.stu_id union select * from (select * from  t_insert_0046_01 where grade = 7) s right join (select * from t_insert_0046_02 where subject = 'math') t on s.id=t.stu_id;

drop table t_insert_0046_01;
drop table t_insert_0046_02;
