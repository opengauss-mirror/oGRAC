drop table if exists explain_table_notin1_0015;
            create table explain_table_notin1_0015(name varchar(10),stu_id integer
            not null,score int );

drop table if exists explain_table_notin2_0015;
            create table explain_table_notin2_0015 (cname varchar(10),cid varchar(5)
            not null,num int,sname varchar(10));

insert into explain_table_notin1_0015 values('张三',1,50),('李四',2,55),
            ('王五',3,30);

insert into explain_table_notin2_0015 values('张三',1,50,'张三'),('李四',2,55,'李四'),('王五',3,30,'王五');

explain select * from explain_table_notin1_0015
            where name not in (select sname from explain_table_notin2_0015 where num >= 50)
            ;

drop table explain_table_notin1_0015;
            drop table explain_table_notin2_0015;
