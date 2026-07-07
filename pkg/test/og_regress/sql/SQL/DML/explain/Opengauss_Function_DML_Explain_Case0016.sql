drop table if exists explain_table_exists1_0016;
            create table explain_table_exists1_0016
            (name varchar(10),stu_id integer not null,score int );

drop table if exists explain_table_exists2_0016;
            create table explain_table_exists2_0016(cname varchar(10),cid varchar(5)
            not null,num int,sname varchar(10));

insert into explain_table_exists1_0016 values('张三',1,50),
            ('李四',2,55),('王五',3,30);

insert into explain_table_exists2_0016 values('数学','01',50,'张三'),
            ('语文','02',55,'李四'),('英语',3,30,'王五');

explain select * from explain_table_exists1_0016
            where exists (select sname from explain_table_exists2_0016 where num >= 50);

drop table explain_table_exists1_0016;
            drop table explain_table_exists2_0016;
