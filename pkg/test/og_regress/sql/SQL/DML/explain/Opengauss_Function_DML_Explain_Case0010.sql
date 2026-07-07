drop table if exists explain_table_leftjoin1_0010;
            create table explain_table_leftjoin1_0010
            (name varchar(10),stu_id integer not null, score int );

drop table if exists explain_table_leftjoin2_0010;
            create table explain_table_leftjoin2_0010
            (cname varchar(10),cid varchar(5) not null,
            num int ,sname varchar(10));

insert into explain_table_leftjoin1_0010 values('张三',1,50),
            ('李四',2,55),('王五',3,30);

insert into explain_table_leftjoin2_0010 values('数学','01',50,'张三'),
            ('语文','02',55,'李四'),('英语',3,30,'王五');

explain select * from explain_table_leftjoin1_0010 left
            join explain_table_leftjoin2_0010 on name = sname;

drop table explain_table_leftjoin1_0010;
            drop table explain_table_leftjoin2_0010;
