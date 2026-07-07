drop table if exists explain_table_func1_0020;
            create table explain_table_func1_0020 (name varchar(10),stu_id integer
            not null,score int );

insert into explain_table_func1_0020 values('张三',1,50),
            ('李四',2,55),('王五',3,30);

explain select left
            ((select name from explain_table_func1_0020 where score = 30),1);

drop table explain_table_func1_0020;
