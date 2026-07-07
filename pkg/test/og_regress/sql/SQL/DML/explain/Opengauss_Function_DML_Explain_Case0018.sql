drop table if exists explain_table_func1_0018;
            create table explain_table_func1_0018 (name varchar(10),stu_id integer
            not null,score int );

insert into explain_table_func1_0018 values('张三',1,50),
            ('李四',2,55),('王五',3,30);

explain select count(*) from explain_table_func1_0018;

drop table explain_table_func1_0018;
