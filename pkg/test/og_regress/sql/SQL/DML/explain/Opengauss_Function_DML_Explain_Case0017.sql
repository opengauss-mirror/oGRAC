drop table if exists explain_table_func1_0017;
            create table explain_table_func1_0017 (name varchar(10),stu_id integer
            not null,score int );

insert into explain_table_func1_0017 values('张三',1,50),
            ('李四',2,55),('王五',3,30);

explain select max(score) from explain_table_func1_0017;

drop table explain_table_func1_0017;
