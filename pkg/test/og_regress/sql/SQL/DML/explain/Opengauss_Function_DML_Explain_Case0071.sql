drop table if exists explain_tab_not_exists1_0071;
            create table explain_tab_not_exists1_0071 (name varchar(10),stu_id
            integer not null,score int );

drop table if exists explain_tab_not_exists2_0071;
            create table explain_tab_not_exists2_0071
            (cname varchar(10),cid varchar(5) not null,num int,
            sname varchar(10));

insert into explain_tab_not_exists2_0071 values('张三',1,50,'张三'),('李四',2,55,'李四'),('王五',3,30,'王五');

insert into explain_tab_not_exists2_0071 values('数学','01',50,'张三'),
            ('语文','02',55,'李四'),('英语',3,30,'王五'),('物理',4,50,'杨六');

explain select * from explain_tab_not_exists1_0071
            where not exists (select sname from explain_tab_not_exists2_0071
            where num >= 50);

drop table explain_tab_not_exists1_0071;
            drop table explain_tab_not_exists2_0071;
