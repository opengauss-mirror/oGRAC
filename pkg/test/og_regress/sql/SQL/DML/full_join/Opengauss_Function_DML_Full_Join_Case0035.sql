drop table if exists t_join_0035_01;
drop table if exists t_join_0035_02;
drop table if exists t_join_0035_03;
drop table if exists t_join_0035_04;
create table t_join_0035_01(w_zip text);
create table t_join_0035_02(w_name varchar(20),w_tax int,w_street_2 varchar(50));
create table t_join_0035_03(d_id int);
create table t_join_0035_04(w_id int,w_ytd numeric(6,2));
insert into t_join_0035_01 values('pandas');
insert into t_join_0035_01 values('pandas1');
insert into t_join_0035_01 values('pandas2');
insert into t_join_0035_02 values('七仔', 1, 'pandas');
insert into t_join_0035_02 values('萌兰', 2, 'pandas');
insert into t_join_0035_02 values('花花', 3, 'pandas3');
insert into t_join_0035_02 values('乐乐', 4, 'pandas1');
insert into t_join_0035_02 values('丫丫', 5, 'pandas2');
insert into t_join_0035_02 values('美香', 6, 'pandas4');
insert into t_join_0035_02 values('小奇迹', 7, 'pandas5');
insert into t_join_0035_04 values(102,40.0);
insert into t_join_0035_04 values(29,3.1);

select
    *
from
    (
    select
        alias2.w_name alias6 ,
        alias2.w_tax alias7,
        mod(t_join_0035_04.w_id,
        t_join_0035_04.w_ytd + 10) alias8
    from
        t_join_0035_01 alias1
    full join t_join_0035_02 alias2 on
        alias1.w_zip = alias2.w_street_2,
        t_join_0035_04)alias9
full join t_join_0035_03 on
    alias9.alias7 != t_join_0035_03.d_id
where
    alias9.alias8 = 2
    or alias9.alias7 = 2
order by alias7, alias8, alias6;

drop table if exists t_join_0035_01;
drop table if exists t_join_0035_02;
drop table if exists t_join_0035_03;
drop table if exists t_join_0035_04;
