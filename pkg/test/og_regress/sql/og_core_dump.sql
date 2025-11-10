-- test out misuse of star * with function
---- test out normal functions, common path function path with no specified star eligibility
select abs(*);
select acos(*);
---- test out window function with star as parameter, expecting window reject star as any parameter, except count(*), prepare table for use
DROP TABLE IF EXISTS test_winsort_function_with_star_1;
DROP TABLE IF EXISTS test_winsort_function_with_star_2;
create table test_winsort_function_with_star_1 (a int);
create table test_winsort_function_with_star_2 (a int, b int);
insert into test_winsort_function_with_star_1 values(1), (2);
insert into test_winsort_function_with_star_2 values(1, 2), (2, 3);
------ test aggregate function (not windowed version) with star in parameter, expecting reject 
select sum(*) from test_winsort_function_with_star_1;
select sum(*) from test_winsort_function_with_star_2;
select COVAR_POP(*, a) from test_winsort_function_with_star_2;
select COVAR_POP(a, *) from test_winsort_function_with_star_2;
select min(*) from test_winsort_function_with_star_1;
select min(*) from test_winsort_function_with_star_2;
select stddev(*) from test_winsort_function_with_star_1;
select approx_count_distinct(*) from test_winsort_function_with_star_1;
select lnnvl(*) from test_winsort_function_with_star_2;
------ test aggregate function (windowed version) with star in parameter, expecting reject 
select sum(*) over() from test_winsort_function_with_star_1;
select sum(*) over() from test_winsort_function_with_star_2;
select sum(*) over(PARTITION BY a) from test_winsort_function_with_star_2;
select COVAR_POP(*, a) over() from test_winsort_function_with_star_2;
select COVAR_POP(*, a) over(PARTITION BY a) from test_winsort_function_with_star_2;
select COVAR_POP(*, a) over(PARTITION BY b) from test_winsort_function_with_star_2;
select min(*) over() from test_winsort_function_with_star_1;
select min(*) over(PARTITION BY a) from test_winsort_function_with_star_2;
select listagg(*, 'x') within group (order by b) from test_winsort_function_with_star_1;
select listagg(*, 'y') within group (order by b) from test_winsort_function_with_star_2;
select b, lag(*, 1) over(order by a) from test_winsort_function_with_star_2;
select b, lag(*, 1) over(PARTITION BY b order by a) from test_winsort_function_with_star_2;
select a, lag(*, 1) over(PARTITION BY b order by a) from test_winsort_function_with_star_2;
select ntile(*) over (ORDER BY a) FROM test_winsort_function_with_star_2;
select avg(*) over () from test_winsort_function_with_star_1;
select avg(*) over (PARTITION BY a) from test_winsort_function_with_star_1;
select avg(*) over (PARTITION BY a) from test_winsort_function_with_star_2;
select cume_dist(*, 1) within group (order by a) from test_winsort_function_with_star_1;
select stddev(*) over() from test_winsort_function_with_star_1;
select stddev(*) over() from test_winsort_function_with_star_2;
select dense_rank(*, 1) within group (order by a) FROM test_winsort_function_with_star_2;
-- accept count(*) use
select count(*) from test_winsort_function_with_star_1;
select count(*) over() from test_winsort_function_with_star_2;
select count(*) over(PARTITION BY a) from test_winsort_function_with_star_2;
DROP TABLE IF EXISTS test_winsort_function_with_star_1;
DROP TABLE IF EXISTS test_winsort_function_with_star_2;

drop table if exists test_part_for_1;
create table test_part_for_1 (id int, value int)
partition by range (id) (
    partition p1 values less than (100),
    partition p2 values less than (200),
    partition p3 values less than (300),
    partition p4 values less than (maxvalue)
);
select * from test_part_for_1 partition for (max(1));
select * from test_part_for_1 partition for (id);
select * from test_part_for_1 partition for (prior id);
select * from test_part_for_1 partition for (rownum);
select * from test_part_for_1 partition for (rowid);
select * from test_part_for_1 partition for (default);
select * from test_part_for_1 partition for (rowscn);
select * from test_part_for_1 partition for (rownodeid);
select * from test_part_for_1 partition for (maxvalue);
select * from test_part_for_1 partition for (cast(rowid as number));
select * from test_part_for_1 partition for (*);
select * from test_part_for_1 partition for (count(1) over());
select * from test_part_for_1 partition for ((select count(*) from test_part_for_1));
select * from test_part_for_1 partition for (1 + rownum);
select * from test_part_for_1 partition for (1 + 1);
drop table if exists test_part_for_1;