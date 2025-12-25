-- test distinct + order by if_func core
drop table if exists t_order_by_if_func;
create table t_order_by_if_func(f1 int, f2 int, f3 int);
insert into t_order_by_if_func values (null, 4, 5),(8, 9, 10),(1, 2, 3);
commit;
select distinct f1, f2, f3 from t_order_by_if_func order by if(f1 is null, f2, f3);
select distinct f1, f2 from t_order_by_if_func order by f3; -- excepted error
drop table if exists t_order_by_if_func;

DROP TABLE IF EXISTS test_connect_by_root_1;
DROP TABLE IF EXISTS test_connect_by_root_2;
DROP TABLE IF EXISTS test_connect_by_root_3;
create table test_connect_by_root_1(id int);
create table test_connect_by_root_2(id int);
create table test_connect_by_root_3(conect_by_rootc1 int, c2 int);
insert into test_connect_by_root_1 values (1),(2),(3);
insert into test_connect_by_root_2 values (2),(3),(4);
insert into test_connect_by_root_3 values (1,1),(2,2),(2,2),(3,3);
commit;
select connect_by_root id, id from test_connect_by_root_1 connect by id > prior id order by 1,2;
select id, connect_by_root id from test_connect_by_root_1 connect by id > prior id order by 1,2;
select connect_by_root id, id from test_connect_by_root_1 connect by id > prior id
union all
select connect_by_root id, id from test_connect_by_root_1 connect by id > prior id order by 1,2;
select id, connect_by_root id from test_connect_by_root_1 connect by id > prior id
union all
select id, connect_by_root id from test_connect_by_root_1 connect by id > prior id order  by 1,2;
DROP TABLE IF EXISTS test_connect_by_root_1;
DROP TABLE IF EXISTS test_connect_by_root_2;
DROP TABLE IF EXISTS test_connect_by_root_3;