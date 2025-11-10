drop table if exists sse_t1;
drop table if exists sse_t2;

create table sse_t1(a int, b int);
create table sse_t2(a int, b int);

--success case
select * from sse_t1
where  
 (
    (a) in (select a from sse_t2 where a > 1) and
    (a) in (select a from sse_t2 where a > 2)
 );

--error case
select * from sse_t1
where  
 (
    (a) in (select a from sse_t2 where a > 1)
    (a) in (select a from sse_t2 where a > 2)
 );

drop table if exists sse_t1;
drop table if exists sse_t2;

--test order by with nested aggregate functions
drop table if exists test_order_by_aggr;
create table test_order_by_aggr (id int);
insert into test_order_by_aggr values(1);
insert into test_order_by_aggr values(2);
select id from test_order_by_aggr group by id order by max(nvl2(nullif(3,id),3,id));
select id from test_order_by_aggr group by id order by max(id) + id;
select id from test_order_by_aggr group by id order by max(id), id;
drop table if exists test_order_by_aggr;

create table test_order_by_aggr (id INT, quantity INT, price DECIMAL(10,2), discount DECIMAL(10,2));
insert into test_order_by_aggr values (1, 5, 100, 10), (2, 8, 120, 5), (3, NULL, 150, NULL), (4, 0, 200, 0);
select id from test_order_by_aggr group by id order by avg(coalesce(round(nullif(id + quantity, 0), 2 ), id ));
select id from test_order_by_aggr group by id order by max(abs(id));
select id from test_order_by_aggr group by id order by sum(round(abs(id * 2), 0));
drop table if exists test_order_by_aggr;