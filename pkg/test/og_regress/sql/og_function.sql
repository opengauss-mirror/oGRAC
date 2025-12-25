drop table if exists tbl_time_zone_1;

drop table if exists tbl_part_1;
drop table if exists tbl_part_2;
create table tbl_part_1(f1 int, f2 int);
insert into tbl_part_1 values (1,2),(3,4),(5,6),(7,8),(9,10);
create table tbl_part_2(f1 int, f2 int);
insert into tbl_part_1 values (1,2),(3,4),(5,6),(7,8),(9,10);
commit;
-- except error not in group list
select count(f1) + f1 from tbl_part_1;
select count(f1) + f2 from tbl_part_1;
select count(f1) + (select f1) from tbl_part_1;
select count(f1) + (select f2) from tbl_part_1;
select count(f1) + connect_by_root f1 from tbl_part_1 start with f1 = 3 connect by f1 = f2;
select count(f1) + connect_by_root (select f1) from tbl_part_1 start with f1 = 3 connect by f1 = f2;

-- select aggr + connect_by_root(subqry with group list column) excepted error more than one value
select count(f1) + connect_by_root (select f1 from tbl_part_1) from tbl_part_1 start with f1 = 3 connect by f1 = f2;
-- select aggr + connect_by_root(subqry without group list column) excepted success with null
select count(f1) + connect_by_root (select f1 from tbl_part_2) from tbl_part_1 start with f1 = 3 connect by f1 = f2;

-- select aggr + connect_by_root(subqry with group list column limit 1) excepted success
select count(f1) + connect_by_root (select f1 from tbl_part_1 limit 1) from tbl_part_1 start with f1 = 3 connect by f1 = f2;
-- select aggr + connect_by_root(subqry without group list column limit 1) excepted success
select count(f1) + connect_by_root (select f1 from tbl_part_1 limit 1) from tbl_part_1 start with f1 = 3 connect by f1 = f2;

-- select aggr + (subqry with group list column) excepted error more than one value
select count(t1.f1) + (select t1.f1 from tbl_part_1 t1) from tbl_part_1 t1;
-- select aggr + (subqry without group list column) excepted success with null
select count(t1.f1) + (select t2.f1 from tbl_part_2 t2) from tbl_part_1 t1;

-- except success
select count(f1) + connect_by_root 99 as c1 from tbl_part_1 start with f1 = 3 connect by f1 = f2;
select count(f1) + connect_by_root null as c1 from tbl_part_1 start with f1 = 3 connect by f1 = f2;
drop table if exists tbl_part_1;
drop table if exists tbl_part_2;

drop table if exists t_lag_1;

drop table if exists t_base_rank_1;
create table t_base_rank_1(id int,c_int int,c_vchar varchar(100),c_clob clob,c_blob blob,c_date date);
insert into t_base_rank_1 values(1,1000,'abc123',lpad('123abc',50,'abc'),lpad('11100011',50,'1100'),to_timestamp(to_char('2023-05-01 10:51:47'),'yyyy-mm-dd hh24:mi:ss'));
CREATE or replace procedure proc_insert(tname varchar,startall int,endall int) as
sqlst varchar(500);
BEGIN
  FOR i IN startall..endall LOOP
                sqlst := 'insert into ' || tname ||' select id+'||i||',c_int+'||i||',c_vchar||'||i||',c_clob||'||i||',c_blob'||',c_date from '||tname|| ' where id=1';
        execute immediate sqlst;
  END LOOP;
END;
/
exec proc_insert('t_base_rank_1',1,5000);
insert into t_base_rank_1 select * from t_base_rank_1;
commit;
create index idx_t_base_rank_1_1 on t_base_rank_1(id);
create index idx_t_base_rank_1_2 on t_base_rank_1(id,c_int);
create index idx_t_base_rank_1_3 on t_base_rank_1(upper(c_vchar));
analyze table t_base_rank_1 compute statistics;

---set autotrace on;
select sum(distinct c1), sum(distinct c2), sum(distinct c3) from
(select approx_count_distinct(id) c1, count(distinct c_vchar) c2, 
rank(444400) within group (order by id) c3 from t_base_rank_1 group by c_int) group by 1;

select sum(distinct c1), sum(distinct c2), sum(distinct c3) from
(select approx_count_distinct(id) c1, count(distinct c_vchar) c2, 
dense_rank(444400) within group (order by id) c3 from t_base_rank_1 group by c_int) group by 1;
---set autotrace off;
drop table if exists t_base_rank_1;