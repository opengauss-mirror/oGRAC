drop table if exists t_dml_upsert_0137;
create table t_dml_upsert_0137(col1 int, col2 int)
partition by list(col1)
(
partition p1 values (2000),
partition p2 values (3000),
partition p3 values (4000),
partition p4 values (5000)
);

create unique index t_unique_key on t_dml_upsert_0137(col2);

insert into t_dml_upsert_0137 values(2000,2000),(3000,3000);
select * from t_dml_upsert_0137 partition(p1);
select * from t_dml_upsert_0137 partition(p2);
select * from t_dml_upsert_0137 partition(p4);

insert into t_dml_upsert_0137 values(2000,2000) on duplicate key update col1 = 5000;
select * from t_dml_upsert_0137 partition(p1);
select * from t_dml_upsert_0137 partition(p2);
select * from t_dml_upsert_0137 partition(p4);

drop table t_dml_upsert_0137;
