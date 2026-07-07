drop table if exists t_dml_upsert_0138;
create table t_dml_upsert_0138 (col1 int, col2 int)
partition by hash(col1)
(
partition p1,
partition p2
);


create unique index t_unique_key on t_dml_upsert_0138(col2);

insert into t_dml_upsert_0138 values(1,1),(2,2);
select * from t_dml_upsert_0138 partition(p1);
select * from t_dml_upsert_0138 partition(p2);

insert into t_dml_upsert_0138 values(2,2) on duplicate key update col1 = 3;
select * from t_dml_upsert_0138 partition(p1);
select * from t_dml_upsert_0138 partition(p2);

drop table t_dml_upsert_0138;
