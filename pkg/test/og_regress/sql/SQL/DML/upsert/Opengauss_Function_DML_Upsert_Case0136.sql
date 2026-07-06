drop table if exists t_dml_upsert_0136;
create table t_dml_upsert_0136(a int, b int) partition by range (a)(
partition p1  values less than (10),
partition p2  values less than (maxvalue)
);

create unique index t_unique_key on t_dml_upsert_0136(b);

insert into t_dml_upsert_0136 values(1,1),(2,2),(11,11);
select * from t_dml_upsert_0136 partition(p1);
select * from t_dml_upsert_0136 partition(p2);

insert into t_dml_upsert_0136 values(2,2) on duplicate key update a = 15;
select * from t_dml_upsert_0136 partition(p1);
select * from t_dml_upsert_0136 partition(p2);

drop table t_dml_upsert_0136;
