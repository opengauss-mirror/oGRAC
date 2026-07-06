drop table if exists t_upsert_0135;
create table t_upsert_0135 (
    product_no integer primary key,
    name text,
    price numeric
);

insert into t_upsert_0135 values(110,'meat',22.5);

insert into t_upsert_0135 values(110,'orange',7.4) on DUPLICATE key update NAME='orange';
select * from t_upsert_0135;
insert into t_upsert_0135 values(889,'orange',7.4) on DUPLICATE key update name='orange';

drop table t_upsert_0135;
