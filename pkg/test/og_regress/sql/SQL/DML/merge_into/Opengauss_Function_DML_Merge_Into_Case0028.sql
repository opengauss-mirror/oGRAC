drop table if exists t_mergeinto_28_01;
drop table if exists t_mergeinto_28_02;
create table t_mergeinto_28_01(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_28_01 values (1501, 'vivitar 35mm', 'electrncs');
insert into t_mergeinto_28_01 values (1502, 'olympus is50', 'electrncs');
insert into t_mergeinto_28_01 values (1600, 'play gym', 'toys');
insert into t_mergeinto_28_01 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_28_01 values (1666, 'harry potter', 'dvd');
create table t_mergeinto_28_02(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_28_02 values (1502, 'olympus camera', 'electrncs');
insert into t_mergeinto_28_02 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_28_02 values (1666, 'harry potter', 'toys');
insert into t_mergeinto_28_02 values (1700, 'wait interface', 'books');
merge into t_mergeinto_28_01 t1  using t_mergeinto_28_02 t2
on (t1.product_name = t2.product_name)
when not matched then
  insert values (t2.product_id, t2.product_name, t2.category)
  where t2.category = 'books';
select * from t_mergeinto_28_01 order by product_id;
drop table t_mergeinto_28_01;
drop table t_mergeinto_28_02;
