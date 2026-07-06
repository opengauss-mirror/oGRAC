drop table if exists t_mergeinto_15_01;
drop table if exists t_mergeinto_15_02;
create table t_mergeinto_15_01(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_15_01 values (1501, 'vivitar 35mm', 'electrncs');
insert into t_mergeinto_15_01 values (1502, 'olympus is50', 'electrncs');
insert into t_mergeinto_15_01 values (1600, 'play gym', 'toys');
insert into t_mergeinto_15_01 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_15_01 values (1666, 'harry potter', 'dvd');
create table t_mergeinto_15_02(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_15_02 values (1502, 'olympus camera', 'electrncs');
insert into t_mergeinto_15_02 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_15_02 values (1666, 'harry potter', 'toys');
insert into t_mergeinto_15_02 values (1700, 'wait interface', 'books');
create view v_mergeinto_15 as select * from t_mergeinto_15_02;
merge into t_mergeinto_15_01  t1   using v_mergeinto_15
on (t1.product_id = v_mergeinto_15.product_id)
when matched then
  update set t1.product_name = v_mergeinto_15.product_name,
  t1.category = v_mergeinto_15.category  where t1.product_name != 'play gym'
when not matched then
  insert values (v_mergeinto_15.product_id, v_mergeinto_15.product_name,
  v_mergeinto_15.category)
   where v_mergeinto_15.category = 'books';
select * from t_mergeinto_15_01 order by product_id;
drop table t_mergeinto_15_01;
drop view v_mergeinto_15;
drop table t_mergeinto_15_02;
