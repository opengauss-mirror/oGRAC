drop table if exists t_mergeinto_14_01;
drop table if exists t_mergeinto_14_02;
create table t_mergeinto_14_01(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_14_01 values (1501, 'vivitar 35mm', 'electrncs');
insert into t_mergeinto_14_01 values (1502, 'olympus is50', 'electrncs');
insert into t_mergeinto_14_01 values (1600, 'play gym', 'toys');
insert into t_mergeinto_14_01 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_14_01 values (1666, 'harry potter', 'dvd');
create table t_mergeinto_14_02(product_id integer,product_name varchar2(60),
category varchar2(60));
insert into t_mergeinto_14_02 values (1502, 'olympus camera', 'electrncs');
insert into t_mergeinto_14_02 values (1601, 'lamaze', 'toys');
insert into t_mergeinto_14_02 values (1666, 'harry potter', 'toys');
insert into t_mergeinto_14_02 values (1700, 'wait interface', 'books');
drop table if exists t_mergeinto_14_03;
create table t_mergeinto_14_03 as select * from t_mergeinto_14_01;
drop table if exists t_mergeinto_14_04;
create table t_mergeinto_14_04 as select * from t_mergeinto_14_02;
merge into t_mergeinto_14_03 t3   using t_mergeinto_14_04 t4
 on (t3.product_id = t4.product_id)
when matched then
  update set t3.product_name = t4.product_name, t3.category = t4.category
  where t3.product_name != 'play gym'
when not matched then
  insert values (t4.product_id, t4.product_name, t4.category)
  where t4.category = 'books';
select * from t_mergeinto_14_03 order by product_id;
drop table t_mergeinto_14_01;
drop table t_mergeinto_14_02;
drop table t_mergeinto_14_03;
drop table t_mergeinto_14_04;
