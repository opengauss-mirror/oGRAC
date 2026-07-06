drop table if exists t_dml_explain_0074_1;
drop table if exists t_dml_explain_0074_2;
drop table if exists t_dml_explain_0074_3;
create table t_dml_explain_0074_1(id int,id1 int);
create table t_dml_explain_0074_2(id int,id1 int);
create table t_dml_explain_0074_3(id int,id1 int);

explain select m.* from ( select tz.* from (select t_dml_explain_0074_1.id from t_dml_explain_0074_1 WHERE exists (select t_dml_explain_0074_2.id from t_dml_explain_0074_2 where t_dml_explain_0074_2.id = t_dml_explain_0074_1.id and t_dml_explain_0074_2.id1 in (1,2,3,4,5,6,7,8,9,10,11))) tz limit 10) m
left join t_dml_explain_0074_3 on m.id = t_dml_explain_0074_3.id;

drop table t_dml_explain_0074_1;
drop table t_dml_explain_0074_2;
drop table t_dml_explain_0074_3;