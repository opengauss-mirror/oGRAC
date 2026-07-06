drop table if exists explain_param_plan_0069;
            create table explain_param_plan_0069(col1 int,col2 int);

insert into explain_param_plan_0069 values(1,1),(2,2);

explain select * from explain_param_plan_0069;

drop table explain_param_plan_0069;
