drop table if exists explain_param_plan_0045;
            create table explain_param_plan_0045(col1 int,col2 int);

insert into explain_param_plan_0045 values(1,1),(2,2);

explain update explain_param_plan_0045 set col1 = 5;

drop table explain_param_plan_0045;
