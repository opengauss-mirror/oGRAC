drop table if exists explain_param_costs_0062;
            create table explain_param_costs_0062(col1 int,col2 int);

insert into explain_param_costs_0062 values(1,1),(2,2);

explain select * from explain_param_costs_0062;

drop table explain_param_costs_0062;
