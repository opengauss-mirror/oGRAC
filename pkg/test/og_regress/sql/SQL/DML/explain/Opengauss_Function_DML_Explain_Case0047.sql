drop table if exists explain_param_performance_0047;
            create table explain_param_performance_0047(col1 int,col2 int);

insert into explain_param_performance_0047 values(1,1),(2,2);

explain select * from explain_param_performance_0047;

drop table explain_param_performance_0047;
