drop table if exists explain_param_nodes_0065;
            create table explain_param_nodes_0065(col1 int,col2 int);

insert into explain_param_nodes_0065 values(1,1),(2,2);

explain select * from explain_param_nodes_0065;

drop table explain_param_nodes_0065;
