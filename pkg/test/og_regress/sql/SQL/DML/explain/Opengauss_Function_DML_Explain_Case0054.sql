drop table if exists explain_param_nodes_0054;
            create table explain_param_nodes_0054(col1 int,col2 int);

insert into explain_param_nodes_0054 values(1,1),(2,2);

explain select * from explain_param_nodes_0054;

drop table explain_param_nodes_0054;
