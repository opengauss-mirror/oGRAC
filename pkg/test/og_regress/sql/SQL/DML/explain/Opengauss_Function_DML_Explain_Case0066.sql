drop table if exists explain_param_num_nodes_0066;
            create table explain_param_num_nodes_0066(col1 int,col2 int);

insert into explain_param_num_nodes_0066 values(1,1),(2,2);

explain select * from explain_param_num_nodes_0066;

drop table explain_param_num_nodes_0066;
