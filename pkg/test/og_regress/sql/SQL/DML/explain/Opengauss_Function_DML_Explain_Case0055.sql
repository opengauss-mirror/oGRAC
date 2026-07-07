drop table if exists explain_param_num_nodes_0055;
            create table explain_param_num_nodes_0055(col1 int,col2 int);

insert into explain_param_num_nodes_0055 values(1,1),(2,2);

explain select * from explain_param_num_nodes_0055;

drop table explain_param_num_nodes_0055;
