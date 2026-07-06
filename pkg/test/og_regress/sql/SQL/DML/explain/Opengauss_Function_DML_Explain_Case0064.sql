drop table if exists explain_param_detail_0064;
            create table explain_param_detail_0064(col1 int,col2 int);

insert into explain_param_detail_0064 values(1,1),(2,2);

explain select * from explain_param_detail_0064;

drop table explain_param_detail_0064;
