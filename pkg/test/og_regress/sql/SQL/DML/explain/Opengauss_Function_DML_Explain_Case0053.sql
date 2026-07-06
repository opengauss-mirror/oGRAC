drop table if exists explain_param_detail_0053;
            create table explain_param_detail_0053(col1 int,col2 int);

insert into explain_param_detail_0053 values(1,1),(2,2);

explain update explain_param_detail_0053 set col1 = 5;

drop table explain_param_detail_0053;
