drop table if exists explain_param_verbose_0037;
            create table explain_param_verbose_0037(col1 int,col2 int);

insert into explain_param_verbose_0037 values(1,1),(2,2);

explain select * from  explain_param_verbose_0037;

drop table explain_param_verbose_0037;
