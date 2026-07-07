drop table if exists explain_param_verbose_0061;
            create table explain_param_verbose_0061(col1 int,col2 int);

insert into explain_param_verbose_0061 values(1,1),(2,2);

explain select * from explain_param_verbose_0061;

drop table explain_param_verbose_0061;
