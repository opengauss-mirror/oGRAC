drop table if exists explain_view_0032;
            create table explain_view_0032(col1 int,col2 int);

insert into  explain_view_0032 values(1,1),(2,2);

create view select_view_0032 as select * from explain_view_0032;

explain select * from select_view_0032;

drop view select_view_0032;
            drop table explain_view_0032;
