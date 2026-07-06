drop table if exists explain_temp_tab1_0031;
drop table if exists explain_temp_tab2_0031;
create table explain_temp_tab1_0031 (col1 int,col2 int);
insert into explain_temp_tab1_0031 values(1,1),(2,2);
create table explain_temp_tab2_0031 as select * from explain_temp_tab1_0031;
explain select * from explain_temp_tab2_0031;
drop table explain_temp_tab2_0031;
drop table explain_temp_tab1_0031;