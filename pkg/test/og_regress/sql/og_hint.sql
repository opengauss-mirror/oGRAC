alter system set use_bison_parser = true;

create table hint_test1(a int, b int, c int);
create table hint_test2(a int, b int, c int);
create table hint_test3(a int, b int, c int);

begin
    insert into hint_test1 values(1,1,1);
    for i in 1000..2000 loop
	    insert into hint_test1 values (i, i + 4, i + 10);
	end loop;
end;
/
begin
    insert into hint_test2 values(1,1,1);
    for i in 1000..1100 loop
	    insert into hint_test2 values (i, i + 4, i + 10);
	end loop;
end;
/
begin
    insert into hint_test3 values(1,1,1);
    for i in 1000..1500 loop
	    insert into hint_test3 values (i, i + 4, i + 10);
	end loop;
end;
/

analyze table hint_test1 compute statistics;
analyze table hint_test2 compute statistics;
analyze table hint_test3 compute statistics;
create index t1_idx1 on hint_test1(b,c);
create index t1_idx2 on hint_test1(a,b,c);
explain select * from hint_test1 where a = 1000;
explain select /*+index(hint_test1 t1_idx1)*/* from hint_test1 where a = 1000;
explain select /*+full(hint_test1)*/* from hint_test1 where a = 1000;

alter system set use_bison_parser = false;