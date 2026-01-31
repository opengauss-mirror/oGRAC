/* index skip scan*/

drop table if exists test_idx1;
create table test_idx1(c1 int, c2 int, c3 int);
create index t_i1 on test_idx1(c1, c2, c3);

declare
   i int;
   begin
    insert into test_idx1 values(1,1,1);
    for i in 1..13 loop
	    insert into test_idx1 select 1000, dbe_random.get_value(1,10)*100000, dbe_random.get_value(1,10)*100000 from test_idx1;
	end loop;
end;
/

analyze table test_idx1 compute statistics;
alter system flush sqlpool;
alter system set cbo =on;

/* use index skip scan for the first column is not equal */
explain select * from test_idx1 where c1 > 100 and c2 = 100 and c3 > 100 and c3 < 100;
/* no use index skip scan */
explain select * from test_idx1 where c1 = 1000 and c2 = 100 and c3 > 100;
/* use index skip scan for lack of the first column */
explain select * from test_idx1 where c2 = 10 and c3 < 1000;

/* index fast full scan */
drop table if exists test_idx2;
create table test_idx2(c1 int, c2 int, c3 int);
create index t_i2 on test_idx2(c2, c3);
create index t_i3 on test_idx2(c1, c2, c3);

begin
    insert into test_idx2 values(1,1,1);
    for i in 10000..15000 loop
	    insert into test_idx2 values (i, i + 4, i + 10);
	end loop;
end;
/

analyze table test_idx2 compute statistics;
alter system flush sqlpool;
alter system set cbo =on;

/* no use fss */
explain select * from test_idx2 where c2 = 1000;
alter system flush sqlpool;
/* use fss */
explain select /*+index_ffs(test_idx2)*/ * from test_idx2 where c2 = 1000;

/* use fss */
explain select * from test_idx2 where c2 > 1000;
/* no use fss due to index_ffs cost not adapt to index order */
explain select * from test_idx2 where c2 > 1000 order by c1;
alter system flush sqlpool;
/* no use fss due to index_ffs cost not adapt to index order when index hint*/
explain select /*+index(test_idx2) */ * from test_idx2 where c2 > 1000 order by c1;
alter system flush sqlpool;
explain select /*+index_ffs(test_idx2) */ * from test_idx2 where c2 > 1000 order by c1;
/* no use fss due to no_index_ffs hint */
explain select /*+no_index_ffs(test_idx2) */* from test_idx2 where c2 > 1000;

/* use fss due to index_ffs cost is optimal */
explain select count(*) from test_idx2;