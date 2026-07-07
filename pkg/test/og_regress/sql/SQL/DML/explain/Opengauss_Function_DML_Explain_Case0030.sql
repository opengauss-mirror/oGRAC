drop table if exists explain_partition_tab_hash_0030;
            create table explain_partition_tab_hash_0030(col1 int,col2 int)
            partition by hash(col1)
            (
                partition p1,
                partition p2
            );

insert into explain_partition_tab_hash_0030 values(1,1),(2,2);

explain select * from explain_partition_tab_hash_0030;

drop table explain_partition_tab_hash_0030;
