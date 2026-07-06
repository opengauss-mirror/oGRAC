drop table if exists explain_partition_tab_list_0029;
            create table explain_partition_tab_list_0029(col1 int,col2 int)
            partition by list(col1)
            (
                partition p1 values (2000),
                partition p2 values (3000),
                partition p3 values (4000),
                partition p4 values (5000)
            );

insert into explain_partition_tab_list_0029 values(2000, 2000);

insert into explain_partition_tab_list_0029 values(3000, 3000);

alter table explain_partition_tab_list_0029 add partition p5
            values (6000);
            insert into  explain_partition_tab_list_0029 VALUES(6000, 6000);

explain select * from explain_partition_tab_list_0029;

drop table explain_partition_tab_list_0029;
