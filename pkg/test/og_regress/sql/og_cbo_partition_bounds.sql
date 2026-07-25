-- Keep statistics absent and scan 65 composite LIST partitions to cover the CBO sampling bound.
declare
    ddl_sql varchar2(32767) := 'create table cbo_part_bound_t (id integer, sub_id integer) partition by list(id) subpartition by list(sub_id) (';
begin
    for i in 0..64 loop
        if i > 0 then
            ddl_sql := ddl_sql || ',';
        end if;
        ddl_sql := ddl_sql || 'partition p' || i || ' values (' || i || ') (subpartition sp' || i || ' values (' || i || '))';
    end loop;
    execute immediate ddl_sql || ')';
end;
/

declare
begin
    for i in 0..64 loop
        insert into cbo_part_bound_t values(i, i);
    end loop;
    commit;
end;
/

select id, rank(4) within group (order by id) as "rank"
from cbo_part_bound_t
group by id
order by id;

drop table cbo_part_bound_t;
