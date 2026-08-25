drop table if exists og_xa_empty_interval_t;

create table og_xa_empty_interval_t(id int, value varchar(32)) partition by range(id) interval(1000) (partition p1 values less than (201), partition p2 values less than (401));

insert into og_xa_empty_interval_t values(1, 'seed');
commit;

-- Empty interval partition table scan must still start a write transaction.
update og_xa_empty_interval_t set value = 'table scan' where id = 1000001;
savepoint aa;
update og_xa_empty_interval_t set value = 'table scan again' where id = 1000001;
prepare transaction '35.AA08240000000001.000001';
commit prepared '35.AA08240000000001.000001';

create index og_xa_empty_interval_idx on og_xa_empty_interval_t(id);

-- Keep partition-key index metadata present, matching the production case.
update og_xa_empty_interval_t set value = 'index scan' where id = 2000001;
prepare transaction '35.AA08240000000002.000002';
commit prepared '35.AA08240000000002.000002';

delete from og_xa_empty_interval_t where id = 3000001;
prepare transaction '35.AA08240000000003.000003';
commit prepared '35.AA08240000000003.000003';

-- A read-only empty partition scan must not start a transaction.
select count(*) from og_xa_empty_interval_t where id = 4000001;
prepare transaction '35.AA08240000000004.000004';
rollback;

drop table og_xa_empty_interval_t;
