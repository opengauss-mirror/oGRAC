alter system set use_bison_parser = true;

commit;
PREPARE TRANSACTION '1.A1B2C3';
COMMIT PREPARED '1.A1B2C3';
rollback;

SAVEPOINT bison_dcl_t1;
ROLLBACK TO bison_dcl_t1;
ROLLBACK TRANSACTION TO bison_dcl_t1;
ROLLBACK TO SAVEPOINT bison_dcl_t1;
ROLLBACK TRANSACTION TO SAVEPOINT bison_dcl_t1;
ROLLBACK PREPARED '1.A1B2C3';

RELEASE SAVEPOINT bison_dcl_t1;

SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL CURRENT COMMITTED;

-- Test BACKUP ARCHIVELOG statements
-- backup archivelog all;
-- backup archivelog all format 'bison_dcl_t1';
-- backup archivelog all as lz4 compressed backupset;
-- backup archivelog all as lz4 compressed backupset level 2;
-- backup archivelog all tag 'bison_dcl_t1';
-- backup archivelog all buffer size 128m;
-- backup archivelog from asn 23333 format 'bison_dcl_t1';

-- Test BACKUP DATABASE statements
-- backup database full exclude for tablespace bison_dcl_t2,bison_dcl_t1;
-- backup database full exclude for tablespace bison_dcl_t2,bison_dcl_t1,bison_dcl_t2;
-- backup database full skip badblock;
-- backup database full skip badblock skip badblock;
-- backup database INCREMENTAL LEVEL 2;
-- backup database INCREMENTAL LEVEL 1;
-- backup database FORMAT 'bison_dcl_t1';
-- backup database as lz4 compressed backupset;
-- backup database as lz4 compressed backupset level 2;
-- backup database tag 'bison_dcl_t1';
-- backup database PARALLELISM 9;
-- backup database SECTION THRESHOLD 134217728;
-- backup database SECTION THRESHOLD 256m;
-- backup database copy of tablespace bison_dcl_t1,bison_dcl_t2;
-- backup database PASSWORD 'Huawei@123';
-- backup database PREPARE;
-- backup database FINISH SCN 123124125412351;
-- backup database buffer size 128m;

-- backup cancel current process;

-- Test RESTORE DATABASE statements
-- restore database from 'bison_dcl_t1';
-- restore database from 'bison_dcl_t1' disconnect from session;
-- restore database from 'bison_dcl_t1' PARALLELISM 9;
-- restore database from 'bison_dcl_t1' tablespace bison_dcl_t1;
-- restore database from 'bison_dcl_t1' PASSWORD 'Huawei@123';
-- restore database from 'bison_dcl_t1' BUFFER SIZE 128m;
-- restore database from 'bison_dcl_t1' repair type RETURN_ERROR;
-- restore database from 'bison_dcl_t1' repair type REPLACE_CHECKSUM;
-- restore database from 'bison_dcl_t1' repair type DISCARD_BADBLOCK;

-- Test RESTORE BLOCKRECOVER statements
-- restore blockrecover datafile 1 page 100 from 'bison_dcl_t1';
-- restore blockrecover datafile 1 page 100 from 'bison_dcl_t1' until lfn 123124125412351;

-- Test RESTORE FILE/ARCHIVELOG statements
-- restore filerecover filename 'bison_dcl_t1' from 'bison_dcl_t1';
-- restore filerecover fileid 1000 from 'bison_dcl_t1';
-- restore filerecover filename 'bison_dcl_t1' from 'bison_dcl_t1' BUFFER SIZE 128m;
-- restore filerecover fileid 1000 from 'bison_dcl_t1' BUFFER SIZE 128m;
-- restore archivelog from 'bison_dcl_t1';
-- restore archivelog from 'bison_dcl_t1' BUFFER SIZE 128m;
-- restore FLUSHPAGE from 'bison_dcl_t1';
-- restore COPYCTRL to 'bison_dcl_t1';

-- Test RECOVER statements
-- recover database;
-- recover database until time '2023-01-01 00:00:00';
-- recover database until scn 1234567890;
-- recover database until cancel;

-- Test OGRAC statements
-- ograc recover 1 start 0 count 1;
-- ograc recover 0 start 0 count 1;

-- Test SHUTDOWN statements
-- shutdown;
-- shutdown immediate;
-- shutdown abort;

-- Test BUILD statements
-- build database;
-- build cascaded standby database;
-- build standby database;
-- build repair database;

-- Test SYNCPOINT statements
-- syncpoint reset;
-- syncpoint my_syncpoint;
-- syncpoint reset;

-- Test REPAIR statements
-- repair_page;
-- repair_copyctrl;

-- Test LOCK TABLE statements
drop table if exists bison_lock_t1;
drop table if exists bison_lock_t2;
create table bison_lock_t1(id int);
create table bison_lock_t2(id int);
lock table bison_lock_t1 in share mode;
lock table bison_lock_t1 in  exclusive mode;
lock table bison_lock_t1, bison_lock_t2 in share mode;
lock table bison_lock_t1 in share mode nowait;
-- lock table bison_lock_t1 in exclusive mode wait 10;
commit;
drop table if exists bison_lock_t1;
drop table if exists bison_lock_t2;

-- Test VALIDATE statements
validate datafile 1 page 100;
validate backupset 1;

-- Test ALTER SYSTEM statements
alter system set use_bison_parser = 'true';
-- alter system set use_bison_parser = 'true' scope = both;
-- alter system switch logfile;
-- alter system checkpoint;
-- alter system checkpoint global;
-- alter system checkpoint local;
-- alter system flush buffer;
-- alter system flush sqlpool;
alter system kill session '123,456';
alter system reset statistics;
alter system reload hba config;
-- alter system reload pbl config;
alter system refresh sysdba privilege;
alter system set replication on 'value';
-- alter system set replication off;
alter system load dictionary for appuser.apptable;
alter system init dictionary;
-- alter system recycle sharedpool;
-- alter system recycle sharedpool force;
-- alter system dump datafile 1 page 100;
alter system dump datafile 1 page 100 to '/path/to/file';
-- alter system dump ctrlfile;
alter system dump ctrlfile to '/path/to/file';
alter system dump catalog table appuser.apptable to '/path/to/file';
alter system dump catalog user username to '/path/to/file';
alter system archive_set param = 'value' global;
alter system archive_set replication on 'arch_dest';
-- alter system archive_set replication off;
alter system add lsnr_addr 'address';
alter system delete lsnr_addr 'address';
alter system add hba entry 'hba_entry_value';
alter system delete hba entry 'hba_entry_value';
alter system debug mode param = 'value';
alter system debug mode param = normal;
-- alter system stop build;
alter system repair catalog;

-- Test ALTER SESSION statements
alter session set nls_date_format = 'YYYY-MM-DD';
alter session set commit_wait = wait;
alter session set commit_logging = immediate;
alter session set lock_wait_timeout = 10;
alter session set current_schema = sys;
alter session set time_zone = '+08:00';
alter session set _show_explain_predicate = true;
alter session set shd_socket_timeout = 30;
alter session set tenant = tenant1;
alter session set _outer_join_optimization = on;
alter session set cbo_index_caching = 80;
alter session set cbo_index_cost_adj = 100;
alter session set _withas_subquery = optimizer;
alter session set _cursor_sharing = off;
alter session set plan_display_format = basic;
alter session set nls_timestamp_format = 'YYYY-MM-DD HH24:MI:SS';
alter session disable triggers;
alter session disable interactive timeout;
alter session disable nologging;
alter session disable optinfo_log;
alter session enable triggers;
alter session enable interactive timeout;
alter session enable nologging;
alter session enable optinfo_log;

alter system set use_bison_parser = false;
