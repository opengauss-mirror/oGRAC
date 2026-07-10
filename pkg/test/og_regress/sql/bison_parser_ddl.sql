alter system set use_bison_parser = true;

drop trigger if exists bison_ddl_trig_stmt;
drop trigger if exists bison_ddl_trig;
drop package body if exists bison_ddl_pkg_if;
drop package if exists bison_ddl_pkg_if;
drop package body if exists bison_ddl_pkg;
drop package if exists bison_ddl_pkg;
drop type if exists bison_ddl_type_arr force;
drop type if exists bison_ddl_type_tab force;
drop type if exists bison_ddl_type_force force;
drop type if exists bison_ddl_type force;
drop function if exists bison_ddl_func_if;
drop function if exists bison_ddl_func_args;
drop function if exists bison_ddl_func_empty_args;
drop function if exists bison_ddl_func;
drop procedure if exists bison_ddl_proc_if;
drop procedure if exists bison_ddl_proc_modes;
drop procedure if exists bison_ddl_proc_args;
drop procedure if exists bison_ddl_proc_empty_args;
drop procedure if exists bison_ddl_proc;
drop sequence if exists bison_ddl_seq_flags;
drop sequence if exists sys.bison_ddl_seq_schema;
drop sequence if exists bison_ddl_seq;
drop sequence if exists bison_ddl_seq_empty;
drop user if exists bison_ddl_user cascade;
drop user if exists bison_ddl_user cascade;
drop tenant if exists bison_ddl_tenant cascade;
drop table if exists bison_ddl_auto_tab;
drop table if exists bison_ddl_comp_tab;
drop table if exists bison_ddl_hash_tab;
drop table if exists bison_ddl_part_tab;
drop table if exists bison_ddl_tab_renamed;
drop table if exists bison_ddl_tab;
create table aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (id number);
drop table aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
create table aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (id number); --error
create table "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" (id number);
drop table "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
create table "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" (id number); --error

create or replace profile bison_ddl_profile limit sessions_per_user 1;
drop profile bison_ddl_profile;

create table bison_ddl_tab(id int, val int);
comment on table sys.bison_ddl_tab is 'bison table comment';
comment on column sys.bison_ddl_tab.id is 'bison id comment';
comment on column sys.bison_ddl_tab.id is '';

alter table bison_ddl_tab add column txt varchar(20) default 'x';
alter table bison_ddl_tab add (extra int, flag int default 0);
alter table bison_ddl_tab modify (extra bigint);
alter table bison_ddl_tab add constraint bison_ddl_ck check(id >= 0);
alter table bison_ddl_tab disable novalidate constraint bison_ddl_ck;
alter table bison_ddl_tab enable validate constraint bison_ddl_ck;
alter table bison_ddl_tab rename constraint bison_ddl_ck to bison_ddl_ck_new;
alter table bison_ddl_tab drop constraint bison_ddl_ck_new;
alter table bison_ddl_tab add constraint bison_ddl_uk unique(val);
alter table bison_ddl_tab drop constraint bison_ddl_uk cascade;
alter table bison_ddl_tab rename column val to value_col;
alter table bison_ddl_tab rename column value_col to val;
alter table bison_ddl_tab pctfree 20;
alter table bison_ddl_tab initrans 2;
alter table bison_ddl_tab storage (initial 64K next 64K maxsize 1M);
alter table bison_ddl_tab appendonly on;
alter table bison_ddl_tab appendonly off;
alter table bison_ddl_tab enable nologging;
alter table bison_ddl_tab disable nologging;
alter table bison_ddl_tab drop column flag;
alter table bison_ddl_tab drop extra;
alter table bison_ddl_tab rename to bison_ddl_tab_renamed;
alter table bison_ddl_tab_renamed rename to bison_ddl_tab;

create table bison_ddl_auto_tab(id bigint primary key auto_increment, val int);
alter table bison_ddl_auto_tab auto_increment = 10;
drop table if exists bison_ddl_auto_tab;

create table bison_ddl_part_tab(id int, val int)
partition by range(id) (
    partition p1 values less than (10),
    partition p2 values less than (20)
);

alter table bison_ddl_part_tab add partition p3 values less than (30);
alter table bison_ddl_part_tab modify partition p2 initrans 2;
alter table bison_ddl_part_tab modify partition p2 storage (initial 64K next 64K maxsize 1M);
alter table bison_ddl_part_tab enable row movement;
alter table bison_ddl_part_tab disable row movement;
alter table bison_ddl_part_tab enable partition p2 nologging;
alter table bison_ddl_part_tab disable partition p2 nologging;
alter table bison_ddl_part_tab truncate partition p1 reuse storage;
alter table bison_ddl_part_tab drop partition p3;
alter table bison_ddl_part_tab drop partition if exists p_not_exists;
alter table bison_ddl_part_tab split partition p2 at(15) into (partition p2a, partition p2b);
alter table bison_ddl_part_tab drop partition p2a;
drop table if exists bison_ddl_part_tab;

create table bison_ddl_hash_tab(id int, val int)
partition by hash(id) partitions 4;
alter table bison_ddl_hash_tab coalesce partition;
drop table if exists bison_ddl_hash_tab;

create table bison_ddl_comp_tab(id int, val int)
partition by hash(id) subpartition by hash(val)
(
    partition cp1 (
        subpartition cp11,
        subpartition cp12
    ),
    partition cp2 (
        subpartition cp21,
        subpartition cp22
    )
);

alter table bison_ddl_comp_tab enable subpartition cp21 nologging;
alter table bison_ddl_comp_tab disable subpartition cp21 nologging;
alter table bison_ddl_comp_tab truncate subpartition cp21 reuse storage;
alter table bison_ddl_comp_tab modify partition cp2 coalesce subpartition;
alter table bison_ddl_comp_tab modify partition cp2 add subpartition cp23;
drop table if exists bison_ddl_comp_tab;

create procedure bison_ddl_proc as
begin
    null;
end;
/

create procedure bison_ddl_proc_empty_args() as
begin
    null;
end;
/

create or replace procedure bison_ddl_proc_args(
    p_plain int,
    p_default int default 1,
    p_assign int := 2
) authid current_user is
begin
    null;
end;
/

create procedure bison_ddl_proc_modes(
    p_in in int,
    p_out out int,
    p_io in out int
) is
begin
    p_out := p_in;
    p_io := p_in;
end;
/

create procedure if not exists bison_ddl_proc_if as
begin
    null;
end;
/

create function bison_ddl_func return int as
begin
    return 1;
end;
/

create function bison_ddl_func_empty_args() return int is
begin
    return 1;
end;
/

create or replace function bison_ddl_func_args(
    p_plain int,
    p_default int default 1,
    p_assign int := 2
) return int is
begin
    return p_plain;
end;
/

create function if not exists bison_ddl_func_if return int as
begin
    return 1;
end;
/

create package bison_ddl_pkg as
    procedure p;
    function f return int;
end;
/

create package body bison_ddl_pkg as
    procedure p as
    begin
        null;
    end;

    function f return int as
    begin
        return 1;
    end;
end;
/

create or replace package bison_ddl_pkg as
    procedure p;
    function f return int;
end;
/

create or replace package body bison_ddl_pkg as
    procedure p as
    begin
        null;
    end;

    function f return int as
    begin
        return 1;
    end;
end;
/

create package if not exists bison_ddl_pkg_if as
    procedure p;
end;
/

create package body if not exists bison_ddl_pkg_if as
    procedure p as
    begin
        null;
    end;
end;
/

create type bison_ddl_type as object(id int);
/

create or replace type bison_ddl_type force as object(id int, val int);
/

create type if not exists bison_ddl_type_force force as object(id int, val int);
/

create type bison_ddl_type_tab is table of int;
/

create type bison_ddl_type_arr is varray(3) of bison_ddl_type_tab;
/

create trigger bison_ddl_trig
before insert on bison_ddl_tab
for each row
begin
    null;
end;
/

create or replace trigger bison_ddl_trig
before insert on bison_ddl_tab
for each row
begin
    null;
end;
/

create trigger if not exists bison_ddl_trig_stmt
after update on bison_ddl_tab
begin
    null;
end;
/

alter trigger bison_ddl_trig disable;
alter trigger bison_ddl_trig enable;
alter trigger bison_ddl_trig_stmt disable;
alter trigger bison_ddl_trig_stmt enable;
alter table bison_ddl_tab disable all triggers;
alter table bison_ddl_tab enable all triggers;

create sequence bison_ddl_seq_empty;
create sequence sys.bison_ddl_seq_schema;
alter sequence sys.bison_ddl_seq_schema restart;
create sequence bison_ddl_seq increment by 2 minvalue 1 maxvalue 100 start with 10 cache 20 cycle order;
alter sequence bison_ddl_seq increment by +3 minvalue 1 maxvalue 200 cache 10 nocycle noorder;
alter sequence bison_ddl_seq restart start with 50;
create sequence bison_ddl_seq_flags increment by -1 nominvalue nomaxvalue nocache nocycle noorder;
alter sequence bison_ddl_seq_flags restart;

create profile bison_ddl_profile limit
    sessions_per_user 10
    password_life_time 30
    password_reuse_time 10
    password_reuse_max 5
    password_min_len 8;
create or replace profile bison_ddl_profile limit
    failed_login_attempts default
    password_lock_time unlimited;
alter profile bison_ddl_profile limit
    failed_login_attempts 5
    password_grace_time default
    sessions_per_user unlimited;
drop profile bison_ddl_profile;

create user bison_ddl_user identified by 'Bison_ddl_123'
    password expire account unlock profile default permanent;
alter user bison_ddl_user identified by 'Bison_ddl_456';
alter user bison_ddl_user identified by 'Bison_ddl_789' replace 'Bison_ddl_456' account lock;
alter user bison_ddl_user account unlock password expire profile default;
alter system set use_bison_parser = false;
alter system set recyclebin = true;
alter system set use_bison_parser = true;
create table bison_ddl_user.purge_owner_tab(a int);
drop table bison_ddl_user.purge_owner_tab;
purge table bison_ddl_user.purge_owner_tab;
create table bison_ddl_user.purge_local_tab(a int);
alter session set current_schema = bison_ddl_user;
drop table purge_local_tab;
purge table purge_local_tab;
alter session set current_schema = sys;
-- ALTER TENANT requires environment-specific tablespaces, keep its bison syntax samples non-executed here.
create tenant bison_ddl_tenant tablespaces (bison_ddl_ts1) default tablespace bison_ddl_ts1;
alter tenant bison_ddl_tenant add tablespaces (bison_ddl_ts2);
alter tenant bison_ddl_tenant default tablespace bison_ddl_ts2;
drop tenant if exists bison_ddl_tenant cascade;

-- CREATE/DROP DATABASE and temporary tablespace syntax is environment-sensitive or unsupported.
-- Keep these samples here to cover the bison grammar paths without executing them in regress.
create database bison_ddl_db;
create database clustered bison_ddl_db;
drop database bison_ddl_db;
create temporary tablespace bison_ddl_temp_ts tempfile 'bison_ddl_temp_ts.dbf';

ALTER FUNCTION is unsupported by the native parser; bison keeps the same capability error.
alter function bison_ddl_func;

alter database set time_zone='+08:00';
alter database set time_zone='+00:00';
alter database enable_logic_replication on;
alter database enable_logic_replication off;

comment on table bison_ddl_issue268_missing is 'desc'; --error

drop table if exists bison_ddl_issue269_basic;
create table bison_ddl_issue269_basic(id number, name varchar2(50));
comment on column bison_ddl_issue269_basic.nonexistent_col is 'desc'; --error
drop table bison_ddl_issue269_basic;

drop trigger if exists bison_ddl_trig_stmt;
drop trigger if exists bison_ddl_trig;
drop type if exists bison_ddl_type_arr force;
drop type if exists bison_ddl_type_tab force;
drop type if exists bison_ddl_type_force force;
drop type if exists bison_ddl_type force;
drop package body if exists bison_ddl_pkg_if;
drop package if exists bison_ddl_pkg_if;
drop package body if exists bison_ddl_pkg;
drop package if exists bison_ddl_pkg;
drop function if exists bison_ddl_func_if;
drop function if exists bison_ddl_func_args;
drop function if exists bison_ddl_func_empty_args;
drop function if exists bison_ddl_func;
drop procedure if exists bison_ddl_proc_if;
drop procedure if exists bison_ddl_proc_modes;
drop procedure if exists bison_ddl_proc_args;
drop procedure if exists bison_ddl_proc_empty_args;
drop procedure if exists bison_ddl_proc;
drop sequence if exists bison_ddl_seq_flags;
drop sequence if exists sys.bison_ddl_seq_schema;
drop sequence if exists bison_ddl_seq;
drop sequence if exists bison_ddl_seq_empty;
drop user if exists bison_ddl_user cascade;
drop user if exists bison_ddl_user cascade;
drop tenant if exists bison_ddl_tenant cascade;
drop table if exists bison_ddl_auto_tab;
drop table if exists bison_ddl_comp_tab;
drop table if exists bison_ddl_hash_tab;
drop table if exists bison_ddl_part_tab;
drop table if exists bison_ddl_tab_renamed;
drop table if exists bison_ddl_tab;
