alter system set use_bison_parser = true;

drop function if exists bison_pl_func;
drop function if exists bison_pl_refcur;
drop procedure if exists bison_pl_inout_proc;
drop procedure if exists bison_pl_out_proc;
drop procedure if exists bison_pl_noarg_proc;
drop procedure if exists bison_pl_proc;
drop trigger if exists bison_pl_stmt_trg;
drop trigger if exists bison_pl_trg;
drop package body if exists bison_pl_pkg;
drop package if exists bison_pl_pkg;
drop table if exists bison_pl_src;
drop table if exists bison_pl_type_t;
drop table if exists bison_pl_t;

create table bison_pl_t(id int, name varchar(32));
create table bison_pl_src(id int, name varchar(32));
create table bison_pl_type_t(type varchar(4), id int);
insert into bison_pl_src values(202, 'merge');
insert into bison_pl_type_t values('T', 1);

create or replace procedure bison_pl_proc(p_id in int) as
begin
    insert into bison_pl_t values(p_id, 'proc');
    return;
end;
/

create or replace procedure bison_pl_out_proc(p_id in int, p_out out int) as
begin
    p_out := p_id + 10;
end;
/

create or replace procedure bison_pl_inout_proc(p_value in out int) as
begin
    p_value := p_value + 1;
end;
/

create or replace procedure bison_pl_noarg_proc as
begin
    null;
end;
/

create or replace function bison_pl_func(p_id in int) return int as
begin
    return p_id + 1;
end;
/

create or replace function bison_pl_refcur return sys_refcursor as
    rc sys_refcursor;
begin
    open rc for select id, name from bison_pl_t;
    return rc;
end;
/

declare
    rc sys_refcursor;
begin
    rc := bison_pl_refcur;
    close rc;
end;
/

create or replace package bison_pl_pkg as
    procedure p(p_id in int);
end;
/

create or replace package body bison_pl_pkg as
    procedure p(p_id in int) as
    begin
        insert into bison_pl_t values(p_id, 'pkg');
    end;
end;
/

create or replace trigger bison_pl_trg
before insert on bison_pl_t
for each row
begin
    :new.name := 'trg';
end;
/

create or replace trigger bison_pl_stmt_trg
after update of name or delete on bison_pl_t
begin
    null;
end;
/

call bison_pl_proc(1);
exec bison_pl_proc(2);
execute bison_pl_proc(3);

begin
    execute immediate 'insert into bison_pl_t values(30, ''top dynamic'')';
end;
/

call bison_pl_pkg.p(7);

begin
    bison_pl_proc(4);
    bison_pl_proc(6);
end;
/

begin
    bison_pl_proc(4);
    execute immediate 'insert into bison_pl_t values(5, ''dynamic'')';
end;
/

begin
    bison_pl_noarg_proc;
end
/

declare
    v_id int := 0;
    v_required int not null := 1;
    v_name varchar(32);
    v_id_copy bison_pl_t.id%type;
    v_row bison_pl_t%rowtype;
    type rec_t is record(id int, name varchar(32));
    type rec_opt_t is record(id int not null := 1, name varchar(32) default 'opt');
    type refcur_t is ref cursor;
    type name_arr_t is varray(4) of varchar(32);
    type rec_tab_t is table of rec_t;
    v_rec rec_t;
    v_rec_opt rec_opt_t;
    v_names name_arr_t;
    v_recs rec_tab_t;
begin
    v_id := bison_pl_func(1);
    v_id_copy := v_id;
    v_row.id := v_id;
    v_row.name := 'rowtype';
    v_rec.id := v_id;
    v_rec.name := 'record';
    v_rec_opt.id := v_required;
    v_rec_opt.name := 'record default';
    v_name := 'using';
end;
/

declare
    v_diff interval day to second;
    v_precise interval day(2) to second(3);
    v_period interval year to month;
    v_period_precise interval year(2) to month;
begin
    null;
end;
/

--error
declare
    v_diff interval day to second;
begin
    DBMS_OUTPUT.PUT_LINE('interval');
end;
/

declare
    v_id int := 0;
    v_name varchar(32) := 'using';
    v_count int := 0;
    type id_tab_t is table of int index by binary_integer;
    v_ids id_tab_t;
begin
    execute immediate 'insert into bison_pl_t values(:1, :2)' using in v_id, in v_name;
    execute immediate 'call bison_pl_out_proc(:1, :2)' using in v_id, out v_count;
    execute immediate 'call bison_pl_inout_proc(:1)' using in out v_count;
    execute immediate 'select count(*) from bison_pl_t' into v_count;
    execute immediate 'select id from bison_pl_t' bulk collect into v_ids;
end;
/

declare
    type id_tab_t is table of int index by binary_integer;
    v_ids id_tab_t;
begin
    v_ids(1) := 301;
    v_ids(2) := 302;

    forall i in 1..2
        insert into bison_pl_t values(v_ids(i), 'forall');
end;
/

declare
    v_id int := 1;
    v_count int := 0;
begin
    select count(*) into v_count from bison_pl_t;
    with q as (select id from bison_pl_t) select count(*) into v_count from q;

    update bison_pl_t set name = 'updated' where id = v_id;
    delete from bison_pl_t where id = -1;
    insert into bison_pl_t values(201, 'insert');

    merge into bison_pl_t t
    using bison_pl_src s
    on (t.id = s.id)
    when matched then update set t.name = s.name
    when not matched then insert (id, name) values (s.id, s.name);
end;
/

declare
    v_count int := 0;
begin
    select count(*) into v_count from bison_pl_type_t where type = 'T';
end;
/

declare
    v_id int := 1;
    v_count int := 0;
begin
    declare
        v_nested int := 1;
    begin
        v_id := v_id + v_nested;
    end;

    if v_id > 0 then
        null;
    elsif v_id = 0 then
        null;
    else
        null;
    end if;

    case v_id
        when 1 then
            null;
        when 2 then
            null;
        else
            null;
    end case;

    case
        when v_id > 0 then
            null;
        else
            null;
    end case;

    <<goto_start>>
    null;
    goto goto_done;
    v_id := -100;
    <<goto_done>>
    null;

    <<block_label>>
    begin
        null;
    end block_label;

    loop
        exit;
    end loop;

    v_count := 0;
    loop
        v_count := v_count + 1;
        if v_count = 1 then
            continue;
        end if;
        exit;
    end loop;

    <<named_loop>>
    loop
        exit named_loop when v_id > 0;
    end loop named_loop;

    while v_count < 2 loop
        v_count := v_count + 1;
        continue when v_count < 2;
    end loop;

    <<while_loop>>
    while v_count < 3 loop
        v_count := v_count + 1;
    end loop while_loop;

    for i in 1..2 loop
        v_id := v_id + i;
    end loop;

    <<for_loop>>
    for i in 1..2 loop
        v_id := v_id + i;
    end loop for_loop;

    for i in reverse 1..2 loop
        v_id := v_id + i;
    end loop;
end;
/

drop table if exists bison_pl_for_shadow;
create table bison_pl_for_shadow(a int, b int, c varchar(20));

create or replace procedure bison_pl_for_shadow_proc(startnum int, endnum int) is
    i int := 99;
begin
    for i in startnum..endnum loop
        insert into bison_pl_for_shadow values(i, i % 10, 'x' || i);
    end loop;
end;
/

call bison_pl_for_shadow_proc(1, 5);
select * from bison_pl_for_shadow order by a;

drop procedure bison_pl_for_shadow_proc;
drop table if exists bison_pl_for_shadow;

declare
    v_id int := 0;
    v_name varchar(32);
    type id_tab_t is table of int index by binary_integer;
    v_ids id_tab_t;
    rc sys_refcursor;
    cursor c is select id, name from bison_pl_t;
    cursor c_ids is select id from bison_pl_t;
    cursor c_empty is select id, name from bison_pl_t;
    cursor c_arg(p_min in int default 0) is select id, name from bison_pl_t where id >= p_min;
    v_crow c%rowtype;
begin
    for r in (select id, name from bison_pl_t) loop
        v_id := r.id;
    end loop;

    for r in c_arg(0) loop
        v_name := r.name;
    end loop;

    for r in c_arg(coalesce(v_id, 0)) loop
        v_name := r.name;
    end loop;

    for r in c_empty loop
        v_name := r.name;
    end loop;

    open c;
    fetch c into v_crow;
    close c;

    open c;
    fetch c into v_id, v_name;
    close c;

    open c_ids;
    fetch c_ids bulk collect into v_ids limit 10;
    close c_ids;

    open c_empty;
    fetch c_empty into v_id, v_name;
    close c_empty;

    open c_arg(v_id);
    fetch c_arg into v_id, v_name;
    close c_arg;

    open c_arg(coalesce(v_id, 0));
    fetch c_arg into v_id, v_name;
    close c_arg;

    open rc for select id, name from bison_pl_t;
    close rc;

    open rc for 'select id, name from bison_pl_t where id = :1' using v_id;
    close rc;
end;
/

declare
    e_user exception;
begin
    begin
        raise e_user;
    exception
        when e_user then
            null;
        when others then
            raise;
    end;

    savepoint bison_pl_sp;
    rollback to savepoint bison_pl_sp;
    savepoint bison_pl_sp2;
    rollback to bison_pl_sp2;
    rollback;
    commit;
end;
/

drop table if exists bison_pl_insert_subq;
create table bison_pl_insert_subq(id int, total int);

declare
    v_id int := 500;
begin
    insert into bison_pl_insert_subq values(v_id, (select count(*) from bison_pl_t));
    insert into bison_pl_insert_subq(id, total)
        select v_id + 1, count(*) from bison_pl_t;
end;
/

drop table if exists bison_pl_insert_subq;

drop table if exists bison_pl_reload_div_t;
create table bison_pl_reload_div_t(a number);

create or replace procedure bison_pl_reload_div_proc as
    v_left number := 5;
    v_right number := 3;
    v_div number := 2;
begin
    insert into bison_pl_reload_div_t(a) values(round((v_left - v_right) / v_div * 100, 2));
end;
/

alter table bison_pl_reload_div_t add b number;

declare
begin
    bison_pl_reload_div_proc;
end;
/

select a from bison_pl_reload_div_t;

drop procedure bison_pl_reload_div_proc;
drop table if exists bison_pl_reload_div_t;

drop table if exists bison_pl_char_concat;
create table bison_pl_char_concat(stage varchar(40), val int, info varchar(100));

declare
    v varchar(100);
    c char(1);
    vc varchar(1);
begin
    c := 'w';
    vc := 'w';

    v := '';
    v := v || c;
    insert into bison_pl_char_concat values('varchar concat char', nvl(length(v), -1), substr(v, 1, 20));

    v := '';
    v := v || vc;
    insert into bison_pl_char_concat values('varchar concat varchar', nvl(length(v), -1), substr(v, 1, 20));
end;
/

select * from bison_pl_char_concat order by stage;

drop table if exists bison_pl_char_concat;

drop trigger if exists bison_pl_stmt_trg;
drop trigger if exists bison_pl_trg;
drop package body if exists bison_pl_pkg;
drop package if exists bison_pl_pkg;
drop function if exists bison_pl_func;
drop function if exists bison_pl_refcur;
drop procedure if exists bison_pl_inout_proc;
drop procedure if exists bison_pl_out_proc;
drop procedure if exists bison_pl_noarg_proc;
drop procedure if exists bison_pl_proc;
drop table if exists bison_pl_src;
drop table if exists bison_pl_type_t;
drop table if exists bison_pl_t;
