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

drop table if exists bison_pl_sql_found_t;
drop table if exists bison_pl_sql_found_log;
create table bison_pl_sql_found_t(id int);
create table bison_pl_sql_found_log(stage varchar(30), val int);
insert into bison_pl_sql_found_t values(1);

create or replace procedure bison_pl_sql_isopen_proc(p_id int) is
begin
    delete from bison_pl_sql_found_t where id = p_id;
    if SQL%ISOPEN then
        insert into bison_pl_sql_found_log values('sql_isopen', 1);
    else
        insert into bison_pl_sql_found_log values('sql_isopen', 0);
    end if;
end;
/

create or replace procedure bison_pl_sql_found_proc(p_id int) is
begin
    delete from bison_pl_sql_found_t where id = p_id;
    if SQL%FOUND then
        insert into bison_pl_sql_found_log values('sql_found', 1);
    else
        insert into bison_pl_sql_found_log values('sql_found', 0);
    end if;
end;
/

declare
begin
    bison_pl_sql_isopen_proc(99);
    bison_pl_sql_found_proc(1);
end;
/

select stage, val from bison_pl_sql_found_log order by stage;

drop procedure bison_pl_sql_found_proc;
drop procedure bison_pl_sql_isopen_proc;
drop table if exists bison_pl_sql_found_log;
drop table if exists bison_pl_sql_found_t;

drop table if exists bison_pl_cursor_attr_t;
drop table if exists bison_pl_cursor_attr_log;
create table bison_pl_cursor_attr_t(id int, note varchar(20));
create table bison_pl_cursor_attr_log(stage varchar(30), val int);
insert into bison_pl_cursor_attr_t values(1, 'one');
insert into bison_pl_cursor_attr_t values(2, 'two');

create or replace procedure bison_pl_sql_notfound_proc(p_id int) is
begin
    update bison_pl_cursor_attr_t set note = note where id = p_id;
    if SQL%NOTFOUND then
        insert into bison_pl_cursor_attr_log values('sql_notfound', 1);
    else
        insert into bison_pl_cursor_attr_log values('sql_notfound', 0);
    end if;
end;
/

declare
begin
    bison_pl_sql_notfound_proc(9);
end;
/

declare
    v_count int;
begin
    update bison_pl_cursor_attr_t set note = note where id = 1;
    v_count := SQL%ROWCOUNT;
    insert into bison_pl_cursor_attr_log values('sql_rowcount', v_count);
end;
/

declare
    cursor c1 is select id from bison_pl_cursor_attr_t order by id;
    v_id int;
    v_count int;
begin
    open c1;
    if c1%ISOPEN then
        insert into bison_pl_cursor_attr_log values('cursor_isopen', 1);
    end if;
    fetch c1 into v_id;
    if c1%FOUND then
        insert into bison_pl_cursor_attr_log values('cursor_found', v_id);
    end if;
    v_count := c1%ROWCOUNT;
    insert into bison_pl_cursor_attr_log values('cursor_rowcount', v_count);
    loop
        fetch c1 into v_id;
        exit when c1%NOTFOUND;
    end loop;
    insert into bison_pl_cursor_attr_log values('cursor_notfound', 1);
    close c1;
end;
/

declare
    rc sys_refcursor;
    v_id int;
begin
    open rc for select id from bison_pl_cursor_attr_t order by id;
    loop
        fetch rc into v_id;
        exit when rc%NOTFOUND;
    end loop;
    insert into bison_pl_cursor_attr_log values('refcursor_notfound', 1);
    close rc;
end;
/

create or replace procedure bison_pl_auto_proc is
    pragma autonomous_transaction;
begin
    insert into bison_pl_cursor_attr_log values('pragma_auto', 1);
    commit;
end;
/

declare
begin
    bison_pl_auto_proc;
end;
/

create or replace procedure bison_pl_exception_init_proc is
    snapshot_too_old exception;
    v_part varchar(130);
    pragma exception_init(snapshot_too_old, 715);
begin
    v_part := 'pragma_exception_init';
    insert into bison_pl_cursor_attr_log values(v_part, 1);
end;
/

begin
    bison_pl_exception_init_proc;
end;
/

drop table if exists bison_pl_cursor_loop_t;
create table bison_pl_cursor_loop_t(owner varchar(20), table_name varchar(20), partition_name varchar(20));
insert into bison_pl_cursor_loop_t values('USR', 'TAB', 'P1');

create or replace procedure bison_pl_cursor_assign_proc is
    v_table varchar(130);
    v_part varchar(130);
    v_owner varchar(130);
begin
    for item in (select owner, table_name, partition_name from bison_pl_cursor_loop_t) loop
        v_table := '"'||ITEM.TABLE_NAME||'"';
        v_part  := '"'||ITEM.PARTITION_NAME||'"';
        v_owner := '"'||ITEM.OWNER||'"';
        if v_table = '"TAB"' and v_part = '"P1"' and v_owner = '"USR"' then
            insert into bison_pl_cursor_attr_log values('cursor_for_assign', 1);
        end if;
    end loop;
end;
/

begin
    bison_pl_cursor_assign_proc;
end;
/

select stage, val from bison_pl_cursor_attr_log order by stage;

drop procedure bison_pl_cursor_assign_proc;
drop procedure bison_pl_exception_init_proc;
drop procedure bison_pl_auto_proc;
drop procedure bison_pl_sql_notfound_proc;
drop table if exists bison_pl_cursor_loop_t;
drop table if exists bison_pl_cursor_attr_log;
drop table if exists bison_pl_cursor_attr_t;

drop table if exists bison_pl_trig_event_log;
drop table if exists bison_pl_trig_event_t;
create table bison_pl_trig_event_t(id int, status varchar(10));
create table bison_pl_trig_event_log(event_name varchar(10));
insert into bison_pl_trig_event_t values(1, 'old');

create or replace trigger bison_pl_trig_event_trg
after insert or update or delete on bison_pl_trig_event_t
for each row
begin
    case
        when inserting then
            insert into bison_pl_trig_event_log values('insert');
        when updating then
            insert into bison_pl_trig_event_log values('update');
        when deleting then
            insert into bison_pl_trig_event_log values('delete');
        else
            insert into bison_pl_trig_event_log values('other');
    end case;
end;
/

insert into bison_pl_trig_event_t values(2, 'new');
update bison_pl_trig_event_t set status = 'new' where id = 1;
delete from bison_pl_trig_event_t where id = 2;
select event_name, count(*) as cnt from bison_pl_trig_event_log group by event_name order by event_name;
select count(*) as updated_rows from bison_pl_trig_event_t where status = 'new';

drop trigger bison_pl_trig_event_trg;
drop table if exists bison_pl_trig_event_log;
drop table if exists bison_pl_trig_event_t;
declare
    res varchar2(100);
begin
--  res := dbms_debug.initialize();
exception
    when others then
        null;
end;
/

declare
    res varchar2(100);
begin
    null;
exception
    when others then
        res := 'handled';
end;
/

drop table if exists bison_pl_issue245_log;
create table bison_pl_issue245_log(name varchar(40), val int);

declare
    n PLS_INTEGER := 1;
begin
    insert into bison_pl_issue245_log values('pls_integer', n);
end;
/

drop table if exists bison_pls_integer_name_t;
create table bison_pls_integer_name_t(pls_integer int);
insert into bison_pls_integer_name_t values(7);
update bison_pls_integer_name_t set pls_integer = pls_integer where pls_integer = 7;
drop table bison_pls_integer_name_t;

declare
    first integer := 1;
    last integer := 3;
    high integer := 10;
    low integer := 5;
begin
    for k in reverse first..last loop
        null;
    end loop;
    for step in 0..(trunc(high / low) * 2) loop
        null;
    end loop;
    first := last;
    insert into bison_pl_issue245_log values('keyword_bounds', first);
end;
/

declare
    type bison_arr is varray(4) of varchar2(10);
    team bison_arr := bison_arr();
begin
    if team.count = 0 then
        insert into bison_pl_issue245_log values('empty_constructor', 0);
    end if;
end;
/

declare
    type roster is table of varchar2(15);
    names roster := roster('A', 'B');
    v varchar2(15);
begin
    for i in names.first .. names.last loop
        v := names(i);
    end loop;
    insert into bison_pl_issue245_log values('collection_bounds', names.count);
end;
/

drop function if exists bison_pl_issue245_return_type;
drop function if exists bison_pl_issue245_body_type;
drop table if exists bison_pl_issue245_type_t;
create table bison_pl_issue245_type_t(id int, note varchar2(20));
insert into bison_pl_issue245_type_t values(1, 'one');

create or replace function bison_pl_issue245_return_type(p_id int)
return bison_pl_issue245_type_t.id%TYPE
is
begin
    return p_id;
end;
/
select bison_pl_issue245_return_type(1) as return_type_result from sys_dummy;

create or replace function bison_pl_issue245_body_type(p_id int)
return int
is
    v_id bison_pl_issue245_type_t.id%TYPE;
    r bison_pl_issue245_type_t%ROWTYPE;
begin
    select * into r from bison_pl_issue245_type_t where id = p_id;
    v_id := r.id;
    return v_id;
end;
/
select bison_pl_issue245_body_type(1) as body_type_result from sys_dummy;

drop function bison_pl_issue245_return_type;
drop function bison_pl_issue245_body_type;
drop table bison_pl_issue245_type_t;

select name, val from bison_pl_issue245_log order by name;

drop table if exists bison_pl_issue245_log;

drop function if exists sys.bison_pl_issue259_func_end3;
create or replace function sys.bison_pl_issue259_func_end3 return number is
begin
    return 1;
end sys.bison_pl_issue259_func_end3;
/
select sys.bison_pl_issue259_func_end3() as issue259_func_end from sys_dummy;
drop function sys.bison_pl_issue259_func_end3;

drop procedure if exists sys.bison_pl_issue261_proc_end3;
create or replace procedure sys.bison_pl_issue261_proc_end3 is
begin
    null;
end sys.bison_pl_issue261_proc_end3;
/
drop procedure sys.bison_pl_issue261_proc_end3;

drop table if exists bison_pl_pushback_log;
drop table if exists bison_pl_pushback_src;
create table bison_pl_pushback_log(stage varchar(40), val int, info varchar(60));
create table bison_pl_pushback_src(id int, name varchar(20));
insert into bison_pl_pushback_src values(7, 'PB');

declare
    type pushback_rec_t is record(id int, name varchar2(20));
    type id_tab_t is table of int index by binary_integer;
    v_rec pushback_rec_t;
    v_ids id_tab_t;
    v_id int := 0;
    v_name varchar2(20);
    cursor c_arg(p_min int, p_name varchar2 default 'PB') is
        select id, name from bison_pl_pushback_src where id >= p_min and name = p_name;
begin
    v_ids(1) := 11;
    bison_pl_proc(v_ids(1));

    open c_arg(p_min => 7, p_name => 'PB');
    fetch c_arg into v_id, v_name;
    close c_arg;
    v_rec.id := v_id;
    v_rec.name := v_name;

    execute immediate 'select id, name from bison_pl_pushback_src where id = :1'
        into v_id, v_name using in v_rec.id;

    insert into bison_pl_pushback_log values('assoc_type_lookahead', v_ids(1), 'ok');
    insert into bison_pl_pushback_log values('cursor_named_arg', v_rec.id, v_rec.name);
    insert into bison_pl_pushback_log values('execute_using', v_id, v_name);
end;
/

select * from bison_pl_pushback_log order by stage;

drop table if exists bison_pl_pushback_log;
drop table if exists bison_pl_pushback_src;

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
