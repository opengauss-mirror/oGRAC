alter system set use_bison_parser = true;

drop table if exists bison_explain_src;
drop table if exists bison_explain_dst;
drop table if exists bison_explain_ctas;
drop table if exists bison_explain_plain;

create table bison_explain_src(id int, val int, name varchar(20));
create table bison_explain_dst(id int, val int, name varchar(20));

insert into bison_explain_src values (1, 10, 'alpha'), (2, 20, 'beta'), (3, 30, 'gamma');
insert into bison_explain_dst values (1, 100, 'old');
commit;

explain select * from bison_explain_src where id = 1;
explain /* bison comment */ plan for select name from bison_explain_src where val between 10 and 30;
explain plan for select s.id, d.val
    from bison_explain_src s left join bison_explain_dst d on s.id = d.id
    where s.val >= 10
    order by s.id;
explain plan for with q as (
    select id, val from bison_explain_src where val > 10
) select * from q where id < 3;

explain plan for insert into bison_explain_dst
    select id + 10, val, name from bison_explain_src;
explain insert into bison_explain_dst(id, val, name) values (9, 90, 'plain');
explain plan for update bison_explain_dst set val = val + 1 where id in (
    select id from bison_explain_src
);
explain update bison_explain_dst set val = val + 2 where id = 1;
explain plan for delete from bison_explain_dst where exists (
    select 1 from bison_explain_src where bison_explain_src.id = bison_explain_dst.id
);
explain delete from bison_explain_dst where id = 2;
explain plan for merge into bison_explain_dst d
    using (select id, val, name from bison_explain_src) s
    on (d.id = s.id)
    when matched then update set d.val = s.val, d.name = s.name
    when not matched then insert (id, val, name) values (s.id, s.val, s.name);
explain merge into bison_explain_dst d
    using (select id, val, name from bison_explain_src where id = 1) s
    on (d.id = s.id)
    when matched then update set d.val = s.val, d.name = s.name
    when not matched then insert (id, val, name) values (s.id, s.val, s.name);
explain plan for replace into bison_explain_dst(id, val, name) values (4, 40, 'delta');
explain replace into bison_explain_dst(id, val, name) values (5, 50, 'epsilon');

explain plan for create table bison_explain_ctas as
    select id, val from bison_explain_src where val > 10;
explain plan for create table bison_explain_plain(id int, val int);
explain create table bison_explain_plain2(id int);
explain plan for create index bison_explain_idx on bison_explain_src(id);
explain create index bison_explain_idx_plain on bison_explain_src(val);
explain plan for create indexcluster (
    index bison_explain_idx1 on bison_explain_src(id),
    index bison_explain_idx2 on bison_explain_src(val)
);
explain create indexcluster (
    index bison_explain_idx3 on bison_explain_src(name)
);

drop table if exists bison_explain_plain;
drop table if exists bison_explain_ctas;
drop table if exists bison_explain_dst;
drop table if exists bison_explain_src;
