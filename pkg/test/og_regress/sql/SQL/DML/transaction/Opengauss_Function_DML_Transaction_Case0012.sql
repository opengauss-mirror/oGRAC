drop table if exists testzl;
                create table testzl (SK INTEGER,ID CHAR(16),
                NAME VARCHAR(20),SQ_FT INTEGER);
                insert into testzl values (001,'sk1','tt',3332);

declare
                            t1 int;
                            v_sql varchar(4000);
                          begin
                            v_sql := 'select count(*) from testzl';
                            execute immediate v_sql into t1;
                          end;
/

select count(*) from testzl;

declare
                            t2 int;
                            v_sql varchar(4000);
                          begin
                            v_sql := 'select count(*) from testzl';
                            execute immediate v_sql into t2;
                          end;
/

select * from testzl;

drop table if exists testzl;
