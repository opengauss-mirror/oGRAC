drop table if exists testzl;
                create table testzl (SK INTEGER,ID CHAR(16),                NAME VARCHAR(20),SQ_FT INTEGER);
                insert into testzl values (001,'sk1','tt',3332);

declare
                            v_sql varchar(4000);
                          begin
                            v_sql := 'insert into testzl                             values (008,''sk1'',''tt'',3332)';
                            execute immediate v_sql ;
                          end;
/

select count(*) from testzl;

drop table if exists testzl;
