declare
                            v_sql varchar(4000);
                          begin
                            v_sql := 'drop table if exists testzl';
                            execute immediate v_sql;
                            v_sql := 'CREATE TABLE testzl(SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER)';
                            execute immediate v_sql ;
                          end;
/

select count(*) from testzl;

drop table if exists testzl;
