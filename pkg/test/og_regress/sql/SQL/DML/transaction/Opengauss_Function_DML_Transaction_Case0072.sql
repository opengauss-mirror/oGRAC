drop table if exists testzl;
                    create table testzl (SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER);

declare
                        i integer;
                      begin
                        i := floor(21.3);
                        insert into testzl values (001,'sk1','tt',i);
                      end;
/

select count(*) from testzl;

drop table if exists testzl;
