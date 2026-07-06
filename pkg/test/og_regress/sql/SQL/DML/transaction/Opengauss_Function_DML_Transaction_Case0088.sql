drop table if exists testzl;
                    CREATE TABLE testzl(SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER);

declare
                        i DECIMAL;
                      begin
                        i := 21.3;
                        insert into testzl values (001,'sk1','tt',floor(i));
                      end;
/

select count(*) from testzl;

drop table if exists testzl;
