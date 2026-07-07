drop table if exists testzl;
                    CREATE TABLE testzl(SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER);

begin
                        insert into testzl values (001,to_char(current_date, 'YYYY-MM-DD'),'tt',3332);
                      end;
/

select count(*) from testzl;

drop table if exists testzl;
