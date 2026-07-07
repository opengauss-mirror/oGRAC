drop table if exists testzl;
                    create table testzl (SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER);

declare
                        i varchar(16);
                      begin
                        i := to_char(current_date, 'YYYY-MM-DD');
                        insert into testzl values (001,i,'tt',3332);
                      end;
/

select count(*) from testzl;

drop table if exists testzl;
