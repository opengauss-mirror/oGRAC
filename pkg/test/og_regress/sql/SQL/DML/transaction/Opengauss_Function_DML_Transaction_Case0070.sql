drop table if exists testzl;
                    create table testzl (SK INTEGER,ID CHAR(16),NAME VARCHAR(20),SQ_FT INTEGER);

declare
                        i integer;
                      begin
                        i := char_length('nnn');
                        insert into testzl values (i,'sk1','tt',3332);
                      end;
/

select count(*) from testzl;

drop table if exists testzl;
