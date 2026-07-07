drop table if exists abort_test;
                     create table abort_test(id int,name varchar(10));
                     insert into abort_test values(1,'a');
                     update abort_test set abort_test.name='cici' where abort_test.id=1;
