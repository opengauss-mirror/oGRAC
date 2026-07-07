drop table if exists student;
                                      create table student(id int, name char(20));
                                      drop index if exists unique_id;
                                      CREATE INDEX unique_id on student(id);

explain select sum(id) from student;
                                      explain select count(*) from student;

drop table student;
