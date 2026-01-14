--CREATE TABLE
drop TABLE if exists salary_2025;
CREATE TABLE salary_2025(id INT NOT NULL, name CHAR(50), job VARCHAR(30), salary NUMBER);
drop TABLE if exists salary_2026;
CREATE TABLE salary_2026(id INT NOT NULL, name CHAR(50), job VARCHAR(30), salary NUMBER);

--WRITE DATA
insert into salary_2025(id, name, job, salary) values(1, 'jack', 'teacher', 2000);
commit;

--CREATE INDEX
create index idx1 on salary_2025(id);
create index idx1 on salary_2025(name);
create index idx1 on salary_2026(id);

--DROP INDEX
drop index idx1;
create index idx1 on salary_2025(id);
drop index idx1 on salary_2025;

--ALTER INDEX
create index idx1 on salary_2025(id);
alter index idx1 rename to idx2;
alter index idx2 rename to idx1;
alter index idx1 on salary_2025 rename to idx2;

--ANALYZE INDEX
analyze table salary_2025 compute statistics;
analyze index idx1 compute statistics;
analyze index idx1 on salary_2025 compute statistics;

--DROP TABLE
drop TABLE if exists salary_2025;
drop TABLE if exists salary_2026;