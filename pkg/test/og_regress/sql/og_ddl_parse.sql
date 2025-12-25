-- the default col and check can not using user define func
CREATE OR REPLACE FUNCTION func1(c1 int) return int is
begin
return 123;
end;
/
-- DEFAULT using user define func
drop table if exists users_status;
CREATE TABLE users_status (id int, status int DEFAULT func1(1)); -- error
-- CHECK using user define func
drop table if exists users_name;
CREATE TABLE users_name (
    id int, age int,
    CONSTRAINT age_check CHECK (age < func1(1))); -- error
CREATE TABLE users_name (
    id int, age int, birth int,
    CONSTRAINT age_check CHECK (birth < 100 and age < func1(1))); -- error

-- alter default 
CREATE TABLE users_status (id int, status int);
alter table users_status modify (status int default  func1(1)); -- error
alter table users_status add CONSTRAINT check_status check (id < func1(1)); -- error
alter table users_status add CONSTRAINT check_status check (status > 100 and id < func1(1)); -- error
DROP TABLE users_status;
DROP FUNCTION func1;