drop table if exists COMPANY;
CREATE TABLE COMPANY(
   ID INT PRIMARY KEY     NOT NULL,
   NAME           TEXT    NOT NULL,
   AGE            INT     NOT NULL,
   ADDRESS        CHAR(50),
   SALARY         REAL,
   JOIN_DATE      DATE
);
insert into COMPANY values(1,'tom''s',10,105,8500.9,'2020-11-17');
insert into COMPANY values(2,'tom''s toys',10,105,8500.9,'2020-11-17');
insert into COMPANY values(3,'tom''s and friend''s',10,105,8500.9,'2020-11-17');
select * from company;
drop table COMPANY;
