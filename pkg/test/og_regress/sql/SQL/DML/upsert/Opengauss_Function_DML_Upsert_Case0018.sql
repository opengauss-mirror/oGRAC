drop table if exists products15;
CREATE TABLE products15 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products15 values(110,'meat',22.5);
select * from products15;
insert into  products15 values(110,'orange',7.4) on DUPLICATE key update name='orange';
select * from products15;
insert into  products15 values(111,'orange',7.4) ;
select * from products15;
drop table products15;
