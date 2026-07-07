drop table if exists products5;
CREATE TABLE products5 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products5 values(01,'grains',5.5);
select * from  products5;
insert into  products5 values(02,'veggies',6.8) on DUPLICATE key update name='veggies';
select * from  products5;
drop table products5;
