drop table if exists products7;
CREATE TABLE products7 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products7 values(01,'grains',5.5);
select * from  products7;
insert into  products7 values(01,'veggies',6.8) on DUPLICATE key update name='veggies';
select * from  products7;
drop table products7;
