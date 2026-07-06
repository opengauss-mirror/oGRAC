drop table if exists products6;
CREATE TABLE products6 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products6 values(01,'grains',5.5);
select * from  products6;
insert into  products6 values(02,'veggies',6.8) on DUPLICATE key update name='veggies',price=6.8;
select * from  products6;
drop table products6;
