drop table if exists products8;
CREATE TABLE products8 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products8 values(01,'grains',5.5);
select * from  products8;
insert into  products8 values(01,'veggies',6.8) on DUPLICATE key update name='veggies', price=6.8;
select * from  products8;
drop table products8;
