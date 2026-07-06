drop table if exists products3;
CREATE TABLE products3 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products3 values(01,'grains',5.5);
select * from products3;
insert into  products3 values(02,'grains',5.5) on DUPLICATE key update name='grains';
select * from products3;
drop table products3;
