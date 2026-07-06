drop table if exists products9;
CREATE TABLE products9 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products9 values(01,'grains',5.5);
select * from  products9;
insert into  products9 values(01,'grains',5.5) on DUPLICATE key update name='grains';
select * from  products9;
drop table products9;
