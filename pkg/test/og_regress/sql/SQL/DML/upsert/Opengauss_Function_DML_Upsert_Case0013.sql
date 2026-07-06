drop table if exists products10;
CREATE TABLE products10 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products10 values(01,'grains',5.5);
select * from  products10;
insert into  products10 values(01,'grains',5.5) on DUPLICATE key update name='grains', price=5.5;
select * from  products10;
drop table products10;
