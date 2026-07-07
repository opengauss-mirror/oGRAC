drop table if exists products18;
CREATE TABLE products18 (
    product_no integer ,
    name text,
    price numeric
);


insert into  products18 values(02,'grains',5.5) on DUPLICATE key update name='grains', price=5.5;
select * from  products18;
drop table products18;
