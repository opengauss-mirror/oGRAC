drop table if exists products4;
CREATE TABLE products4 (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products4 values(01,'grains',5.5);
select * from  products4;
insert into  products4 values(02,'grains1',5.5) on DUPLICATE key update  name ='grains1',  price=5.5;
select * from  products4;
drop table products4;
