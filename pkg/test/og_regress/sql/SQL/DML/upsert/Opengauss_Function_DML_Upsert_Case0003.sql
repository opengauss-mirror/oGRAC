drop table if exists products;
CREATE TABLE products (
    product_no integer PRIMARY KEY,
    name text,
    price numeric
);
insert into  products values(01,'grains',5.5),(02,'veggies',6.5);
select * from products;
drop table products;
