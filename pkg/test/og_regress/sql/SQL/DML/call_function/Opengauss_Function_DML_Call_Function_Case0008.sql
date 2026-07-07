drop FUNCTION if EXISTS func_add_sql009;
CREATE FUNCTION func_add_sql009(num1 integer, num2 integer) RETURN integer
AS
BEGIN
RETURN num1 + num2;
END;
/
select func_add_sql009(num1=>1, num2=>3) from sys_dummy;
drop FUNCTION func_add_sql009;
