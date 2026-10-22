/* standalone single-line comment */

select 1 as c01 from sys.sys_dummy;

/* multi-line comment opens here
   and closes with a statement on the same line */ select 2 as c02 from sys.sys_dummy;

/* bare close: nothing follows the closing mark
   note */
select 3 as c03 from sys.sys_dummy;

/* header comment
   ahead of a procedure block */
create or replace procedure p_comment_close as
begin
    null;
end;
/

drop procedure p_comment_close;

/* header on the same line as the block start */ create or replace procedure p_comment_close2 as
begin
    null;
end;
/

drop procedure p_comment_close2;

/* a quote in the comment body: don't */
select 4 as c04 from sys.sys_dummy;

/* command words in the comment tail: set up data */
select 5 as c05 from sys.sys_dummy;

/* hint style close */ select
6 as c06 from sys.sys_dummy;

/* exit word in the comment tail
exit */ select 7 as c07 from sys.sys_dummy;
