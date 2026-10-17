-- issue #389: switching use_bison_parser at runtime must not serve plans cached under the other parser mode
-- '1234'::nchar varying is rejected on the bison path (nvarchar requires a size)
-- and accepted on the native path (nchar + column alias "varying").
alter system set use_bison_parser = true;
select '1234'::nchar varying; --error
alter system set use_bison_parser = false;
select '1234'::nchar varying;
alter system set use_bison_parser = true;
select '1234'::nchar varying; --error (must be reparsed, not served from the native-mode cache)
alter system set use_bison_parser = false;
select '1234'::nchar varying;
