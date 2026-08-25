include_directories(
	"${OGRACDB_SRC}/cluster"
	"${OGRACDB_SRC}/rc"
	"${OGRACDB_SRC}/cms/interface"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/catalog"
        "${CMAKE_CURRENT_SOURCE_DIR}/executor"
        "${CMAKE_CURRENT_SOURCE_DIR}/executor/hash_join"
        "${CMAKE_CURRENT_SOURCE_DIR}/executor/explain"
        "${CMAKE_CURRENT_SOURCE_DIR}/json"
        "${CMAKE_CURRENT_SOURCE_DIR}/node"
        "${CMAKE_CURRENT_SOURCE_DIR}/function"
        "${CMAKE_CURRENT_SOURCE_DIR}/optimizer"
        "${CMAKE_CURRENT_SOURCE_DIR}/parser"
        "${CMAKE_CURRENT_SOURCE_DIR}/parser_ddl"
        "${CMAKE_CURRENT_SOURCE_DIR}/plan"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl/type"
        "${CMAKE_CURRENT_SOURCE_DIR}/verifier"
        "${CMAKE_CURRENT_SOURCE_DIR}/gdv"

)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --extern ${CMAKE_CURRENT_SOURCE_DIR}/parser/kwlist.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating kwlist_d.h from kwlist.h"
)

set(BISON_PARAM_ORDER_STAMP "${CMAKE_CURRENT_BINARY_DIR}/bison_param_order.checked")
set(BISON_PARAM_ORDER_CHECKER "${CMAKE_CURRENT_SOURCE_DIR}/parser/check_bison_param_order.pl")
add_custom_command(
    OUTPUT ${BISON_PARAM_ORDER_STAMP}
    COMMAND perl ${BISON_PARAM_ORDER_CHECKER}
        ${CMAKE_SOURCE_DIR}/pkg/src/server/params/srv_param.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dcl_alter_parser.c
        ${CMAKE_SOURCE_DIR}/pkg/src/common/cm_nls.c
    COMMAND ${CMAKE_COMMAND} -E touch ${BISON_PARAM_ORDER_STAMP}
    DEPENDS
        ${BISON_PARAM_ORDER_CHECKER}
        ${CMAKE_SOURCE_DIR}/pkg/src/server/params/srv_param.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dcl_alter_parser.c
        ${CMAKE_SOURCE_DIR}/pkg/src/common/cm_nls.c
    COMMENT "Checking Bison parameter table order"
    VERBATIM
)
add_custom_target(check_bison_param_order DEPENDS ${BISON_PARAM_ORDER_STAMP})

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.inc
    COMMAND rm -fr lex.backup
    COMMAND flex -CF -b -p -p -o scan.inc scan.l
    #COMMAND sed -i "s/YY_NULL/YY_ZERO/g" scan.inc
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating scan.inc from scan.l"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.h
    COMMAND bison -d -o gram.c gram.y
    COMMAND sed -i "s/YY_NULL nullptr/YY_NULL 0/g" gram.c
    COMMAND sed -i "s/\# define YYINITDEPTH .*/\# define YYINITDEPTH 1000/g" gram.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating gram.c, gram.h from gram.y"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.inc
    COMMAND rm -fr lex.backup
    COMMAND flex -CF -b -p -p -o hint_scan.inc hint_scan.l
    #COMMAND sed -i "s/YY_NULL/YY_ZERO/g" hint_scan.inc
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating hint_scan.inc from hint_scan.l"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.h
    COMMAND bison -d -o hint_gram.c hint_gram.y
    COMMAND sed -i "s/YY_NULL nullptr/YY_NULL 0/g" hint_gram.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating hint_gram.c, hint_gram.h from hint_gram.y"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_reserved_kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --varname ReservedPLKeywords --extern ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_reserved_kwlist.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_reserved_kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_reserved_kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating pl_reserved_kwlist_d.h from pl_reserved_kwlist.h"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_unreserved_kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --varname UnreservedPLKeywords --extern ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_unreserved_kwlist.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_unreserved_kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_unreserved_kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser
    COMMENT "Generating pl_unreserved_kwlist_d.h from pl_unreserved_kwlist.h"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.c ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.h
    COMMAND bison -d -o pl_gram.c pl_gram.y
    COMMAND sed -i "s/YY_NULL nullptr/YY_NULL 0/g" pl_gram.c
    COMMAND sed -i "s/\# define YYINITDEPTH .*/\# define YYINITDEPTH 1000/g" pl_gram.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.y
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.y
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser
    COMMENT "Generating pl_gram.c, pl_gram.h from pl_gram.y"
)


####### a format database #####
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser/ ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --extern ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/kwlist.h --varname dialect_a_ScanKeywords --dialect a
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser
    COMMENT "Generating a format kwlist_d.h from kwlist.h"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/ scan.l a_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.l
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate a-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.inc
    COMMAND rm -fr lex.backup
    COMMAND flex -CF -b -p -p -o scan-backend.inc scan-backend.l
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser
    COMMENT "Generating a format scan.inc from scan.l"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/ gram.y a_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.y
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.y
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate a-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.h
    COMMAND bison -d -o ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.y
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.l
	MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.l
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser
	COMMENT "Generating b format gram.c"
)


####### b format database #####
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser/ ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --extern ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/kwlist.h --varname dialect_b_ScanKeywords --dialect b
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser
    COMMENT "Generating b format kwlist_d.h from kwlist.h"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/ scan.l b_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.l
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate b-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.inc
    COMMAND rm -fr lex.backup
    COMMAND flex -CF -b -p -p -o scan-backend.inc scan-backend.l
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser
    COMMENT "Generating b format scan.inc from scan.l"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/ gram.y b_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.y
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.y
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate b-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.h
    COMMAND bison -d -o ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.y
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.l
	MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.l
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser
	COMMENT "Generating b format gram.c"
)

#######c format database######
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/kwlist_d.h
    COMMAND perl -I ${CMAKE_CURRENT_SOURCE_DIR}/parser/ ${CMAKE_CURRENT_SOURCE_DIR}/parser/gen_keywordlist.pl --extern ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/kwlist.h --varname dialect_c_ScanKeywords --dialect c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/kwlist.h
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/kwlist.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser
    COMMENT "Generating c format kwlist_d.h from kwlist.h"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/ scan.l c_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.l
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.l
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate c-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.inc
    COMMAND rm -fr lex.backup
    COMMAND flex -CF -b -p -p -o scan-backend.inc scan-backend.l
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.l
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.l
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser
    COMMENT "Generating c format scan.inc from scan.l"
)

execute_process(
    COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/parser/include.pl ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/ gram.y c_
    RESULT_VARIABLE RET_RESULT
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.y
    OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.y
)

if(RET_RESULT)
    message(FATAL_ERROR "Failed to generate c-format gram.y by include.pl.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.h
    COMMAND bison -d -o ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.c ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.y
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.l
	MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.y ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.l
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser
	COMMENT "Generating c format gram.c"
)

set(LIBRARY_OUTPUT_PATH ${OGRACDB_LIB})

aux_source_directory(. SQL_SRC)
aux_source_directory(./catalog SQL_CATALOG_SRC)
aux_source_directory(./executor SQL_EXECUTOR_SRC)
aux_source_directory(./executor/hash_join SQL_EXECUTOR_HASH_JOIN_SRC)
aux_source_directory(./executor/explain SQL_EXECUTOR_EXPLAIN_SRC)
aux_source_directory(./json SQL_JSON_SRC)
aux_source_directory(./node SQL_NODE_SRC)
aux_source_directory(./function SQL_FUNCTION_SRC)
aux_source_directory(./optimizer SQL_OPTIMIZER_SRC)
aux_source_directory(./parser SQL_PARSER_SRC)
aux_source_directory(./parser_ddl SQL_DDL_PARSER_SRC)
aux_source_directory(./verifier SQL_VERIFIER_SRC)
aux_source_directory(./plan SQL_PLAN_SRC)
aux_source_directory(./gdv SQL_GDV_SRC)
aux_source_directory(./pl SQL_PL_SRC)
aux_source_directory(./pl/include SQL_PL_INC_SRC)
aux_source_directory(./pl/type SQL_PL_TYPE_SRC)
#aux_source_directory(./pl/clang SQL_PL_CLANG_SRC)
aux_source_directory(./pl/debug SQL_PL_DEBUG_SRC)
aux_source_directory(./pl/meta SQL_PL_META_SRC)
aux_source_directory(./pl/persist SQL_PL_PERSIST_SRC)
aux_source_directory(./pl/parser SQL_PL_PARSER_SRC)
aux_source_directory(./pl/ast SQL_PL_AST_SRC)
aux_source_directory(./pl/executor SQL_PL_EXECUTOR_SRC)
aux_source_directory(./pl/common SQL_PL_COMMON_SRC)
set(PL_TOTAL_SRC ${SQL_PL_SRC} ${SQL_PL_INC_SRC} ${SQL_PL_TYPE_SRC} ${SQL_PL_CLANG_SRC} ${SQL_PL_DEBUG_SRC} ${SQL_PL_META_SRC} ${SQL_PL_PERSIST_SRC} ${SQL_PL_PARSER_SRC} ${SQL_PL_AST_SRC} ${SQL_PL_EXECUTOR_SRC} ${SQL_PL_COMMON_SRC})
set(SQL_ALL_SRC
        ${SQL_SRC}
        ${SQL_CATALOG_SRC}
        ${SQL_EXECUTOR_SRC}
        ${SQL_EXECUTOR_HASH_JOIN_SRC}
        ${SQL_EXECUTOR_EXPLAIN_SRC}
        ${SQL_NODE_SRC}
        ${SQL_FUNCTION_SRC}
        ${SQL_JSON_SRC}
        ${SQL_OPTIMIZER_SRC}
        ${SQL_PARSER_SRC}
        ${SQL_DDL_PARSER_SRC}
        ${SQL_VERIFIER_SRC}
        ${SQL_PLAN_SRC}
        ${SQL_GDV_SRC}
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/gram.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/scan.inc
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_gram.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/hint_scan.inc
        ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_gram.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_reserved_kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pl/parser/pl_unreserved_kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/kwlist_d.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/scan-backend.inc
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_a/backend_parser/gram-backend.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/scan-backend.inc
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_b/backend_parser/gram-backend.h
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/scan-backend.inc
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.c
        ${CMAKE_CURRENT_SOURCE_DIR}/parser/dialect_c/backend_parser/gram-backend.h
        )

link_directories(${OGRACDB_LIB} ${PCRE_LIB_PATH} ${VPP_LIB_PATH} ${Z_LIB_PATH})

add_library(ogracsql STATIC ${SQL_ALL_SRC} ${PL_TOTAL_SRC})
add_dependencies(ogserver check_bison_param_order)
add_dependencies(oGRAC check_bison_param_order)
add_dependencies(ogracsql check_bison_param_order)
if (USE_FUZZASAN)
target_link_libraries(ogracsql PRIVATE ogkernel)
endif(USE_FUZZASAN)
