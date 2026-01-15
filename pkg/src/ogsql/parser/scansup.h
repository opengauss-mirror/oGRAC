/* -------------------------------------------------------------------------
 *
 * scansup.h
 *	  scanner support routines.  used by both the bootstrap lexer
 * as well as the normal lexer
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * pkg/src/ogsql/parser/scansup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef SCANSUP_H
#define SCANSUP_H

#include "cm_defs.h"

#define NAMEDATALEN 64
/* msb for char */
#define HIGHBIT 0x80
#define IS_HIGHBIT_SET(ch) ((unsigned char)(ch)&HIGHBIT)

extern char* scanstr(const char* s);

extern char* downcase_truncate_identifier(const char* ident, int len, bool8 warn);

extern char* upcase_truncate_identifier(const char* ident, int len, bool8 warn);

extern void truncate_identifier(char* ident, int len, bool8 warn);

extern bool8 scanner_isspace(char ch);

#endif