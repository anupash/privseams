/* A Bison parser, made by GNU Bison 1.875d.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     A = 258,
     B = 259,
     C = 260,
     E = 261,
     F = 262,
     I = 263,
     L = 264,
     N = 265,
     P = 266,
     R = 267,
     S = 268,
     T = 269,
     ALL = 270,
     SP = 271,
     CRLF = 272,
     COMMA = 273,
     USER = 274,
     PASS = 275,
     ACCT = 276,
     REIN = 277,
     QUIT = 278,
     PORT = 279,
     PASV = 280,
     TYPE = 281,
     STRU = 282,
     MODE = 283,
     RETR = 284,
     STOR = 285,
     APPE = 286,
     MLFL = 287,
     MAIL = 288,
     MSND = 289,
     MSOM = 290,
     MSAM = 291,
     MRSQ = 292,
     MRCP = 293,
     ALLO = 294,
     REST = 295,
     RNFR = 296,
     RNTO = 297,
     ABOR = 298,
     DELE = 299,
     CWD = 300,
     LIST = 301,
     NLST = 302,
     SITE = 303,
     STAT = 304,
     HELP = 305,
     NOOP = 306,
     MKD = 307,
     RMD = 308,
     PWD = 309,
     CDUP = 310,
     STOU = 311,
     SMNT = 312,
     SYST = 313,
     SIZE = 314,
     MDTM = 315,
     LPRT = 316,
     LPSV = 317,
     EPRT = 318,
     EPSV = 319,
     UMASK = 320,
     IDLE = 321,
     CHMOD = 322,
     LEXERR = 323,
     STRING = 324,
     NUMBER = 325
   };
#endif
#define A 258
#define B 259
#define C 260
#define E 261
#define F 262
#define I 263
#define L 264
#define N 265
#define P 266
#define R 267
#define S 268
#define T 269
#define ALL 270
#define SP 271
#define CRLF 272
#define COMMA 273
#define USER 274
#define PASS 275
#define ACCT 276
#define REIN 277
#define QUIT 278
#define PORT 279
#define PASV 280
#define TYPE 281
#define STRU 282
#define MODE 283
#define RETR 284
#define STOR 285
#define APPE 286
#define MLFL 287
#define MAIL 288
#define MSND 289
#define MSOM 290
#define MSAM 291
#define MRSQ 292
#define MRCP 293
#define ALLO 294
#define REST 295
#define RNFR 296
#define RNTO 297
#define ABOR 298
#define DELE 299
#define CWD 300
#define LIST 301
#define NLST 302
#define SITE 303
#define STAT 304
#define HELP 305
#define NOOP 306
#define MKD 307
#define RMD 308
#define PWD 309
#define CDUP 310
#define STOU 311
#define SMNT 312
#define SYST 313
#define SIZE 314
#define MDTM 315
#define LPRT 316
#define LPSV 317
#define EPRT 318
#define EPSV 319
#define UMASK 320
#define IDLE 321
#define CHMOD 322
#define LEXERR 323
#define STRING 324
#define NUMBER 325




/* Copy the first part of user declarations.  */
#line 45 "ftpcmd.y"


char ftpcmd_rcsid[] = 
  "$Id: ftpcmd.y,v 1.11 1999/10/09 02:32:12 dholland Exp $";

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/ftp.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <netdb.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef __linux__
#include <tzfile.h>
#else
#define TM_YEAR_BASE 1900
#endif

#include "extern.h"

extern	union sockunion his_addr, data_dest;
extern	int logged_in;
extern	struct passwd *pw;
extern	int guest;
extern	int logging;
extern	int type;
extern	int form;
extern	int debug;
extern	int timeout;
extern	int maxtimeout;
extern  int pdata;
extern	char hostname[], remotehost[];
extern	char proctitle[];
extern	int usedefault;
extern  int transflag;
extern  char tmpline[];
extern	int portcheck;
extern	int epsvall;

off_t	restart_point;

static	int cmd_type;
static	int cmd_form;
static	int cmd_bytesz;
char	cbuf[512];
char	*fromname;

struct tab;
static int	 yylex __P((void));
static void	 sizecmd __P((char *));
static void	 help __P((struct tab *, char *));

extern struct tab cmdtab[];
extern struct tab sitetab[];



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 116 "ftpcmd.y"
typedef union YYSTYPE {
	int	i;
	char   *s;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 292 "y.tab.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 304 "y.tab.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   define YYSTACK_ALLOC alloca
#  endif
# else
#  if defined (alloca) || defined (_ALLOCA_H)
#   define YYSTACK_ALLOC alloca
#  else
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short int yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short int) + sizeof (YYSTYPE))			\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short int yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   304

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  71
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  17
/* YYNRULES -- Number of rules. */
#define YYNRULES  83
/* YYNRULES -- Number of states. */
#define YYNSTATES  278

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   325

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned short int yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    15,    20,    26,    32,
      38,    42,    46,    52,    58,    62,    68,    74,    80,    86,
      96,   102,   108,   114,   118,   124,   128,   134,   140,   144,
     150,   156,   160,   164,   170,   173,   178,   181,   187,   193,
     197,   201,   206,   213,   219,   227,   237,   243,   251,   257,
     261,   267,   273,   276,   279,   285,   291,   293,   294,   296,
     298,   310,   352,   370,   372,   374,   376,   378,   382,   384,
     388,   390,   392,   396,   399,   401,   403,   405,   407,   409,
     411,   413,   415,   417
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      72,     0,    -1,    -1,    72,    73,    -1,    72,    74,    -1,
      19,    16,    75,    17,    -1,    20,    16,    76,    17,    -1,
      24,    87,    16,    78,    17,    -1,    61,    87,    16,    79,
      17,    -1,    63,    87,    16,    69,    17,    -1,    25,    87,
      17,    -1,    62,    87,    17,    -1,    64,    87,    16,    70,
      17,    -1,    64,    87,    16,    15,    17,    -1,    64,    87,
      17,    -1,    26,    87,    16,    81,    17,    -1,    27,    87,
      16,    82,    17,    -1,    28,    87,    16,    83,    17,    -1,
      39,    87,    16,    70,    17,    -1,    39,    87,    16,    70,
      16,    12,    16,    70,    17,    -1,    29,    87,    16,    84,
      17,    -1,    30,    87,    16,    84,    17,    -1,    31,    87,
      16,    84,    17,    -1,    47,    87,    17,    -1,    47,    87,
      16,    69,    17,    -1,    46,    87,    17,    -1,    46,    87,
      16,    84,    17,    -1,    49,    87,    16,    84,    17,    -1,
      49,    87,    17,    -1,    44,    87,    16,    84,    17,    -1,
      42,    87,    16,    84,    17,    -1,    43,    87,    17,    -1,
      45,    87,    17,    -1,    45,    87,    16,    84,    17,    -1,
      50,    17,    -1,    50,    16,    69,    17,    -1,    51,    17,
      -1,    52,    87,    16,    84,    17,    -1,    53,    87,    16,
      84,    17,    -1,    54,    87,    17,    -1,    55,    87,    17,
      -1,    48,    16,    50,    17,    -1,    48,    16,    50,    16,
      69,    17,    -1,    48,    16,    65,    87,    17,    -1,    48,
      16,    65,    87,    16,    86,    17,    -1,    48,    16,    67,
      87,    16,    86,    16,    84,    17,    -1,    48,    16,    87,
      66,    17,    -1,    48,    16,    87,    66,    16,    70,    17,
      -1,    56,    87,    16,    84,    17,    -1,    58,    87,    17,
      -1,    59,    87,    16,    84,    17,    -1,    60,    87,    16,
      84,    17,    -1,    23,    17,    -1,     1,    17,    -1,    41,
      87,    16,    84,    17,    -1,    40,    87,    16,    77,    17,
      -1,    69,    -1,    -1,    69,    -1,    70,    -1,    70,    18,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    -1,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    18,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    18,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    18,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    18,
      70,    -1,    70,    18,    70,    18,    70,    18,    70,    18,
      70,    18,    70,    18,    70,    18,    70,    18,    70,    -1,
      10,    -1,    14,    -1,     5,    -1,     3,    -1,     3,    16,
      80,    -1,     6,    -1,     6,    16,    80,    -1,     8,    -1,
       9,    -1,     9,    16,    77,    -1,     9,    77,    -1,     7,
      -1,    12,    -1,    11,    -1,    13,    -1,     4,    -1,     5,
      -1,    85,    -1,    69,    -1,    70,    -1,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short int yyrline[] =
{
       0,   153,   153,   155,   160,   164,   169,   175,   186,   203,
     212,   220,   228,   234,   241,   247,   281,   295,   309,   315,
     321,   328,   335,   342,   347,   354,   359,   366,   373,   378,
     385,   399,   404,   409,   416,   420,   438,   442,   449,   456,
     461,   466,   470,   477,   487,   502,   516,   523,   539,   546,
     572,   589,   611,   616,   622,   636,   649,   654,   657,   661,
     665,   688,   731,   754,   758,   762,   769,   774,   779,   784,
     789,   793,   798,   804,   812,   816,   820,   827,   831,   835,
     842,   886,   890,   918
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "A", "B", "C", "E", "F", "I", "L", "N",
  "P", "R", "S", "T", "ALL", "SP", "CRLF", "COMMA", "USER", "PASS", "ACCT",
  "REIN", "QUIT", "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR",
  "APPE", "MLFL", "MAIL", "MSND", "MSOM", "MSAM", "MRSQ", "MRCP", "ALLO",
  "REST", "RNFR", "RNTO", "ABOR", "DELE", "CWD", "LIST", "NLST", "SITE",
  "STAT", "HELP", "NOOP", "MKD", "RMD", "PWD", "CDUP", "STOU", "SMNT",
  "SYST", "SIZE", "MDTM", "LPRT", "LPSV", "EPRT", "EPSV", "UMASK", "IDLE",
  "CHMOD", "LEXERR", "STRING", "NUMBER", "$accept", "cmd_list", "cmd",
  "rcmd", "username", "password", "byte_size", "host_port",
  "host_long_port", "form_code", "type_code", "struct_code", "mode_code",
  "pathname", "pathstring", "octal_number", "check_login", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short int yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    71,    72,    72,    72,    73,    73,    73,    73,    73,
      73,    73,    73,    73,    73,    73,    73,    73,    73,    73,
      73,    73,    73,    73,    73,    73,    73,    73,    73,    73,
      73,    73,    73,    73,    73,    73,    73,    73,    73,    73,
      73,    73,    73,    73,    73,    73,    73,    73,    73,    73,
      73,    73,    73,    73,    74,    74,    75,    76,    76,    77,
      78,    79,    79,    80,    80,    80,    81,    81,    81,    81,
      81,    81,    81,    81,    82,    82,    82,    83,    83,    83,
      84,    85,    86,    87
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     2,     2,     4,     4,     5,     5,     5,
       3,     3,     5,     5,     3,     5,     5,     5,     5,     9,
       5,     5,     5,     3,     5,     3,     5,     5,     3,     5,
       5,     3,     3,     5,     2,     4,     2,     5,     5,     3,
       3,     4,     6,     5,     7,     9,     5,     7,     5,     3,
       5,     5,     2,     2,     5,     5,     1,     0,     1,     1,
      11,    41,    17,     1,     1,     1,     1,     3,     1,     3,
       1,     1,     3,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     0
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,    83,    83,    83,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    83,    83,    83,     0,    83,     0,     0,    83,    83,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
       3,     4,    53,     0,    57,    52,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    83,     0,     0,    34,    36,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      56,     0,    58,     0,     0,    10,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    31,     0,     0,    32,
       0,    25,     0,    23,     0,    83,    83,     0,     0,    28,
       0,     0,     0,    39,    40,     0,    49,     0,     0,     0,
      11,     0,     0,    14,     5,     6,     0,     0,    66,    68,
      70,    71,     0,    74,    76,    75,     0,    78,    79,    77,
       0,    81,     0,    80,     0,     0,     0,    59,     0,     0,
       0,     0,     0,     0,     0,     0,    41,     0,     0,     0,
       0,    35,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     7,     0,     0,     0,    73,    15,    16,
      17,    20,    21,    22,     0,    18,    55,    54,    30,    29,
      33,    26,    24,     0,     0,    43,     0,     0,    46,    27,
      37,    38,    48,    50,    51,     0,     8,     9,    13,    12,
       0,    65,    63,    64,    67,    69,    72,     0,    42,    82,
       0,     0,     0,     0,     0,     0,    44,     0,    47,     0,
       0,     0,     0,     0,     0,    19,    45,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    60,     0,     0,     0,
       0,     0,     0,    62,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    61
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     1,    40,    41,    81,    83,   148,   127,   168,   214,
     132,   136,   140,   142,   143,   220,    46
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -115
static const short int yypact[] =
{
    -115,    47,  -115,     3,     8,    10,    28,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,    49,  -115,    -4,    63,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,    16,    35,  -115,   100,   105,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   108,   132,
      -1,    52,    66,    14,    97,    59,  -115,  -115,   133,   134,
     135,   136,   138,   139,   141,   142,   143,   144,   146,   104,
    -115,   147,  -115,   148,    81,  -115,   109,   112,    -2,    86,
      86,    86,    90,    93,    86,    86,  -115,    86,    86,  -115,
      86,  -115,    98,  -115,   113,  -115,  -115,   102,    86,  -115,
     149,    86,    86,  -115,  -115,    86,  -115,    86,    86,    99,
    -115,   101,    -9,  -115,  -115,  -115,   153,   155,   157,   158,
    -115,    -7,   159,  -115,  -115,  -115,   160,  -115,  -115,  -115,
     161,  -115,   162,  -115,   163,   164,   115,  -115,   165,   166,
     167,   168,   169,   170,   171,   106,  -115,   117,   173,   119,
     174,  -115,   175,   176,   177,   178,   179,   172,   180,   181,
     182,   183,   137,  -115,     9,     9,    93,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,   189,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,   185,   140,  -115,   140,   145,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,   150,  -115,  -115,  -115,  -115,
     186,  -115,  -115,  -115,  -115,  -115,  -115,   187,  -115,  -115,
     188,   190,   191,   193,   151,   152,  -115,    86,  -115,   154,
     194,   192,   196,   198,   156,  -115,  -115,   184,   199,   200,
     195,   197,   201,   205,   202,   203,  -115,   207,   204,   209,
     206,   210,   208,   211,   212,   213,   214,   215,   216,   217,
     218,   219,   220,   221,   222,   223,   224,   225,   226,   227,
     228,   229,   230,   231,   232,   233,   234,  -115
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
    -115,  -115,  -115,  -115,  -115,  -115,  -114,  -115,  -115,    39,
    -115,  -115,  -115,   -90,  -115,    34,    21
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned short int yytable[] =
{
     144,   145,   137,   138,   149,   150,   170,   151,   152,   176,
     153,   139,    65,    66,   211,    98,    99,   177,   160,   212,
      42,   162,   163,   213,    43,   164,    44,   165,   166,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    45,    64,     2,     3,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,   171,   216,   147,   104,    63,     4,     5,   100,   101,
       6,     7,     8,     9,    10,    11,    12,    13,    14,   105,
      67,   106,   102,   103,   107,    80,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    82,    33,    34,    35,    36,    37,
      38,    39,   128,   108,   109,   129,    84,   130,   131,   133,
     122,   123,    85,   134,   135,    96,   157,   158,   110,   155,
     156,   184,   185,   194,   195,   197,   198,   232,    86,    87,
      88,    89,    90,    91,    92,    93,    94,    95,    97,   111,
     112,   126,   113,   114,   115,   141,   116,   117,   118,   119,
     146,   120,   121,   147,   124,   125,   161,   154,   159,   167,
     169,   172,   173,   174,   175,   193,   178,   179,   180,   181,
     182,   183,   186,   187,   188,   189,   190,   191,   192,   196,
     205,   199,   200,   201,   202,   203,   204,   206,   207,   208,
     209,   217,   218,   225,   224,   226,   227,   210,   228,   235,
     219,   229,   234,   236,   215,   222,   237,   240,   241,   244,
     223,   230,   231,   245,   233,   248,   238,   250,   252,   254,
     221,   256,     0,   258,     0,   260,     0,   262,     0,   264,
       0,   266,     0,   268,     0,   270,     0,   272,     0,   274,
       0,   276,     0,     0,   239,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   242,     0,   243,     0,     0,
       0,     0,   246,   247,   249,     0,   251,     0,   253,     0,
       0,     0,   255,     0,   257,     0,   259,     0,   261,     0,
     263,     0,   265,     0,   267,     0,   269,     0,   271,     0,
     273,     0,   275,     0,   277
};

static const short int yycheck[] =
{
      90,    91,     4,     5,    94,    95,    15,    97,    98,    16,
     100,    13,    16,    17,     5,    16,    17,   131,   108,    10,
      17,   111,   112,    14,    16,   115,    16,   117,   118,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    17,    25,     0,     1,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    70,   176,    70,    50,    16,    19,    20,    16,    17,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    65,
      17,    67,    16,    17,    63,    69,    39,    40,    41,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    69,    58,    59,    60,    61,    62,
      63,    64,     3,    16,    17,     6,    16,     8,     9,     7,
      16,    17,    17,    11,    12,    17,   105,   106,    69,    16,
      17,    16,    17,    16,    17,    16,    17,   227,    16,    16,
      16,    16,    16,    16,    16,    16,    16,    16,    16,    16,
      16,    70,    17,    17,    16,    69,    17,    16,    16,    16,
      70,    17,    16,    70,    17,    17,    17,    69,    66,    70,
      69,    18,    17,    16,    16,    69,    17,    17,    17,    17,
      17,    17,    17,    17,    17,    17,    17,    17,    17,    16,
      18,    17,    17,    17,    17,    17,    17,    17,    17,    17,
      17,    12,    17,    16,    18,    17,    16,    70,    17,    17,
      70,    18,    18,    17,   175,    70,    18,    18,    18,    18,
      70,    70,    70,    18,    70,    18,    70,    18,    18,    18,
     196,    18,    -1,    18,    -1,    18,    -1,    18,    -1,    18,
      -1,    18,    -1,    18,    -1,    18,    -1,    18,    -1,    18,
      -1,    18,    -1,    -1,    70,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    -1,    70,    -1,    -1,
      -1,    -1,    70,    70,    70,    -1,    70,    -1,    70,    -1,
      -1,    -1,    70,    -1,    70,    -1,    70,    -1,    70,    -1,
      70,    -1,    70,    -1,    70,    -1,    70,    -1,    70,    -1,
      70,    -1,    70,    -1,    70
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    72,     0,     1,    19,    20,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    58,    59,    60,    61,    62,    63,    64,
      73,    74,    17,    16,    16,    17,    87,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    87,    16,    87,    16,    17,    17,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      69,    75,    69,    76,    16,    17,    16,    16,    16,    16,
      16,    16,    16,    16,    16,    16,    17,    16,    16,    17,
      16,    17,    16,    17,    50,    65,    67,    87,    16,    17,
      69,    16,    16,    17,    17,    16,    17,    16,    16,    16,
      17,    16,    16,    17,    17,    17,    70,    78,     3,     6,
       8,     9,    81,     7,    11,    12,    82,     4,     5,    13,
      83,    69,    84,    85,    84,    84,    70,    70,    77,    84,
      84,    84,    84,    84,    69,    16,    17,    87,    87,    66,
      84,    17,    84,    84,    84,    84,    84,    70,    79,    69,
      15,    70,    18,    17,    16,    16,    16,    77,    17,    17,
      17,    17,    17,    17,    16,    17,    17,    17,    17,    17,
      17,    17,    17,    69,    16,    17,    16,    16,    17,    17,
      17,    17,    17,    17,    17,    18,    17,    17,    17,    17,
      70,     5,    10,    14,    80,    80,    77,    12,    17,    70,
      86,    86,    70,    70,    18,    16,    17,    16,    17,    18,
      70,    70,    84,    70,    18,    17,    17,    18,    70,    70,
      18,    18,    70,    70,    18,    18,    70,    70,    18,    70,
      18,    70,    18,    70,    18,    70,    18,    70,    18,    70,
      18,    70,    18,    70,    18,    70,    18,    70,    18,    70,
      18,    70,    18,    70,    18,    70,    18,    70
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)		\
   ((Current).first_line   = (Rhs)[1].first_line,	\
    (Current).first_column = (Rhs)[1].first_column,	\
    (Current).last_line    = (Rhs)[N].last_line,	\
    (Current).last_column  = (Rhs)[N].last_column)
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short int *bottom, short int *top)
#else
static void
yy_stack_print (bottom, top)
    short int *bottom;
    short int *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if defined (YYMAXDEPTH) && YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short int yyssa[YYINITDEPTH];
  short int *yyss = yyssa;
  register short int *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;


  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short int *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short int *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 3:
#line 156 "ftpcmd.y"
    {
			fromname = (char *) 0;
			restart_point = (off_t) 0;
		}
    break;

  case 5:
#line 165 "ftpcmd.y"
    {
			user(yyvsp[-1].s);
			free(yyvsp[-1].s);
		}
    break;

  case 6:
#line 170 "ftpcmd.y"
    {
			pass(yyvsp[-1].s);
			memset(yyvsp[-1].s, 0, strlen(yyvsp[-1].s));
			free(yyvsp[-1].s);
		}
    break;

  case 7:
#line 176 "ftpcmd.y"
    {
			if (epsvall) {
				reply(501, "PORT disallowed after EPSV ALL");
			} else if (!yyvsp[-3].i) {
			} else if (port_check("PORT") == 1) {
			} else {
				usedefault = 1;
				reply(500, "Invalid address rejected.");
			}
		}
    break;

  case 8:
#line 187 "ftpcmd.y"
    {
			if (epsvall) {
				reply(501, "LPRT disallowed after EPSV ALL");
			} else if (!yyvsp[-3].i) {
			} else if (port_check("LPRT") == 1) {
#ifdef HIP_NATIVE
			} else if (port_check_hip("LPRT") == 1) {
#endif
#ifdef INET6
			} else if (port_check_v6("LPRT") == 1) {
#endif
			} else {
				usedefault = 1;
				reply(500, "Invalid address rejected.");
			}
		}
    break;

  case 9:
#line 204 "ftpcmd.y"
    {
			if (epsvall) {
				reply(501, "EPRT disallowed after EPSV ALL");
			} else if (yyvsp[-3].i) {
				extended_port(yyvsp[-1].s);
			}
			free(yyvsp[-1].s);
		}
    break;

  case 10:
#line 213 "ftpcmd.y"
    {
			if (epsvall) {
				reply(501, "PASV disallowed after EPSV ALL");
			} else if (yyvsp[-1].i) {
				passive();
			}
		}
    break;

  case 11:
#line 221 "ftpcmd.y"
    {
			if (epsvall) {
				reply(501, "LPSV disallowed after EPSV ALL");
			} else if (yyvsp[-1].i) {
				long_passive("LPSV", PF_UNSPEC);
			}
		}
    break;

  case 12:
#line 229 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				long_passive("EPSV", ex_prot2af(yyvsp[-1].i));
			}
		}
    break;

  case 13:
#line 235 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				reply(200, "EPSV ALL command successful.");
				epsvall++;
			}
		}
    break;

  case 14:
#line 242 "ftpcmd.y"
    {
			if (yyvsp[-1].i) {
				long_passive("EPSV", PF_UNSPEC);
			}
		}
    break;

  case 15:
#line 248 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				switch (cmd_type) {

				case TYPE_A:
					if (cmd_form == FORM_N) {
						reply(200, "Type set to A.");
						type = cmd_type;
						form = cmd_form;
					} else
						reply(504, "Form must be N.");
					break;

				case TYPE_E:
					reply(504, "Type E not implemented.");
					break;
	
				case TYPE_I:
					reply(200, "Type set to I.");
					type = cmd_type;
					break;

				case TYPE_L:
					if (cmd_bytesz == 8) {
					       reply(200,
					       "Type set to L (byte size 8).");
					       type = cmd_type;
					} else
					    reply(504, "Byte size must be 8.");

				}
			}
		}
    break;

  case 16:
#line 282 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				switch (yyvsp[-1].i) {

				case STRU_F:
					reply(200, "STRU F ok.");
					break;

				default:
					reply(504, "Unimplemented STRU type.");
				}
			}
		}
    break;

  case 17:
#line 296 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				switch (yyvsp[-1].i) {

				case MODE_S:
					reply(200, "MODE S ok.");
					break;

				default:
					reply(502, "Unimplemented MODE type.");
				}
			}
		}
    break;

  case 18:
#line 310 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				reply(202, "ALLO command ignored.");
			}
		}
    break;

  case 19:
#line 316 "ftpcmd.y"
    {
			if (yyvsp[-7].i) {
				reply(202, "ALLO command ignored.");
			}
		}
    break;

  case 20:
#line 322 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve((char *) 0, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 21:
#line 329 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 22:
#line 336 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "a", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 23:
#line 343 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				send_file_list(".");
		}
    break;

  case 24:
#line 348 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				send_file_list(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 25:
#line 355 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				retrieve("/bin/ls -lgA", "");
		}
    break;

  case 26:
#line 360 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve("/bin/ls -lgA %s", yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 27:
#line 367 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				statfilecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 28:
#line 374 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				statcmd();
		}
    break;

  case 29:
#line 379 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				delete(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 30:
#line 386 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
				if (fromname) {
					renamecmd(fromname, yyvsp[-1].s);
					free(fromname);
					fromname = (char *) 0;
				} else {
					reply(503,
					  "Bad sequence of commands.");
				}
			}
			free(yyvsp[-1].s);
		}
    break;

  case 31:
#line 400 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				reply(225, "ABOR command successful.");
		}
    break;

  case 32:
#line 405 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				cwd(pw->pw_dir);
		}
    break;

  case 33:
#line 410 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				cwd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 34:
#line 417 "ftpcmd.y"
    {
			help(cmdtab, (char *) 0);
		}
    break;

  case 35:
#line 421 "ftpcmd.y"
    {
			char *cp = yyvsp[-1].s;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = yyvsp[-1].s + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, (char *) 0);
			} else
				help(cmdtab, yyvsp[-1].s);

			if (yyvsp[-1].s != NULL)
				free (yyvsp[-1].s);
		}
    break;

  case 36:
#line 439 "ftpcmd.y"
    {
			reply(200, "NOOP command successful.");
		}
    break;

  case 37:
#line 443 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				makedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 38:
#line 450 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				removedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 39:
#line 457 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				pwd();
		}
    break;

  case 40:
#line 462 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
				cwd("..");
		}
    break;

  case 41:
#line 467 "ftpcmd.y"
    {
			help(sitetab, (char *) 0);
		}
    break;

  case 42:
#line 471 "ftpcmd.y"
    {
			help(sitetab, yyvsp[-1].s);

			if (yyvsp[-1].s != NULL)
				free (yyvsp[-1].s);
		}
    break;

  case 43:
#line 478 "ftpcmd.y"
    {
			int oldmask;

			if (yyvsp[-1].i) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o", oldmask);
			}
		}
    break;

  case 44:
#line 488 "ftpcmd.y"
    {
			int oldmask;

			if (yyvsp[-3].i) {
				if ((yyvsp[-1].i == -1) || (yyvsp[-1].i > 0777)) {
					reply(501, "Bad UMASK value");
				} else {
					oldmask = umask(yyvsp[-1].i);
					reply(200,
					    "UMASK set to %03o (was %03o)",
					    yyvsp[-1].i, oldmask);
				}
			}
		}
    break;

  case 45:
#line 503 "ftpcmd.y"
    {
			if (yyvsp[-5].i && (yyvsp[-1].s != NULL)) {
				if (yyvsp[-3].i > 0777)
					reply(501,
				"CHMOD: Mode value must be between 0 and 0777");
				else if (chmod(yyvsp[-1].s, yyvsp[-3].i) < 0)
					perror_reply(550, yyvsp[-1].s);
				else
					reply(200, "CHMOD command successful.");
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 46:
#line 517 "ftpcmd.y"
    {
			if (yyvsp[-2].i)
			  reply(200,
			    "Current IDLE time limit is %d seconds; max %d",
				timeout, maxtimeout);
		}
    break;

  case 47:
#line 524 "ftpcmd.y"
    {
			if (yyvsp[-4].i) {
				if (yyvsp[-1].i < 30 || yyvsp[-1].i > maxtimeout) {
				reply(501,
			 "Maximum IDLE time must be between 30 and %d seconds",
				    maxtimeout);
				} else {
					timeout = yyvsp[-1].i;
					(void) alarm((unsigned) timeout);
					reply(200,
					 "Maximum IDLE time set to %d seconds",
					    timeout);
				}
			}
		}
    break;

  case 48:
#line 540 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 1);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 49:
#line 547 "ftpcmd.y"
    {
			if (yyvsp[-1].i)
#ifdef __linux__
			reply(215, "UNIX Type: L%d (Linux)", CHAR_BIT);
#else
#ifdef unix
#ifdef BSD
			reply(215, "UNIX Type: L%d Version: BSD-%d",
				CHAR_BIT, BSD);
#else /* BSD */
			reply(215, "UNIX Type: L%d", CHAR_BIT);
#endif /* BSD */
#else /* unix */
			reply(215, "UNKNOWN Type: L%d", CHAR_BIT);
#endif /* unix */
#endif /* __linux__ */
		}
    break;

  case 50:
#line 573 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				sizecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 51:
#line 590 "ftpcmd.y"
    {
			if (yyvsp[-3].i && yyvsp[-1].s != NULL) {
				struct stat stbuf;
				if (stat(yyvsp[-1].s, &stbuf) < 0)
					reply(550, "%s: %s",
					    yyvsp[-1].s, strerror(errno));
				else if (!S_ISREG(stbuf.st_mode)) {
					reply(550, "%s: not a plain file.", yyvsp[-1].s);
				} else {
					struct tm *t;
					t = gmtime(&stbuf.st_mtime);
					reply(213,
					    "%04d%02d%02d%02d%02d%02d",
					    TM_YEAR_BASE + t->tm_year,
					    t->tm_mon+1, t->tm_mday,
					    t->tm_hour, t->tm_min, t->tm_sec);
				}
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
    break;

  case 52:
#line 612 "ftpcmd.y"
    {
			reply(221, "Goodbye.");
			dologout(0);
		}
    break;

  case 53:
#line 617 "ftpcmd.y"
    {
			yyerrok;
		}
    break;

  case 54:
#line 623 "ftpcmd.y"
    {
			restart_point = (off_t) 0;
			if (yyvsp[-3].i && yyvsp[-1].s) {
				fromname = renamefrom(yyvsp[-1].s);
				if (fromname == (char *) 0 && yyvsp[-1].s) {
					free(yyvsp[-1].s);
				}
			} else {
				if (yyvsp[-1].s)
					free (yyvsp[-1].s);
			}
		}
    break;

  case 55:
#line 637 "ftpcmd.y"
    {
			if (yyvsp[-3].i) {
			    fromname = (char *) 0;
			    restart_point = yyvsp[-1].i;	/* XXX $4 is only "int" */
			    reply(350, "Restarting at %qd. %s",
			       (quad_t) restart_point,
			       "Send STORE or RETRIEVE to initiate transfer.");
			}
		}
    break;

  case 57:
#line 654 "ftpcmd.y"
    {
			yyval.s = (char *)calloc(1, sizeof(char));
		}
    break;

  case 60:
#line 667 "ftpcmd.y"
    {
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));
			if (yyvsp[-10].i < 0 || yyvsp[-10].i > 255 || yyvsp[-8].i < 0 || yyvsp[-8].i > 255 ||
			    yyvsp[-6].i < 0 || yyvsp[-6].i > 255 || yyvsp[-4].i < 0 || yyvsp[-4].i > 255 ||
			    yyvsp[-2].i < 0 || yyvsp[-2].i > 255 || yyvsp[0].i < 0 || yyvsp[0].i > 255) {
			} else {
#ifndef __linux__
				data_dest.sin_len = sizeof(struct sockaddr_in);
#endif
				data_dest.su_family = AF_INET;
				p = (char *)&data_dest.su_sin.sin_port;
				p[0] = yyvsp[-2].i; p[1] = yyvsp[0].i;
				a = (char *)&data_dest.su_sin.sin_addr;
				a[0] = yyvsp[-10].i; a[1] = yyvsp[-8].i; a[2] = yyvsp[-6].i; a[3] = yyvsp[-4].i;
			}
		}
    break;

  case 61:
#line 694 "ftpcmd.y"
    {
			memset(&data_dest, 0, sizeof(data_dest));
			if (yyvsp[-40].i != 6 || yyvsp[-38].i != 16 || yyvsp[-4].i != 2 ||
			    yyvsp[-36].i < 0 || yyvsp[-36].i > 255 || yyvsp[-34].i < 0 || yyvsp[-34].i > 255 ||
			    yyvsp[-32].i < 0 || yyvsp[-32].i > 255 || yyvsp[-30].i < 0 || yyvsp[-30].i > 255 ||
			    yyvsp[-28].i < 0 || yyvsp[-28].i > 255 || yyvsp[-26].i < 0 || yyvsp[-26].i > 255 ||
			    yyvsp[-24].i < 0 || yyvsp[-24].i > 255 || yyvsp[-22].i < 0 || yyvsp[-22].i > 255 ||
			    yyvsp[-20].i < 0 || yyvsp[-20].i > 255 || yyvsp[-18].i < 0 || yyvsp[-18].i > 255 ||
			    yyvsp[-16].i < 0 || yyvsp[-16].i > 255 || yyvsp[-14].i < 0 || yyvsp[-14].i > 255 ||
			    yyvsp[-12].i < 0 || yyvsp[-12].i > 255 || yyvsp[-10].i < 0 || yyvsp[-10].i > 255 ||
			    yyvsp[-8].i < 0 || yyvsp[-8].i > 255 || yyvsp[-6].i < 0 || yyvsp[-6].i > 255 ||
			    yyvsp[-2].i < 0 || yyvsp[-2].i > 255 || yyvsp[0].i < 0 || yyvsp[0].i > 255) {
			} else {
#if defined(INET6) || defined(HIP_NATIVE)
				char *a, *p;
#ifdef HIP_NATIVE
				data_dest.su_family = AF_HIP;
#else
				data_dest.su_family = AF_INET6;
#endif
				p = (char *)&data_dest.su_port;
				p[0] = yyvsp[-2].i; p[1] = yyvsp[0].i;
				a = (char *)&data_dest.su_sin6.sin6_addr;
			  a[0] =  yyvsp[-36].i;  a[1] =  yyvsp[-34].i;  a[2] =  yyvsp[-32].i;  a[3] = yyvsp[-30].i;
			  a[4] = yyvsp[-28].i;  a[5] = yyvsp[-26].i;  a[6] = yyvsp[-24].i;  a[7] = yyvsp[-22].i;
			  a[8] = yyvsp[-20].i;  a[9] = yyvsp[-18].i; a[10] = yyvsp[-16].i; a[11] = yyvsp[-14].i;
			  a[12] = yyvsp[-12].i; a[13] = yyvsp[-10].i; a[14] = yyvsp[-8].i; a[15] = yyvsp[-6].i;
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
				if (his_addr.su_family == AF_INET6) {
					/* XXX more sanity checks! */
					data_dest.su_sin6.sin6_scope_id =
					  his_addr.su_sin6.sin6_scope_id;
				}
#endif
#endif
			}
		}
    break;

  case 62:
#line 734 "ftpcmd.y"
    {
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));
			if (yyvsp[-16].i != 4 || yyvsp[-14].i != 4 || yyvsp[-4].i != 2 ||
			    yyvsp[-12].i < 0 || yyvsp[-12].i > 255 || yyvsp[-10].i < 0 || yyvsp[-10].i > 255 ||
			    yyvsp[-8].i < 0 || yyvsp[-8].i > 255 || yyvsp[-6].i < 0 || yyvsp[-6].i > 255 ||
			    yyvsp[-2].i < 0 || yyvsp[-2].i > 255 || yyvsp[0].i < 0 || yyvsp[0].i > 255) {
			} else {

				data_dest.su_family = AF_INET;
				p = (char *)&data_dest.su_port;
				p[0] = yyvsp[-2].i; p[1] = yyvsp[0].i;
				a = (char *)&data_dest.su_sin.sin_addr;
				a[0] = yyvsp[-12].i; a[1] = yyvsp[-10].i; a[2] = yyvsp[-8].i; a[3] = yyvsp[-6].i;
			}
		}
    break;

  case 63:
#line 755 "ftpcmd.y"
    {
			yyval.i = FORM_N;
		}
    break;

  case 64:
#line 759 "ftpcmd.y"
    {
			yyval.i = FORM_T;
		}
    break;

  case 65:
#line 763 "ftpcmd.y"
    {
			yyval.i = FORM_C;
		}
    break;

  case 66:
#line 770 "ftpcmd.y"
    {
			cmd_type = TYPE_A;
			cmd_form = FORM_N;
		}
    break;

  case 67:
#line 775 "ftpcmd.y"
    {
			cmd_type = TYPE_A;
			cmd_form = yyvsp[0].i;
		}
    break;

  case 68:
#line 780 "ftpcmd.y"
    {
			cmd_type = TYPE_E;
			cmd_form = FORM_N;
		}
    break;

  case 69:
#line 785 "ftpcmd.y"
    {
			cmd_type = TYPE_E;
			cmd_form = yyvsp[0].i;
		}
    break;

  case 70:
#line 790 "ftpcmd.y"
    {
			cmd_type = TYPE_I;
		}
    break;

  case 71:
#line 794 "ftpcmd.y"
    {
			cmd_type = TYPE_L;
			cmd_bytesz = CHAR_BIT;
		}
    break;

  case 72:
#line 799 "ftpcmd.y"
    {
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		}
    break;

  case 73:
#line 805 "ftpcmd.y"
    {
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		}
    break;

  case 74:
#line 813 "ftpcmd.y"
    {
			yyval.i = STRU_F;
		}
    break;

  case 75:
#line 817 "ftpcmd.y"
    {
			yyval.i = STRU_R;
		}
    break;

  case 76:
#line 821 "ftpcmd.y"
    {
			yyval.i = STRU_P;
		}
    break;

  case 77:
#line 828 "ftpcmd.y"
    {
			yyval.i = MODE_S;
		}
    break;

  case 78:
#line 832 "ftpcmd.y"
    {
			yyval.i = MODE_B;
		}
    break;

  case 79:
#line 836 "ftpcmd.y"
    {
			yyval.i = MODE_C;
		}
    break;

  case 80:
#line 843 "ftpcmd.y"
    {
			/*
			 * Problem: this production is used for all pathname
			 * processing, but only gives a 550 error reply.
			 * This is a valid reply in some cases but not in others.
			 */
			if (logged_in && yyvsp[0].s && strchr(yyvsp[0].s, '~') != NULL) {
				glob_t gl;
#ifdef __linux__
				/* see popen.c */
				int flags = GLOB_NOCHECK;
#else
				int flags =
				 GLOB_BRACE|GLOB_NOCHECK|GLOB_QUOTE|GLOB_TILDE;
#endif
				char *pptr = yyvsp[0].s;

				/*
				 * glob() will only find a leading ~, but
				 * Netscape kindly puts a slash in front of
				 * it for publish URLs.  There needs to be
				 * a flag for glob() that expands tildes
				 * anywhere in the string.
				 */
				if ((pptr[0] == '/') && (pptr[1] == '~'))
					pptr++;

				memset(&gl, 0, sizeof(gl));
				if (glob(pptr, flags, NULL, &gl) ||
				    gl.gl_pathc == 0) {
					reply(550, "not found");
					yyval.s = NULL;
				} else {
					yyval.s = strdup(gl.gl_pathv[0]);
				}
				globfree(&gl);
				free(yyvsp[0].s);
			} else
				yyval.s = yyvsp[0].s;
		}
    break;

  case 82:
#line 891 "ftpcmd.y"
    {
			int ret, dec, multby, digit;

			/*
			 * Convert a number that was read as decimal number
			 * to what it would be if it had been read as octal.
			 */
			dec = yyvsp[0].i;
			multby = 1;
			ret = 0;
			while (dec) {
				digit = dec%10;
				if (digit > 7) {
					ret = -1;
					break;
				}
				ret += digit * multby;
				multby *= 8;
				dec /= 10;
			}
			yyval.i = ret;
		}
    break;

  case 83:
#line 918 "ftpcmd.y"
    {
			if (logged_in)
				yyval.i = 1;
			else {
				reply(530, "Please login with USER and PASS.");
				yyval.i = 0;
			}
		}
    break;


    }

/* Line 1010 of yacc.c.  */
#line 2333 "y.tab.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  const char* yyprefix;
	  char *yymsg;
	  int yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 0;

	  yyprefix = ", expecting ";
	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		yysize += yystrlen (yyprefix) + yystrlen (yytname [yyx]);
		yycount += 1;
		if (yycount == 5)
		  {
		    yysize = 0;
		    break;
		  }
	      }
	  yysize += (sizeof ("syntax error, unexpected ")
		     + yystrlen (yytname[yytype]));
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yyprefix = ", expecting ";
		  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			yyp = yystpcpy (yyp, yyprefix);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yyprefix = " or ";
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (yychar == YYEOF)
	     for (;;)
	       {
		 YYPOPSTACK;
		 if (yyssp == yyss)
		   YYABORT;
		 YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
		 yydestruct (yystos[*yyssp], yyvsp);
	       }
        }
      else
	{
	  YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
	  yydestruct (yytoken, &yylval);
	  yychar = YYEMPTY;

	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     yyerrorlab therefore never appears in user code.  */
  if (0)
     goto yyerrorlab;
#endif

  yyvsp -= yylen;
  yyssp -= yylen;
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 928 "ftpcmd.y"


extern jmp_buf errcatch;

#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

struct tab {
	const char	*name;
	short	token;
	short	state;
	short	implemented;	/* 1 if command is implemented */
	const char	*help;
};

struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
	{ "LPRT", LPRT, ARGS, 1,	"<sp> af, hal, h1, h2, h3,..., pal, p1, p2..." },
	{ "EPRT", EPRT, STR1, 1,	"<sp> |af|addr|port|" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "LPSV", LPSV, ARGS, 1,	"(set server in passive mode)" },
	{ "EPSV", EPSV, ARGS, 1,	"[<sp> af|ALL]" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"<sp> offset (restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

static void	 help __P((struct tab *, char *));
static struct tab *
		 lookup __P((struct tab *, char *));
static void	 sizecmd __P((char *));
static int	 yylex __P((void));

static struct tab *lookup(struct tab *p, char *cmd)
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char * ftpd_getline(char *s, int n, FILE *iop)
{
	int c;
	register char *cs;

	cs = s;
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (debug)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(s);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
	while ((c = getc(iop)) != EOF) {
		c &= 0377;
		if (c == IAC) {
		    if ((c = getc(iop)) != EOF) {
			c &= 0377;
			switch (c) {
			case WILL:
			case WONT:
				c = getc(iop);
				printf("%c%c%c", IAC, DONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case DO:
			case DONT:
				c = getc(iop);
				printf("%c%c%c", IAC, WONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		    }
		}
		*cs++ = c;
		if (--n <= 0 || c == '\n')
			break;
	}
	if (c == EOF && cs == s)
		return (NULL);
	*cs++ = '\0';
	if (debug) {
		if (!guest && strncasecmp("pass ", s, 5) == 0) {
			/* Don't syslog passwords */
			syslog(LOG_DEBUG, "command: %.5s ???", s);
		} else {
			register char *cp;
			register int len;

			/* Don't syslog trailing CR-LF */
			len = strlen(s);
			cp = s + len - 1;
			while (cp >= s && (*cp == '\n' || *cp == '\r')) {
				--cp;
				--len;
			}
			syslog(LOG_DEBUG, "command: %.*s", len, s);
		}
	}
	return (s);
}

void toolong(int signo)
{
	(void)signo;

	reply(421,
	    "Timeout (%d seconds): closing control connection.", timeout);
	if (logging)
		syslog(LOG_INFO, "User %s timed out after %d seconds",
		    (pw ? pw -> pw_name : "unknown"), timeout);
	dologout(1);
}

static int yylex(void)
{
	static int cpos, state;
	char *cp, *cp2;
	struct tab *p;
	int n, value;
	char c;

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm((unsigned) timeout);
			if (ftpd_getline(cbuf, sizeof(cbuf)-1, stdin)==NULL) {
				reply(221, "You could at least say goodbye.");
				dologout(0);
			}
			(void) alarm(0);
			if ((cp = strchr(cbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
#ifdef HASSETPROCTITLE
			if (strncasecmp(cbuf, "PASS", 4) != 0) {
				if ((cp = strpbrk(cbuf, "\n"))) {
					c = *cp;
					*cp = '\0';
					setproctitle("%s: %s", proctitle, cbuf);
					*cp = c;
				}
			}
#endif /* HASSETPROCTITLE */
			if ((cp = strpbrk(cbuf, " \n")))
				cpos = cp - cbuf;
			if (cpos == 0)
				cpos = 4;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cbuf);
			p = lookup(cmdtab, cbuf);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = (char *)p->name;  /* XXX */
				return (p->token);
			}
			break;

		case SITECMD:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cbuf;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					state = CMD;
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = (char *) p->name;  /* XXX */
				return (p->token);
			}
			state = CMD;
			break;

		case OSTR:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		case ZSTR1:
		dostr1:
			if (cbuf[cpos] == ' ') {
				cpos++;
				/* DOH!!! who wrote this?
				 * state = ++state; is undefined in C!
				 * state = state == OSTR ? STR2 : ++state;
				 * looks elegant but not correct, adding 'value'
				 */
				value = state == OSTR ? STR2 : ++state;
				state = value;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cbuf[cpos] == '\n') {
				cbuf[cpos] = '\0';
				yylval.s = strdup(cp);
				if (yylval.s == NULL)
					fatal("Ran out of memory.");
				cbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				return (NUMBER);
			}
			if (strncasecmp(&cbuf[cpos], "ALL", 3) == 0
			    && !isalnum(cbuf[cpos + 3])) {
				cpos += 3;
				return ALL;
			}
			switch (cbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return (A);

			case 'B':
			case 'b':
				return (B);

			case 'C':
			case 'c':
				return (C);

			case 'E':
			case 'e':
				return (E);

			case 'F':
			case 'f':
				return (F);

			case 'I':
			case 'i':
				return (I);

			case 'L':
			case 'l':
				return (L);

			case 'N':
			case 'n':
				return (N);

			case 'P':
			case 'p':
				return (P);

			case 'R':
			case 'r':
				return (R);

			case 'S':
			case 's':
				return (S);

			case 'T':
			case 't':
				return (T);

			}
			break;

		default:
			fatal("Unknown state in scanner.");
		}
		yyerror((char *) 0);
		state = CMD;
		longjmp(errcatch,0);
	}
}

void upper(char *s)
{
	while (*s != '\0') {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

static void help(struct tab *ctab, char *s)
{
	struct tab *c;
	int width, NCMDS;
	const char *type;

	if (ctab == sitetab)
		type = "SITE ";
	else
		type = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		int i, j, w;
		int columns, lines;

		lreply(214, "The following %scommands are recognized %s.",
		    type, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			printf("   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				printf("%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					putchar(' ');
					w++;
				}
			}
			printf("\r\n");
		}
		(void) fflush(stdout);
		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == (struct tab *)0) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", type, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", type, width,
		    c->name, c->help);
}

static void sizecmd(char *filename)
{
	switch (type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(filename, &stbuf) < 0 || !S_ISREG(stbuf.st_mode))
			reply(550, "%s: not a plain file.", filename);
		else
			reply(213, "%qu", (quad_t) stbuf.st_size);
		break; }
	case TYPE_A: {
		FILE *fin;
		int c;
		off_t count;
		struct stat stbuf;
		fin = fopen(filename, "r");
		if (fin == NULL) {
			perror_reply(550, filename);
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0 || !S_ISREG(stbuf.st_mode)) {
			reply(550, "%s: not a plain file.", filename);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, "%qd", (quad_t) count);
		break; }
	default:
		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
	}
}


