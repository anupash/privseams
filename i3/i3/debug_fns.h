#ifndef I3_DEBUG_FNS_H
#define I3_DEBUG_FNS_H 1


/**
 *  This macro is used to terminate the program when some fatal error
 *  occurs.
 */
#define EXIT_ON_ERROR   exit(-1)

//#define I3_DEBUG


#	ifndef I3_PRINT_DEBUG
#		if !defined(_WIN32) || defined(__CYGWIN__)
#			ifdef DEBUG_ENABLED
			/**
   			 * This macro is used to print debugging information. 
			 * The message is printed only if the current debugging level is
			 * greater than that of the level specified in the macro call.
			 */

#				define I3_PRINT_DEBUG(debugLevel, msg, ... )  if(debugLevel <= I3_CURRENT_DEBUG_LEVEL) { printf("[Line:%d in file:%s] ", __LINE__, __FILE__); printf(msg, ##__VA_ARGS__);}

#			else 

#				define I3_PRINT_DEBUG(debugLevel, msg, ... ) 

#			endif //DEBUG_ENABLED

#			define I3_PRINT_DEBUG0	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG1	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG2	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG3	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG4	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG5	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG6	I3_PRINT_DEBUG
#			define I3_PRINT_DEBUG7	I3_PRINT_DEBUG

#		else
		// stg: the MS compiler will support variadic macros only from version 7 on. Until then, we will have to live with warnings about too few arguments to this macro
		#define I3_PRINT_DEBUG0(debugLevel, msg) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG1(debugLevel, msg, arg1) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG2(debugLevel, msg, arg1, arg2) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG3(debugLevel, msg, arg1, arg2, arg3) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG4(debugLevel, msg, arg1, arg2, arg3, arg4) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG5(debugLevel, msg, arg1, arg2, arg3, arg4, arg5) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG6(debugLevel, msg, arg1, arg2, arg3, arg4, arg5, arg6) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5, arg6);fflush(i3DebugFD);}
		#define I3_PRINT_DEBUG7(debugLevel, msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7) if (debugLevel <= I3_CURRENT_DEBUG_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7);fflush(i3DebugFD);}
		//#define I3_PRINT_DEBUG(debugLevel, msg)
#endif
#endif  //I3_PRINT_DEBUG

/**
  * This macro is used to print messages irrespective of debug level.
  * These are messages are not for debugging, but for giving information
  * to the user.
  */
#	ifndef I3_PRINT_INFO
#		if !defined(_WIN32) || defined(__CYGWIN__)
#			define I3_PRINT_INFO(infoLevel, msg, ...) if(infoLevel <= I3_CURRENT_INFO_LEVEL) printf(msg, ##__VA_ARGS__)

#			define I3_PRINT_INFO0	I3_PRINT_INFO
#			define I3_PRINT_INFO1	I3_PRINT_INFO
#			define I3_PRINT_INFO2	I3_PRINT_INFO
#			define I3_PRINT_INFO3	I3_PRINT_INFO
#			define I3_PRINT_INFO4	I3_PRINT_INFO
#			define I3_PRINT_INFO5	I3_PRINT_INFO
#			define I3_PRINT_INFO6	I3_PRINT_INFO
#			define I3_PRINT_INFO7	I3_PRINT_INFO

#		else
			// stg: the MS compiler will support variadic macros only from version 7 on. Until then, we will have to live with warnings about too few arguments to this macro
//#			define I3_PRINT_INFO(infoLevel, msg)
#			define I3_PRINT_INFO0(infoLevel, msg) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg);fflush(i3DebugFD);}
#			define I3_PRINT_INFO1(infoLevel, msg, arg1) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1);fflush(i3DebugFD);}
#			define I3_PRINT_INFO2(infoLevel, msg, arg1, arg2) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2);fflush(i3DebugFD);}
#			define I3_PRINT_INFO3(infoLevel, msg, arg1, arg2, arg3) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3);fflush(i3DebugFD);}
#			define I3_PRINT_INFO4(infoLevel, msg, arg1, arg2, arg3, arg4) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4);fflush(i3DebugFD);}
#			define I3_PRINT_INFO5(infoLevel, msg, arg1, arg2, arg3, arg4, arg5) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5);fflush(i3DebugFD);}
#			define I3_PRINT_INFO6(infoLevel, msg, arg1, arg2, arg3, arg4, arg5, arg6) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5, arg6);fflush(i3DebugFD);}
#			define I3_PRINT_INFO7(infoLevel, msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7) if (infoLevel <= I3_CURRENT_INFO_LEVEL) {fprintf (i3DebugFD, msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7);fflush(i3DebugFD);}
#		endif
#endif //I3_PRINT_INFO


#endif
