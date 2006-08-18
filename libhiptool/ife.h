#ifndef _HIP_IFE
#define _HIP_IFE


/*
 * HIP IFE-macros.
 *
 */

#define GOTO_OUT -3

#define HIP_IFE(func, eval) \
{ \
	if (func) { \
		err = eval; \
		goto out_err; \
	} \
}

#define HIP_IFEL(func, eval, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
		goto out_err; \
	} \
}

#define HIP_IFEB(func, eval, finally) \
{ \
	if (func) { \
		err = eval; \
                finally;\
		goto out_err; \
	} else {\
		finally;\
        }\
}

#define HIP_IFEBL(func, eval, finally, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
                finally;\
		goto out_err; \
	} else {\
		finally;\
        }\
}

#define HIP_IFEBL2(func, eval, finally, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
                finally;\
        }\
}

/* HIP_IFCS takes a pointer and an command to execute.
   it executes the command exec if cond != NULL */ 
#define HIP_IFCS(condition, consequence)\
	 if( condition ) {	\
	 	consequence ; 						\
	 } else {							\
	 	HIP_ERROR("No state information found.\n");		\
	 }

#endif /* _HIP_IFE */

