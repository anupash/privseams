#!/bin/bash -u




function find_verbous_decls () {
	TAG_FILE=$1
	TEMPFILE=$2
	grep -vE '(djbdns|daemonto|libdht|hipsock|static)' $TAG_FILE  | cut -f 1 | sort -u | while read SYM
	do
		DEF_FILES="$(cscope -R -L -1 "${SYM}" | cut -d ' ' -f 1 | sort -u | cut -d "." -f1)"
		if [ "${DEF_FILES}" ]
		then
			DEF_FILE_FILTER="$(echo -n "${DEF_FILES}" | tr '\n' '|')|/usr/include"
			REF_FILES="$(cscope -R -L -0 "${SYM}" | cut -d ' ' -f 1 | sort -u | egrep -v "${DEF_FILE_FILTER}")"
			if [ "$REF_FILES" = "" ]
			then
				echo $DEF_FILES | while read DEF
					do
						echo "$DEF.h : $SYM" >> $TEMPFILE
						echo "$DEF.h : $SYM" 
					done
			fi
		fi
	done
}


#Check for cscopet
if which cscope >/dev/null; then
    echo "GOOD: cscope found"
else
    echo "ERROR: cscope  NOT found! Install cscope"
    exit
fi





echo "Creating cscope file"
find . \( -name "*".hh -or -name "*".h -or -name "*".hxx -or -name "*".H -or -name "*".C -or -name "*".cxx -or -name "*".c -or -name "*".cc \) -type f -print | grep -v {arch}> cscope.files

rm -f cscope.out 
cscope -bR

echo "Searching for unused declarations"
TEMPFILE=$(mktemp)
find_verbous_decls searchtags_local_headers $TEMPFILE 

grep -vE "android|libinet6|i3|_H$" $TEMPFILE | sort -u >| verbose-headers.txt

