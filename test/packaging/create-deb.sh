#!/bin/sh -xv
# This script allows for building binary and source debian packages

#Default debian package is BINARY
TYPE=binary

MAJOR=1
MINOR=0
VERSION="$MAJOR.$MINOR"
RELEASE=3
SUFFIX="-$VERSION-$RELEASE"
NAME=hipl
NAMEGPL=libhiptool

DEBARCH="i386"
if uname -m|grep x86_64; then DEBARCH=amd64; fi
# if uname -m|grep arm*; then DEBARCH=armel; fi 
if dpkg --print-architecture|grep armel;then DEBARCH=armel;fi

DEBIAN=${DEBARCH}/DEBIAN

DEBIANGPL=$DEBARCH/DEBIAN-hiptool
CORPORATE=
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}${SUFFIX}-deb
PKGDIR_SRC=$PKGROOT/${NAME}${SUFFIX}-deb-src
SRCDIR=${PKGDIR_SRC}/${NAME}${SUFFIX}
HIPL=$PWD

POSTFIX="deb"
TMPNAME="${VERSION}-${RELEASE}-${DEBARCH}"
if dpkg --print-architecture|grep armel;then TMPNAME="${VERSION}-${RELEASE}-armel"; fi
PKGNAME="${NAME}-${TMPNAME}.${POSTFIX}"
TMP=""
DEBLIB="$NAME-$TMP"

LINE0="Depends:"
LINE1="Build-Depends:"
LINE2="Package:"
LINE3="Architecture:"

PKGDIRGPL=$PKGROOT/${NAMEGPL}-${VERSION}-deb
PKGNAMEGPL="${NAMEGPL}-${VERSION}-${RELEASE}-${DEBARCH}.deb"

# copy the tarball from the HIPL directory
copy_tarball ()
{
	set -e
	
	echo "** Copying the tarball"
	#cd ${PKGDIR}
	cp ${HIPL}/hipl-main.tar.gz ${PKGDIR_SRC}/${NAME}_${VERSION}.orig.tar.gz
	
	echo "** Copying Debian control files to '${SRCDIR}/debian'"
	mkdir -p "${SRCDIR}/debian"
	cp ${PKGROOT}/$DEBIAN/control-src ${SRCDIR}/debian/control
	for f in changelog copyright;do
	cp ${PKGROOT}/$DEBIAN/$f "${SRCDIR}/debian"
	done
	
	set +e
}

# copy GPL files when building corporate packages
copy_files_gpl()
{
	echo "** Copying Debian control files to '$PKGDIRGPL/DEBIAN'"
	
	set -e
	mkdir -p "$PKGDIRGPL/DEBIAN"
	for f in control changelog copyright postinst prerm;do
	cp $DEBIANGPL/$f "$PKGDIRGPL/DEBIAN"
	done
	
	echo "** Copying binary files to '$PKGDIRGPL'"
	mkdir -p "$PKGDIRGPL/usr"
	cd "$PKGDIRGPL"
	
	# create directory structure
	mkdir -p usr/lib
	cd "$HIPL"
	
	for suffix in a so so.0 so.0.0.0;do
	cp -d libhiptool/.libs/libhiptool.$suffix $PKGDIRGPL/usr/lib/
	done
	cp -L libhiptool/.libs/libhiptool.la $PKGDIRGPL/usr/lib/
	
	set +e
}

init_files ()
{
    echo "** Copying Debian control files to '$PKGDIR/DEBIAN'"
    set -e
    mkdir -p "$PKGDIR/DEBIAN"
    
    if [ $TMP = "core" ]; then
    	for f in control changelog copyright postinst prerm;do
		cp $DEBIAN/$f "$PKGDIR/DEBIAN" 
    	done
    else
	for f in control changelog copyright;do
		cp $DEBIAN/$f "$PKGDIR/DEBIAN" 
    	done
    fi

    echo "** Modifying Debian control file for $DEBLIB $TMP and $DEBARCH"
    
    if [ "$DEBLIB" = "" ]; then
     sed -i '/'"$LINE0"'/d' $PKGDIR\/DEBIAN\/control
    else
     sed -i '/'"$LINE1"'/a\'"$LINE0"' '"$DEBLIB"'' $PKGDIR\/DEBIAN\/control
    fi

    sed -i '/'"$LINE2"'/ s/.*/&\-'"$TMP"'/' $PKGDIR\/DEBIAN\/control
    sed -i 's/"$LINE3"/&'" $DEBARCH"'/' $PKGDIR\/DEBIAN\/control

    # cp $PKGDIR/DEBIAN/control $PKGROOT/control-$TMP
   
}

# copy and build package files
copy_and_package_files ()
{
    echo "copying and packaging files"

    TMP="lib"
    DEBLIB=""
    init_files;
    
    echo "** Copying library files to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"
   
    echo "$PKGDIR"

    mkdir -p usr/lib

    cd "$HIPL"
    
    echo "$HIPL"

    for suffix in a so so.0 so.0.0.0;do
	cp -d libinet6/.libs/libinet6.$suffix $PKGDIR/usr/lib/
	if [ ! $CORPORATE ];then
		cp -d libhiptool/.libs/libhiptool.$suffix $PKGDIR/usr/lib/
	fi
	cp -d libopphip/.libs/libopphip.$suffix $PKGDIR/usr/lib/
	cp -d opendht/.libs/libhipopendht.$suffix $PKGDIR/usr/lib/
    done

    cp -L libinet6/.libs/libinet6.la $PKGDIR/usr/lib/
	if [ ! $CORPORATE ];then
	    cp -L libhiptool/.libs/libhiptool.la $PKGDIR/usr/lib/
	fi
   
    cp -L libopphip/.libs/libopphip.la $PKGDIR/usr/lib/
    
    cp -L opendht/.libs/libhipopendht.la $PKGDIR/usr/lib/
    
    cp -d libhipgui/libhipgui.a $PKGDIR/usr/lib/

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="core"
    #hipl-core hipd: depends on hipl-lib
    DEBLIB="$NAME-lib"
    init_files;
    
    echo "** Copying binary files to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    echo "$PKGDIR"

    # create directory structure
    # mkdir -p usr/sbin usr/bin usr/lib etc/hip usr/share/doc etc/init.d
    mkdir -p usr/sbin usr/bin etc/init.d etc/hip
    cd "$HIPL"
    
    echo "$HIPL"

    cp hipd/hipd $PKGDIR/usr/sbin/
    echo "** Copying init.d script to $PKGDIR"
    cp test/packaging/debian-init.d-hipd $PKGDIR/etc/init.d/hipd
    
    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
    
    TMP="firewall"
    DEBLIB="$NAME-lib"
    init_files;
    
    echo "** Making directory to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    mkdir -p usr/sbin
    cd "$HIPL"

    echo "** Copying firewall to $PKGDIR"
    cp firewall/firewall $PKGDIR/usr/sbin/

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="tools"
    #hipl-tools (depends on hipl-lib and hipl-core)
    DEBLIB="$NAME-lib, $NAME-core"
    init_files;

    echo "** Making directory to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    mkdir -p usr/sbin usr/bin

    cd "$HIPL"

    cp tools/hipconf $PKGDIR/usr/sbin/
    cp tools/myasn.py $PKGDIR/usr/bin/
    cp tools/parse-key-3.py $PKGDIR/usr/bin/
    cp tools/dnsproxy.py $PKGDIR/usr/bin/
    cp tools/hosts.py $PKGDIR/usr/bin/
    cp tools/pyip6.py $PKGDIR/usr/bin/
    cp tools/util.py $PKGDIR/usr/bin/

    chmod ugo+rx $PKGDIR/usr/bin/*.py

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
   
    TMP="test"
    DEBLIB="$NAME-lib, $NAME-core"
    init_files;
    
    echo "** Making directory to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    mkdir -p usr/bin usr/sbin
    cd "$HIPL"

    for suffix in "" -gai -native -native-user-key;do
	cp test/conntest-client$suffix $PKGDIR/usr/bin/
    done

    for suffix in "" -native;do
	cp test/conntest-server$suffix $PKGDIR/usr/bin/
    done

    cp test/hipsetup $PKGDIR/usr/sbin/

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="agent"
    DEBLIB="$NAME-lib, $NAME-core"
    init_files;

    echo "** Making directory to '$PKGDIR'"
    #mkdir -p "$PKGDIR/usr"
    #cd "$PKGDIR"

    mkdir -p "$PKGDIR/usr"
    mkdir -p "$PKGDIR/usr/sbin"
    mkdir -p "$PKGDIR/usr/lib"
    mkdir -p "$PKGDIR/usr/share"
    mkdir -p "$PKGDIR/usr/share/hipl"
    mkdir -p "$PKGDIR/usr/share/hipl/libhipgui"
    mkdir -p "$PKGDIR/usr/share/menu"
    mkdir -p "$PKGDIR/usr/share/pixmaps"
    mkdir -p "$PKGDIR/usr/share/applications"
    mkdir -p "$PKGDIR/etc"
    mkdir -p "$PKGDIR/etc/xdg"
    mkdir -p "$PKGDIR/etc/xdg/autostart"

    #mkdir -p usr/sbin
    
    cd "$HIPL"

    echo "** Copying hipagent to '$PKGDIR'"
    cp agent/hipagent $PKGDIR/usr/sbin/

    cp -d libhipgui/hipmanager.png $PKGDIR/usr/share/pixmaps/hipmanager.png

    set +e

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
  
    TMP="doc"
    DEBLIB=""
    init_files;

    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    if [ $DEBARCH != "armel" ]; then

    	mkdir -p usr/share/doc
    	#cd "$HIPL"

    	echo "** Copying documentation to '$PKGDIR'"
    	cd "$HIPL/doc"
    	DOCDIR_PREFIX=$PKGDIR/usr/share/doc make -e install
    	set +e
    
    	PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    	create_sub_package;
    fi

}


error_cleanup()
{
    if [ -n "$PKGDIR" -a -d "$PKGDIR" ];then
	echo "** Removing '$PKGDIR'"
	if ! rm -rf "$PKGDIR";then
	    echo "** Warning: Some error occurred while removing directory '$PKGDIR'"
	fi
    fi
}

create_sub_package()
{

    echo "** Creating the Debian package '$PKGNAME'"
    cd "$PKGROOT"
    if dpkg-deb -b "$PKGDIR" "$PKGNAME";then
	echo "** Successfully finished building the binary Debian package"
	echo "** The debian packages is located in $PKGROOT/$PKGNAME"
	echo "** The package can now be installed with dpkg -i $PKGROOT/$PKGNAME"
    else
	echo "** Error: unable to build package, exiting"
	error_cleanup
	exit 1
    fi

    rm -rf ${PKGDIR}
}

error_cleanup_src()
{
    if [ -n "$PKGDIR_SRC" -a -d "$PKGDIR_SRC" ];then
	echo "** Removing '$PKGDIR'"
	if ! rm -rf "$PKGDIR";then
	    echo "** Warning: Some error occurred while removing directory '$PKGDIR_SRC'"
	fi
    fi
}

die() {
    echo "$0: $@"
    exit 1
}

help() {
cat <<EOF
#usage: $0 [-b] | [-s] | [-a]
#b=binary, s=source, a=armel
usage: $0 [-b] | [-s]
b=binary, s=source
default: ${TYPE}
EOF
}


parse_args() {
    OPTIND=1
    while [ $# -ge  $OPTIND ]
      do
      getopts abchs N "$@"
      
      case $N in
	#    a) TYPE=binary
        #     	DEBIAN=armel/DEBIAN
	#	PKGNAME="${NAME}-${VERSION}-${RELEASE}-armel.deb" ;;

            b) TYPE=binary    
               	GIVEN=${GIVEN}+1 ;;

            s) TYPE=source ;;

            # XX FIXME!!!
	    c) TYPE=binary
	       GIVEN=${GIVEN}+1
	       CORPORATE=1 ;;

            h) help; exit 0 ;;

            *) help
               die "bad args" ;;
        esac
    done
}

######################## "Main" function #############################

parse_args $@

echo "** Creating the directory structure and files for building the"
echo "** binary Debian package containing HIPL user space software"
echo "**"
echo "** Building: Version $VERSION (release $RELEASE)"
echo "**"

echo "** Using directory '$HIPL' as the HIPL installation directory"
echo "** Package building root is '$PKGROOT'" 
echo "** Temporary Debian package root is '$PKGDIR'" 

if [ ! -d "$HIPL" ];then
  echo "** Error: '$HIPL' is not a directory, exiting"
  exit 1
fi

if [ $TYPE = "binary" ];then
# Binary Debian Package
# First compile all programs
    echo "** Compiling user space software"
    echo "**"

	if [ $CORPORATE ];then
		echo "** Must do make install for libhiptool to be able to make hipl"
		echo "** (note: only when compiling libhiptool as dynamically linked)"
	    echo "** Running make in $HIPL/libhiptool"
		cd "$HIPL/libhiptool"
		if ! make;then
			echo "** Error while running make in $HIPL/libhiptool, exiting"
			exit 1
		fi
		if ! sudo make install;then
			echo "** Error while running make install in $HIPL/libhiptool, exiting"
			exit 1
		fi
	fi

    # jk: do not re-configure as it messes up any configs we might need.
    cd "$HIPL"
    #echo "** Running make in $HIPL"
    #./autogen.sh
    #./configure --prefix=/usr
    #echo "** Running make in $HIPL"
    #if ! make clean all;then
    echo "** Running make in $HIPL"
    if ! make all;then
    	echo "** Error while running make in $HIPL, exiting"
    	exit 1
    fi
    echo "** Compilation was successful"
    echo "**"

	cd "$PKGROOT"
    if [ -d "$PKGDIR" ];then
	if ! rm -rf "$PKGDIR";then
	    echo "** Error: unable to remove directory '$PKGDIR', exiting"
	    exit 1
	fi
    fi
	cd "$PKGROOT"
    if [ -d "$PKGDIRGPL" ];then
	if ! rm -rf "$PKGDIRGPL";then
	    echo "** Error: unable to remove directory '$PKGDIRGPL', exiting"
	    exit 1
	fi
    fi

    if ! mkdir "$PKGDIR";then
	echo "** Error: unable to create directory '$PKGDIR', exiting"
	exit 1
    fi

    if ! mkdir "$PKGDIRGPL";then
	echo "** Error: unable to create directory '$PKGDIRGPL', exiting"
	exit 1
    fi

    cd "$PKGROOT"
    if ! copy_and_package_files;then
	echo "** Error: unable to copy files, exiting"
	exit 1
    fi

    cd "$PKGROOT"
    	if [ $CORPORATE = 1 ];then
    		if ! copy_files_gpl;then
    		echo "** Error: unable to copy GPL files, exiting"
    		exit 1
    		fi
	
    		cd "$PKGROOT"
    		if dpkg-deb -b "$PKGDIRGPL" "$PKGNAMEGPL";then
    		echo "** Successfully finished building the binary GPL Debian package"
    		else
		echo "** Error!"
		echo "** Error: Unable to build the binary GPL Debian package!"
		echo "** Error!"
		exit 1
		fi
	fi
fi

if [ $TYPE = "source" ];then
# Debian SOURCE package

    if ! mkdir -p "$PKGDIR_SRC";then
	echo "** Error: unable to create directory '$PKGDIR_SRC', exiting"
	exit 1
    fi

    cd "$HIPL"

    echo "** Running make dist in $HIPL"
    if ! make dist;then
	echo "** Error while running 'make dist' in $HIPL, exiting"
	exit 1
    fi
    echo "** Tarball was successfully created"
    echo "**"

    if ! copy_tarball;then
	echo "** Error: unable to copy tarball, exiting"
	error_cleanup_source
	exit 1
    fi

    echo "** Creating the Debian Source package of $PKGDIR"
    cd "${PKGDIR_SRC}"
    

    if dpkg-source -b "${NAME}${SUFFIX}";then

	rm -rf "${NAME}${SUFFIX}"

	echo "** Successfully finished building the source Debian package"
	echo "** The debian packages are located in $PKGDIR_SRC"
	echo "** and they are named:"
	echo "${NAME}-${VERSION}.diff.gz"
	echo "${NAME}-${VERSION}.dsc"
 	echo "${NAME}-${VERSION}.orig.tar.gz"
    else
	echo "** Error: unable to build package, exiting"
	rm -rf "${PKGDIR_SRC}"
	exit 1
    fi
fi

exit 0

