#!/bin/sh -xv
# This script allows for building binary and source debian packages

# XX FIXME: ADD OPP + RVS OPTIONS

#Default debian package is BINARY
TYPE=binary

MAJOR=1
MINOR=0
VERSION="$MAJOR.$MINOR"
RELEASE=1
SUFFIX="-$VERSION-$RELEASE"
NAME=hipl
NAMEGPL=libhiptool
DEBIAN=i386/DEBIAN
CORPORATE=
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}-${VERSION}-deb
PKGDIR_SRC=$PKGROOT/${NAME}-${VERSION}-deb-src
SRCDIR=${PKGDIR_SRC}/${NAME}-${VERSION}
HIPL=$PWD
PKGNAME="${NAME}-${VERSION}-${RELEASE}-i386.deb"

PKGDIRGPL=$PKGROOT/${NAMEGPL}-${VERSION}-deb
PKGNAMEGPL="${NAMEGPL}-${VERSION}-${RELEASE}-i386.deb"

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
	cp $DEBIAN/$f "$PKGDIRGPL/DEBIAN"
	done
	
	echo "** Copying binary files to '$PKGDIRGPL'"
	mkdir -p "$PKGDIRGPL/usr"
	cd "$PKGDIRGPL"
	
	# create directory structure
	mkdir -p usr/lib
	cd "$HIPL"
	
	for suffix in a so so.0 so.0.0.0;do
	cp -d libinet6/.libs/libinet6.$suffix $PKGDIRGPL/usr/lib/
	done
	cp -L libinet6/.libs/libinet6.la $PKGDIRGPL/usr/lib/
	
	set +e
}

# copy files
copy_files ()
{
    echo "** Copying Debian control files to '$PKGDIR/DEBIAN'"
    
    set -e
    mkdir -p "$PKGDIR/DEBIAN"
    for f in control changelog copyright postinst prerm;do
	cp $DEBIAN/$f "$PKGDIR/DEBIAN"
    done
    
    echo "** Copying binary files to '$PKGDIR'"
    mkdir -p "$PKGDIR/usr"
    cd "$PKGDIR"

    # create directory structure
    mkdir -p usr/sbin usr/bin usr/lib etc/hip usr/share/doc etc/init.d
    cd "$HIPL"
    
    cp hipd/hipd $PKGDIR/usr/sbin/

    cp tools/hipconf $PKGDIR/usr/sbin/
    cp agent/hipagent $PKGDIR/usr/sbin/

    for suffix in "" -gai -native -native-user-key;do
	cp test/conntest-client$suffix $PKGDIR/usr/bin/
    done
    for suffix in "" -native;do
	cp test/conntest-server$suffix $PKGDIR/usr/bin/
    done
    cp test/hipsetup $PKGDIR/usr/sbin/
    for suffix in a so so.0 so.0.0.0;do
	if [ ! $CORPORATE ];then
		cp -d libinet6/.libs/libinet6.$suffix $PKGDIR/usr/lib/
	fi
	cp -d libhiptool/.libs/libhiptool.$suffix $PKGDIR/usr/lib/
	cp -d libopphip/.libs/libopphip.$suffix $PKGDIR/usr/lib/
	cp -d opendht/.libs/libhipopendht.$suffix $PKGDIR/usr/lib/
    done
	if [ ! $CORPORATE ];then
	    cp -L libinet6/.libs/libinet6.la $PKGDIR/usr/lib/
	fi
    cp -L libhiptool/.libs/libhiptool.la $PKGDIR/usr/lib/
    cp -L libopphip/.libs/libopphip.la $PKGDIR/usr/lib/
    cp -L opendht/.libs/libhipopendht.la $PKGDIR/usr/lib/
    
    cp -d libhipgui/libhipgui.a $PKGDIR/usr/lib/


    echo "** Copying init.d script to $PKGDIR"
    cp test/packaging/debian-init.d-hipd $PKGDIR/etc/init.d/hipd
    
    echo "** Copying documentation to '$PKGDIR'"
    cd "$HIPL/doc"
    DOCDIR_PREFIX=$PKGDIR/usr/share/doc make -e install
    set +e
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
usage: $0 [-b] | [-s] | [-a]
b=binary, s=source, a=armel
default: ${TYPE}
EOF
}


parse_args() {
    OPTIND=1
    while [ $# -ge  $OPTIND ]
      do
      getopts abchs N "$@"
      
      case $N in
	    a) TYPE=binary
               DEBIAN=armel/DEBIAN
		PKGNAME="${NAME}-${VERSION}-${RELEASE}-armel.deb" ;;

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

######## "Main" function ###################################################

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

	if [ $CORPORATE = 1 ];then
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

    cd "$HIPL"

    echo "** Running make in $HIPL"
    if ! make;then
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
    if ! copy_files;then
	echo "** Error: unable to copy files, exiting"
	exit 1
    fi

	cd "$PKGROOT"
	if [ $CORPORATE = 1 ];then
		if ! copy_files_gpl;then
		echo "** Error: unable to copy GPL files, exiting"
		exit 1
		fi
	fi

	cd "$PKGROOT"
	if dpkg-deb -b "$PKGDIRGPL" "$PKGNAMEGPL";then
	echo "** Successfully finished building the binary GPL Debian package"
	else
	echo "** Error!"
	echo "** Error: Unable to build the binary GPL Debian package!"
	echo "** Error!"
	fi

	cd "$PKGROOT"
	echo "** Creating the Debian package '$PKGNAME'"
    if dpkg-deb -b "$PKGDIR" "$PKGNAME";then
	echo "** Successfully finished building the binary Debian package"
	echo "** The debian packages is located in $PKGROOT/$PKGNAME"
	echo "** The package can now be installed with dpkg -i $PKGNAME"
    else
	echo "** Error: unable to build package, exiting"
	error_cleanup
	exit 1
    fi
    rm -rf ${PKGDIR}
else
# $TYPE == "source
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
    if dpkg-source -b "${NAME}-${VERSION}";then

	rm -rf "${NAME}-${VERSION}"

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
