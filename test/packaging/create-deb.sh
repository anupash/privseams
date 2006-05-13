#!/bin/sh
# This script allows for building binary and source debian packages

#Default debian package is BINARY
TYPE=binary

MAJOR=1
MINOR=0
VERSION="$MAJOR.$MINOR"
RELEASE=1
SUFFIX="-$VERSION-$RELEASE"
NAME=hipl
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}-${VERSION}-deb
PKGDIR_SRC=$PKGROOT/${NAME}-${VERSION}-deb-src
SRCDIR=${PKGDIR_SRC}/${NAME}-${VERSION}
HIPL=$PWD
PKGNAME="${NAME}-${VERSION}-${RELEASE}-i386.deb"

# copy the tarball from the HIPL directory
copy_tarball ()
{
 set -e

 echo "** Copying the tarball"
 #cd ${PKGDIR}
 cp ${HIPL}/hipl-main.tar.gz ${PKGDIR_SRC}/${NAME}_${VERSION}.orig.tar.gz
 
 echo "** Copying Debian control files to '${SRCDIR}/debian'"
 mkdir -p "${SRCDIR}/debian"
 cp ${PKGROOT}/DEBIAN/control-src ${SRCDIR}/debian/control
 for f in changelog copyright;do
     cp ${PKGROOT}/DEBIAN/$f "${SRCDIR}/debian"
 done

 set +e
}

# copy files
copy_files ()
{
 echo "** Copying Debian control files to '$PKGDIR/DEBIAN'"

 set -e
 mkdir -p "$PKGDIR/DEBIAN"
 for f in control changelog copyright postinst prerm;do
   cp DEBIAN/$f "$PKGDIR/DEBIAN"
 done

 echo "** Copying binary files to '$PKGDIR'"
 mkdir -p "$PKGDIR/usr"
 cd "$PKGDIR"
 # create directory structure
 mkdir -p usr/sbin usr/bin usr/lib etc/hip /usr/share/doc
 cd "$HIPL"

 cp tools/hipconf $PKGDIR/usr/sbin/
 for suffix in "" -gai -native -native-user-key;do
   cp test/conntest-client$suffix $PKGDIR/usr/bin/
 done
 for suffix in "" -legacy -native;do
   cp test/conntest-server$suffix $PKGDIR/usr/bin/
 done
 cp test/hipsetup $PKGDIR/usr/sbin/
 for suffix in a so so.0 so.0.0.0;do
   cp -d libinet6/.libs/libinet6.$suffix $PKGDIR/usr/lib/
 done
 cp -L libinet6/.libs/libinet6.la $PKGDIR/usr/lib/

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
usage: $0 [-b] | [-s]
b=binary, s=source
default: ${TYPE}
EOF
}


parse_args() {
    OPTIND=1
    while [ $# -ge  $OPTIND ]
      do
      getopts bsh N "$@"
      
      case $N in
            b) TYPE=binary    
               GIVEN=${GIVEN}+1;;
            s) TYPE=source    ;;
            h) help; exit 0      ;;
            *) help
               die "bad args"    ;;
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

if [ $TYPE == "binary" ];then
# Binary Debian Package
# First compile all programs
    echo "** Compiling user space software"
    echo "**"
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

    if ! mkdir "$PKGDIR";then
	echo "** Error: unable to create directory '$PKGDIR', exiting"
	exit 1
    fi

    if ! copy_files;then
	echo "** Error: unable to copy files, exiting"
	exit 1
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
	echo "** The debian packages are located in $PKGDIR"
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
