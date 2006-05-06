#!/bin/sh

# Diego: XX FIXME: how to handle source package building?

MAJOR=1
MINOR=0
VERSION="$MAJOR.$MINOR"
RELEASE=1
SUFFIX="-$VERSION-$RELEASE"
NAME=hipl
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}-$VERSION-deb
HIPL=$PWD

error_cleanup()
{
 if [ -n "$PKGDIR" -a -d "$PKGDIR" ];then
   #echo "** Removing '$PKGDIR'"
   if ! rm -rf "$PKGDIR";then
     echo "** Warning: Some error occurred while removing directory '$PKGDIR'"
   fi
 fi
}

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

# copy files
copy_files ()
{
 echo "** Copying Debian control files to '$PKGDIR/DEBIAN'"

 set -e
 mkdir "$PKGDIR/DEBIAN"
 for f in control postinst prerm;do
   cp DEBIAN/$f "$PKGDIR/DEBIAN"
 done

 echo "** Copying binary files to '$PKGDIR'"
 cd "$PKGDIR/CONTENTS"
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

if ! copy_files;then
  echo "** Error: unable to copy files, exiting"
  exit 1
fi

cd "$PKGROOT"
PKGNAME="${NAME}_${VERSION}-${RELEASE}_i386.deb"
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

exit 0
