#!/bin/sh

MAJOR=1
MINOR=0
RELEASE=1
VERSION="$MAJOR.$MINOR"
SUFFIX="-$VERSION.$RELEASE"
NAME=hipl
PKGROOT=$PWD
HIPL=$PWD/..
PKGDIR=$PKGROOT/${NAME}$SUFFIX

error_cleanup()
{
 if [ -n "$PKGDIR" -a -d "$PKGDIR" ];then
   echo "removing '$PKGDIR'"
   rm -rf "$PKGDIR"
 fi
}

echo <<EOF
** Creating the directory structure and files for building the
** source package needed for RPM package containing HIPL
** user space software
**
** Version $VERSION (release $RELEASE)
**
EOF

echo "** Using directory '$HIPL' as the HIPL installation directory"

if [ ! -d "$HIPL" ];then
  echo "** Error: '$HIPL' is not a directory" 
  exit 1
fi

make dist

#echo "** Package building root is '$PKGROOT'" 
tar xzf ${NAME}-main.tar.gz
find ${NAME}-main -name '.arch*' | xargs rm -rf
mv -v ${NAME}-main $PKGDIR

echo "** Creating source package $PKGROOT/${NAME}${SUFFIX}.tar.gz"
tar czf $PKGROOT/hipl${SUFFIX}.tar.gz ${NAME}$SUFFIX
ls -l $PKGROOT/hipl${SUFFIX}.tar.gz

cat <<EOF

*** Now, execute the following commands as root:

mv -f $PKGROOT/hipl${SUFFIX}.tar.gz /usr/src/redhat/SOURCES
rpmbuild -ba $PKGROOT/test/packaging/hipl.spec


*** The RPMs can be found from /usr/src/redhat/ SRPMS and RPMS
EOF

error_cleanup
