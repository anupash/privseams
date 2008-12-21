#!/bin/sh -xv

# XX FIXME: read major, minor and release from spec file

MAJOR=1
MINOR=0
RELEASE=4
VERSION="$MAJOR.$MINOR"
SUFFIX="-$VERSION.$RELEASE"
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/test/packaging
PKGDIR=$PKGROOT/${NAME}$SUFFIX
DEBDIR=/usr/src/debian
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUDO=sudo


die()
{
    echo $@
    exit 1
}

build_rpm()
{
    test -e ~/.rpmmacros && die "Move ~/.rpmmacros out of the way"
    # The RPMs can be found from /usr/src/redhat/ SRPMS and RPMS
    $SUDO mv -f $PKGROOT/hipl${SUFFIX}.tar.gz /usr/src/redhat/SOURCES
    $SUDO rpmbuild -ba $SPECFILE
}

build_deb()
{
    test -e ~/.debmacros && die "Move ~/.rpmmacros out of the way"

    if test ! -x /usr/bin/pax
    then
	die "apt-get install pax"
    fi

    if test ! -d $DEBDIR
    then
	for SUBDIR in $SUBDEBDIRS
	do
	    $SUDO mkdir -p $DEBDIR/$SUBDIR
	done
    fi

    $SUDO cp $SPECFILE $DEBDIR/SPECS

    $SUDO mv -f $PKGROOT/hipl${SUFFIX}.tar.gz /usr/src/debian/SOURCES
    # http://www.deepnet.cx/debbuild/
    $SUDO $PKGEXE/debbuild -ba $SPECFILE
}

cleanup()
{
    if [ -n "$PKGDIR" -a -d "$PKGDIR" ];then
	echo "removing '$PKGDIR'"
	rm -rf "$PKGDIR"
    fi
}

set -e

echo <<EOF
** Creating the directory structure and files for building the
** source package needed for RPM package containing HIPL
** user space software
**
** Version $VERSION (release $RELEASE)
**
EOF

cleanup

make dist

tar xzf ${NAME}-main.tar.gz
find ${NAME}-main -name '.arch*' | xargs rm -rf
mv -v ${NAME}-main $PKGDIR

echo "** Creating source package $PKGROOT/${NAME}${SUFFIX}.tar.gz"
tar czf $PKGROOT/hipl${SUFFIX}.tar.gz ${NAME}$SUFFIX
ls -l $PKGROOT/hipl${SUFFIX}.tar.gz

cat <<EOF

#############################################
# Assuming that you are in /etc/sudoers!!!! #
#############################################

EOF

if test x"$1" = x"rpm"
then
    SPECFILE=$PKGEXE/hipl-rpm.spec 
    build_rpm
elif test x"$1" = x"deb"
then
    SPECFILE=$PKGEXE/hipl-deb.spec 
    build_deb
else
    echo "*** Unknown platform, aborting ***"
fi

cleanup
