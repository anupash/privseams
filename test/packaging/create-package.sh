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
PKG_INDEX_NAME=Packages.gz
PKG_INDEX_DIR=$PKGEXE
PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
PKGDIR=$PKGROOT/${NAME}$SUFFIX
PKG_WEB_DIR=
PKG_SERVER_DIR=
DEBDIR=/usr/src/debian
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUDO=sudo
ARCH=
DISTRO_RELEASE=
DISTRO=
DISTROBASE=
REPO_SERVER=packages.infrahip.net
REPO_BASE=/var/www/html
BIN_FORMAT=

die()
{
    echo $@
    exit 1
}

build_maemo_deb()
{
    env PYEXECDIR=$(PYEXECDIR) $PKGEXE/create-deb.sh
    env PYEXECDIR=$(PYEXECDIR) $PKGEXE/create-deb.sh -s
}

build_rpm()
{
    test -e ~/.rpmmacros && die "Move ~/.rpmmacros out of the way"
    # The RPMs can be found from /usr/src/redhat/ SRPMS and RPMS
    $SUDO mv -f $PKGROOT/hipl${SUFFIX}.tar.gz /usr/src/redhat/SOURCES
    $SUDO rpmbuild -ba $SPECFILE
}

syncrepo_deb()
{
    ssh $REPO_SERVER sudo mkdir -p $PKG_SERVER_DIR
    TEMPDIR=`ssh $REPO_SERVER mktemp -d`
    scp $PKG_INDEX $REPO_SERVER:$TEMPDIR/
    scp $PKG_DIR/*.deb $REPO_SERVER:$TEMPDIR/
    ssh $REPO_SERVER \
	sudo mv $TEMPDIR/* $PKG_SERVER_DIR/
    #ssh $REPO_SERVER "chown apache.apache PACKAGES_GZ_DIR"
}

scanpackages_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=`echo $PKG_WEB_DIR|sed 's/\//\\\\\//g'`
    dpkg-scanpackages . | sed "s/Filename: \./Filename: $WD/" | \
	gzip -9c > $PKG_INDEX
    cd $ORIG
}

build_deb()
{
    if dpkg --print-architecture|grep -q armel
    then
	build_maemo_deb
	exit 0
    fi

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

############### Main program #####################

set -e

# Set architecture, distro and repo details
if test -r /etc/debian_version
then
    DISTROBASE=debian
    ARCH=`dpkg --print-architecture`
    PKG_DIR=$DEBDIR/DEBS/$ARCH 
    DISTRO_RELEASE=`lsb_release -c|cut -f2`
    DISTRO=`lsb_release -d|cut -f2|tr '[:upper:]' '[:lower:]'|cut -d" " -f1`
    PKG_WEB_DIR=dists/$DISTRO_RELEASE/main/binary-${ARCH}
    PKG_SERVER_DIR=$REPO_BASE/$DISTRO/$PKG_WEB_DIR
elif test -r /etc/redhat-release
then
    DISTROBASE=redhat
    ARCH=`uname -m` # xx test i386
else
    die "Unknown architecture"
fi

# Determine action
if test x"$1" = x"scanpackages"
then
    scanpackages_deb # xx fix rpm
    exit
elif test x"$1" = x"syncrepo"
then
    syncrepo_deb # xx fix rpm
    exit
elif test x"$1" = x"bin"
then
    if test test x"$DISTROBASE" = x"redhat"
    then
	BIN_FORMAT=rpm
    elif test x"$DISTROBASE" = x"debian"
    then
	BIN_FORMAT=deb
    else
	die "Unknown distro"
    fi
fi
echo "Architecture: $ARCH"

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

if test x"$1" = x"rpm" || test x"$BIN_FORMAT" = x"rpm"
then
    SPECFILE=$PKGEXE/hipl-rpm.spec 
    build_rpm
elif test x"$1" = x"deb" || test x"$BIN_FORMAT" = x"deb"
then
    SPECFILE=$PKGEXE/hipl-deb.spec 
    build_deb
    scanpackages_deb
else
    die "*** Unknown platform, aborting ***"
fi

cleanup
