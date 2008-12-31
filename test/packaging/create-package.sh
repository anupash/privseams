#!/bin/sh -xv

VERSION=
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/test/packaging
PKG_WEB_DIR=
PKG_SERVER_DIR=
DEBDIR=/usr/src/debian
RPMDIR=/usr/src/redhat
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUDO=sudo
ARCH=
DISTRO_RELEASE=
DISTRO=
DISTROBASE=
DISTRO_PKG_SUFFIX=
REPO_SERVER=packages.infrahip.net
REPO_BASE=/var/www/html/
BIN_FORMAT=
TARBALL=
RSYNC_OPTS=-uvr
REPO_USER=hipl
REPO_GROUP=hipl
SPECFILE_DIR=`mktemp -d`
SPECFILE=$SPECFILE_DIR/hipl.spec 

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
    $SUDO mv -f $TARBALL /usr/src/redhat/SOURCES
    $SUDO rpmbuild -ba $SPECFILE
}

mkindex_rpm()
{
    if test ! -d $PKG_INDEX
    then
	mkdir $PKG_INDEX
    fi
    createrepo --update $PKG_DIR --outputdir $PKG_INDEX
}

mkindex_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=`echo $PKG_WEB_DIR|sed 's/\//\\\\\//g'`
    dpkg-scanpackages --multiversion . | \
	sed "s/Filename: \./Filename: $WD/" | \
	gzip -9c > $PKG_INDEX
    cd $ORIG
}

syncrepo()
{
    # We are reusing /usr/src/something to store multiversions of binaries
    # and we have to have download priviledges there for rsync.
    $SUDO chown $USER -R $PKG_DIR

    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR
    # (over)write package to the repository
    rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${REPO_USER}@${REPO_SERVER}:$PKG_SERVER_DIR/
    # fetch all versions of packages to build complete repo index
    rsync $RSYNC_OPTS ${REPO_USER}@${REPO_SERVER}:$PKG_SERVER_DIR/ $PKG_DIR/

    # build index of all packages
    if test x"$DISTROBASE" = x"debian"
    then
	mkindex_deb
    elif test x"$DISTROBASE" = x"redhat"
    then
	mkindex_rpm
    else
	die "Unhandled distro $DISTROBASE"
    fi

    # Copy all packages and repo index to the repository
    rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/

    # Restore file priviledges on /usr/src/somewhere
    $SUDO chown root -R $PKG_DIR
}

build_deb()
{
    if dpkg --print-architecture|grep -q armel
    then
	build_maemo_deb
	exit 0
    fi

    test -e ~/.debmacros && die "Move ~/.debmacros out of the way"

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

    $SUDO mv -f $TARBALL /usr/src/debian/SOURCES
    # http://www.deepnet.cx/debbuild/
    $SUDO $PKGEXE/debbuild -ba $SPECFILE
}

############### Main program #####################

set -e

cp $PKGROOT/release.version $SPECFILE

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
    cat $PKGEXE/hipl-deb.spec >> $SPECFILE
    VERSION=`grep Version: $SPECFILE|cut -d" " -f2`
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
    PKG_INDEX_DIR=$PKGEXE
    PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
elif test -r /etc/redhat-release
then
    DISTROBASE=redhat
    SPECFILE=$PKGEXE/hipl-rpm.spec 
    ARCH=`uname -i`
    PKG_DIR=$RPMDIR/RPMS/$ARCH
    DISTRO_RELEASE=`lsb_release -r|cut -f2`
    DISTRO=`lsb_release -d|cut -f2|tr '[:upper:]' '[:lower:]'|cut -d" " -f1`
    PKG_WEB_DIR=fedora/base/$DISTRO_RELEASE/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/$PKG_WEB_DIR
    cat $PKGEXE/hipl-rpm.spec >> $SPECFILE
    VERSION=`grep Version: $SPECFILE|cut -d" " -f2`
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
    PKG_INDEX_DIR=$PKGEXE
    PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
else
    die "Unknown architecture"
fi

TARBALL=$PKGROOT/hipl-${VERSION}.tar.gz

# Determine action
if test x"$1" = x"syncrepo"
then
    syncrepo
    exit
elif test x"$1" = x"bin"
then
    if test x"$DISTROBASE" = x"redhat"
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
** Version $VERSION
**
EOF

make dist
rm -rf ${NAME}-${VERSION}
tar xzf ${NAME}-main.tar.gz
#find ${NAME}-main -name '.arch*' | xargs rm -rf
mv -v ${NAME}-main ${NAME}-${VERSION}
tar czf $TARBALL ${NAME}-${VERSION}
#mv $PKGROOT/${NAME}-main.tar.gz $TARBALL
ls -ld $TARBALL

cat <<EOF

#############################################
# Assuming that you are in /etc/sudoers!!!! #
#############################################

EOF

if test x"$1" = x"rpm" || test x"$BIN_FORMAT" = x"rpm"
then
    build_rpm
elif test x"$1" = x"deb" || test x"$BIN_FORMAT" = x"deb"
then
    build_deb
else
    die "*** Unknown platform, aborting ***"
fi

