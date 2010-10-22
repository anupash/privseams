#!/bin/sh

############### helper functions #####################

die()
{
    echo $@
    exit 1
}

set_release_version()
{
    if test -r $OPT_CHANGELOG; then
        RELEASE=$(head -2 $OPT_CHANGELOG | tail -1 | cut -d" " -f2)
    else
        RELEASE=$(bzr log --line -l 1 | cut -d: -f1)
    fi
}

build_rpm()
{
    make dist > /dev/null

    echo "Deleting old .rpmmacros"
    echo "%_topdir $RPMBUILD" > $HOME/.rpmmacros

    for SUBDIR in $SUBRPMDIRS; do
        if test ! -d $RPMBUILD/$SUBDIR; then
            mkdir -p $RPMBUILD/$SUBDIR
        fi
    done

    # fix this hack -miika
    test -d $RPMBUILD/RPMS/i586 &&
        cp -a $RPMBUILD/RPMS/i586 $RPMBUILD/RPMS/i386

    mv -f $TARBALL $RPMBUILD/SOURCES
    rpmbuild -ba $SPECFILE

    # rpmbuild does not want to build to $RPMDIR, so let's just move it
    # to there from $RPMBUILD
    test -d $RPMDIR && rm -rf $RPMDIR
    mv $RPMBUILD $RPMDIR
    find $RPMDIR -name '*rpm'
}

mkindex_rpm()
{
    test ! -d $PKG_INDEX && mkdir $PKG_INDEX
    # fix this hack -miika
    test -d  /tmp/hipl-${VERSION}/buildenv/RPMS/i586 &&
        cp -a /tmp/hipl-${VERSION}/buildenv/RPMS/i586 /tmp/hipl-${VERSION}/buildenv/RPMS/i386
    #createrepo --update --outputdir=$PKG_INDEX_DIR $PKG_DIR
    createrepo --outputdir=$PKG_INDEX_DIR $PKG_DIR
}

mkindex_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=$(echo $PKG_WEB_DIR | sed 's/ubuntu\///' | sed 's/\//\\\//g')
    #dpkg-scanpackages --multiversion . |
    dpkg-scanpackages . | \
        sed "s/Filename: \./Filename: $WD/" | \
        gzip -9c > $PKG_INDEX
    cd $ORIG
}

syncrepo()
{
    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR

    # build index of all packages
    if test x"$DISTROBASE" = x"debian"; then
        mkindex_deb
    elif test x"$DISTROBASE" = x"redhat"; then
        mkindex_rpm
    else
        die "Unhandled distro $DISTROBASE"
    fi

    # Delete old packages from the repo
    ssh  ${REPO_USER}@${REPO_SERVER} "rm -f ${PKG_SERVER_DIR}/*.${DISTRO_PKG_SUFFIX}"

    # Copy all packages and repo index to the repository
    rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/

}

build_deb()
{
    make dist > /dev/null

    test -e ~/.debmacros && echo "Warning: ~/.debmacros found, could be a problem"
    if test -e ~/debbuild; then
        echo "Warning: ~/debbuild found, could be a problem"
        echo "It should be a link to /usr/src/debian"
    fi

    if test ! -x /usr/bin/pax; then
        die "apt-get install pax"
    fi

    rm -rf $DEBDIR
    for SUBDIR in $SUBDEBDIRS; do
        if test ! -d $DEBDIR/$SUBDIR; then
            mkdir -p $DEBDIR/$SUBDIR
        fi
    done

    cp $SPECFILE $DEBDIR/SPECS

    mv -f $TARBALL $DEBDIR/SOURCES
    # http://www.deepnet.cx/debbuild/
    $PKGEXE/debbuild --buildroot $DEBDIR -ba $SPECFILE
}

############### Main program #####################

set -e

VERSION=$(grep '^AC_INIT' configure.ac|cut -d'[' -f 3|cut -d']' -f1)
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/packaging
PKG_INDEX_DIR=$PKGEXE
PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
DEBDIR=$PWD/debbuild
RPMDIR=$PWD/rpmbuild
RPMBUILD=/tmp/rpmbuild
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUBRPMDIRS="BUILD RPMS SOURCES SPECS SRPMS"
DISTRO=$(lsb_release -d | cut -f2 | tr '[:upper:]' '[:lower:]' | cut -d" " -f1)
DISTRO_RELEASE=$(lsb_release -c | cut -f2)
REPO_SERVER=hipl.hiit.fi
REPO_BASE=/var/www/packages/html
TARBALL=$PKGROOT/hipl-${VERSION}.tar.gz
RSYNC_OPTS=-uvr
REPO_USER=hipl
REPO_GROUP=hipl
SPECFILE_DIR=$(mktemp -d)
SPECFILE=$SPECFILE_DIR/hipl.spec
OPT_CHANGELOG='doc/ChangeLog'

# Set architecture, distro and repo details
if test -r /etc/debian_version; then
    DISTROBASE=debian
    ARCH=$(dpkg --print-architecture)
    PKG_DIR=$DEBDIR/DEBS/$ARCH
    PKG_WEB_DIR=ubuntu/dists/$DISTRO_RELEASE/main/binary-${ARCH}
    PKG_SERVER_DIR=$REPO_BASE/$DISTRO/$PKG_WEB_DIR
    SPECFILE_TEMPLATE=$PKGEXE/hipl-deb.spec
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
elif test -r /etc/redhat-release; then
    DISTROBASE=redhat
    ARCH=$(uname -i)
    PKG_DIR=$RPMDIR/RPMS/$ARCH
    PKG_WEB_DIR=fedora/base/$DISTRO_RELEASE/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/$PKG_WEB_DIR
    SPECFILE_TEMPLATE=$PKGEXE/hipl-rpm.spec
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
else
    die "Unknown architecture"
fi

set_release_version
echo "Version: $VERSION" > $SPECFILE
echo "Release: $RELEASE" >> $SPECFILE

cat $SPECFILE_TEMPLATE >> $SPECFILE

# Determine action
if test x"$1" = x"syncrepo"; then
    syncrepo
    exit
elif test x"$1" = x"bin"; then
    if test x"$DISTROBASE" = x"redhat"; then
        BIN_FORMAT=rpm
    elif test x"$DISTROBASE" = x"debian"; then
        BIN_FORMAT=deb
    else
        die "Unknown distro"
    fi
fi

if test x"$1" = x"rpm" || test x"$BIN_FORMAT" = x"rpm"; then
    build_rpm
elif test x"$1" = x"deb" || test x"$BIN_FORMAT" = x"deb"; then
    build_deb
else
    die "*** Unknown platform, aborting ***"
fi
