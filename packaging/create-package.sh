#!/bin/sh

############### helper functions #####################

die()
{
    echo $@
    exit 1
}

mkindex_rpm()
{
    mkdir -p $PKG_DIR
    createrepo $PKG_DIR
}

mkindex_deb()
{
    PKG_WEB_DIR=dists/$DISTRO_RELEASE/main/binary-${ARCH}

    dpkg-scanpackages $PKG_DIR |
        sed "s,Filename: $PKG_DIR,Filename: $PKG_WEB_DIR," |
        gzip -9c > $PKG_INDEX
}

syncrepo()
{
    $INDEXING_CMD

    NAME=hipl
    REPO_SERVER=hipl.hiit.fi
    REPO_USER=hipl

    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR

    # Delete old packages from the repo
    ssh  ${REPO_USER}@${REPO_SERVER} "rm -f ${PKG_SERVER_DIR}/*.${DISTRO_PKG_SUFFIX}"

    # Copy all packages and repo index to the repository
    rsync -uvr $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/
}

build_package()
{
    rm -rf $BUILDDIR
    for SUBDIR in $SUBBUILDDIRS; do
        mkdir -p $BUILDDIR/$SUBDIR
    done

    RELEASE=$(grep BZR_REVISION $SRCDIR/version.h | cut -d\" -f2)

    echo "Version: $VERSION"  > $SPECFILE
    echo "Release: $RELEASE" >> $SPECFILE
    echo "%define _topdir $BUILDDIR" >> $SPECFILE
    cat $SPECFILE_TEMPLATE   >> $SPECFILE

    make dist > /dev/null
    mv -f hipl-${VERSION}.tar.gz $BUILDDIR/SOURCES

    $PACKAGING_CMD
}

build_rpm()
{
    rpmbuild --target $ARCH -ba $SPECFILE
}

build_deb()
{
    which pax > /dev/null || die "aptitude install pax"

    # http://www.deepnet.cx/debbuild/
    $PACKAGING_DIR/debbuild --buildroot $BUILDDIR -ba $SPECFILE
}

############### Main program #####################

set -e

SRCDIR=$(echo $0 | sed s:/packaging/create-package.sh::)
VERSION=$(grep '^AC_INIT' $SRCDIR/configure.ac | cut -d'[' -f 3 | cut -d']' -f1)
PACKAGING_DIR=$SRCDIR/packaging
DISTRO_RELEASE=$(lsb_release -c | cut -f2)
REPO_BASE=/var/www/packages/html

# Set architecture, distro and repo details
if test -r /etc/debian_version; then
    DISTRO=debian
    ARCH=$(dpkg --print-architecture)
    BUILDDIR=$PWD/debbuild
    SUBBUILDDIRS="BUILD SOURCES SPECS DEBS SDEBS"
    PKG_DIR=$BUILDDIR/DEBS/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/ubuntu/dists/$DISTRO_RELEASE/main/binary-${ARCH}
    SPECFILE_TEMPLATE=$PACKAGING_DIR/hipl-deb.spec
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
    INDEXING_CMD=mkindex_deb
    PACKAGING_CMD=build_deb
elif test -r /etc/redhat-release; then
    DISTRO=redhat
    ARCH=$(uname -i)
    BUILDDIR=$PWD/rpmbuild
    SUBBUILDDIRS="BUILD SOURCES SPECS RPMS SRPMS"
    PKG_DIR=$BUILDDIR/RPMS/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/fedora/base/$DISTRO_RELEASE/$ARCH
    SPECFILE_TEMPLATE=$PACKAGING_DIR/hipl-rpm.spec
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
    INDEXING_CMD=mkindex_rpm
    PACKAGING_CMD=build_rpm
else
    die "unknown distribution"
fi

PKG_INDEX=$PKG_DIR/$PKG_INDEX_NAME
SPECFILE=$BUILDDIR/SPECS/hipl.spec

# Determine action
case $1 in
    syncrepo_deb)
        INDEXING_CMD=mkindex_deb syncrepo ;;
    syncrepo_rpm)
        INDEXING_CMD=mkindex_rpm syncrepo ;;
    syncrepo)
        syncrepo ;;
    deb)
        PACKAGING_CMD=build_deb build_package ;;
    rpm)
        PACKAGING_CMD=build_rpm build_package ;;
    bin)
        build_package ;;
    *)
        die "usage: $0 <syncrepo|syncrepo_deb|syncrepo_rpm|deb|rpm|bin>"
esac
