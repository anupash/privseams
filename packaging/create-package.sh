#!/bin/sh

############### helper functions #####################

die()
{
    echo $@
    exit 1
}

mkindex_rpm()
{
    mkdir -p $PKG_INDEX
    # fix this hack -miika
    test -d  /tmp/hipl-${VERSION}/buildenv/RPMS/i586 &&
        cp -a /tmp/hipl-${VERSION}/buildenv/RPMS/i586 /tmp/hipl-${VERSION}/buildenv/RPMS/i386
    createrepo --outputdir=$PKG_EXE $PKG_DIR
}

mkindex_deb()
{
    PKG_WEB_DIR=dists/$DISTRO_RELEASE/main/binary-${ARCH}

    ORIG=$PWD
    cd $PKG_DIR
    dpkg-scanpackages . |
        sed "s,Filename: \.,Filename: $PKG_WEB_DIR," |
        gzip -9c > $PKG_INDEX
    cd $ORIG
}

syncrepo()
{
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

    RELEASE=$(grep BZR_REVISION $PKGROOT/version.h | cut -d\" -f2)

    echo "Version: $VERSION"  > $SPECFILE
    echo "Release: $RELEASE" >> $SPECFILE
    cat $SPECFILE_TEMPLATE   >> $SPECFILE

    make dist > /dev/null
    mv -f $TARBALL $BUILDDIR/SOURCES

    $1
}

build_rpm()
{
    # fix this hack -miika
    test -d $BUILDDIR/RPMS/i586 &&
        cp -a $BUILDDIR/RPMS/i586 $BUILDDIR/RPMS/i386

    rpmbuild -ba $SPECFILE
}

build_deb()
{
    which pax > /dev/null || die "aptitude install pax"

    # http://www.deepnet.cx/debbuild/
    $PKG_EXE/debbuild --buildroot $BUILDDIR -ba $SPECFILE
}

############### Main program #####################

set -e

VERSION=$(grep '^AC_INIT' configure.ac | cut -d'[' -f 3 | cut -d']' -f1)
PKGROOT=$PWD
PKG_EXE=$PKGROOT/packaging
DISTRO_RELEASE=$(lsb_release -c | cut -f2)
REPO_BASE=/var/www/packages/html
TARBALL=$PKGROOT/hipl-${VERSION}.tar.gz

# Set architecture, distro and repo details
if test -r /etc/debian_version; then
    DISTROBASE=debian
    ARCH=$(dpkg --print-architecture)
    BUILDDIR=$PWD/debbuild
    SUBBUILDDIRS="BUILD SOURCES SPECS DEBS SDEBS"
    PKG_DIR=$BUILDDIR/DEBS/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/ubuntu/dists/$DISTRO_RELEASE/main/binary-${ARCH}
    SPECFILE_TEMPLATE=$PKG_EXE/hipl-deb.spec
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
elif test -r /etc/redhat-release; then
    DISTROBASE=redhat
    ARCH=$(uname -i)
    BUILDDIR=$PWD/rpmbuild
    SUBBUILDDIRS="BUILD SOURCES SPECS RPMS SRPMS"
    PKG_DIR=$BUILDDIR/RPMS/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/fedora/base/$DISTRO_RELEASE/$ARCH
    SPECFILE_TEMPLATE=$PKG_EXE/hipl-rpm.spec
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
else
    die "unknown distribution"
fi

PKG_INDEX=$PKG_DIR/$PKG_INDEX_NAME
SPECFILE=$BUILDDIR/SPECS/hipl.spec

# Determine action
case $1 in
    syncrepo_deb)
        mkindex_deb
        syncrepo
        ;;
    syncrepo_rpm)
        mkindex_rpm
        syncrepo
        ;;
    syncrepo)
        if test "$DISTROBASE" = "debian"; then
            mkindex_deb
        else
            mkindex_rpm
        fi
        syncrepo
        ;;
    deb)
        build_package build_deb ;;
    rpm)
        build_package build_rpm ;;
    bin)
        if test "$DISTROBASE" = "debian"; then
            build_package build_deb
        else
            build_package build_rpm
        fi
        ;;
    *)
        die "usage: $0 <syncrepo|syncrepo_deb|syncrepo_rpm|deb|rpm|bin>"
esac
