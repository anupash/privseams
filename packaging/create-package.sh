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
    #createrepo --update --outputdir=$PKG_EXE $PKG_DIR
    createrepo --outputdir=$PKG_EXE $PKG_DIR
}

mkindex_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=$(echo $PKG_WEB_DIR | sed 's/ubuntu\///' | sed 's/\//\\\//g')
    #dpkg-scanpackages --multiversion . |
    dpkg-scanpackages . |
        sed "s/Filename: \./Filename: $WD/" |
        gzip -9c > $PKG_INDEX
    cd $ORIG
}

syncrepo()
{
    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR

    # Delete old packages from the repo
    ssh  ${REPO_USER}@${REPO_SERVER} "rm -f ${PKG_SERVER_DIR}/*.${DISTRO_PKG_SUFFIX}"

    # Copy all packages and repo index to the repository
    rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/

}

set_release_version()
{
    if test -r $OPT_CHANGELOG; then
        RELEASE=$(head -2 $OPT_CHANGELOG | tail -1 | cut -d" " -f2)
    else
        RELEASE=$(bzr log --line -l 1 | cut -d: -f1)
    fi
}

build_package()
{
    set_release_version
    echo "Version: $VERSION" > $SPECFILE
    echo "Release: $RELEASE" >> $SPECFILE
    cat $SPECFILE_TEMPLATE >> $SPECFILE

    make dist > /dev/null

    $1
}

build_rpm()
{
    echo "Deleting old .rpmmacros"
    echo "%_topdir $RPMBUILD" > $HOME/.rpmmacros

    for SUBDIR in $SUBRPMDIRS; do
        mkdir -p $RPMBUILD/$SUBDIR
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

build_deb()
{
    if test -e ~/debbuild; then
        echo "Warning: ~/debbuild found, could be a problem"
        echo "It should be a link to /usr/src/debian"
    fi

    if test ! -x /usr/bin/pax; then
        die "apt-get install pax"
    fi

    rm -rf $DEBDIR
    for SUBDIR in $SUBDEBDIRS; do
        mkdir -p $DEBDIR/$SUBDIR
    done

    cp $SPECFILE $DEBDIR/SPECS

    mv -f $TARBALL $DEBDIR/SOURCES
    # http://www.deepnet.cx/debbuild/
    $PKGEXE/debbuild --buildroot $DEBDIR -ba $SPECFILE
}

############### Main program #####################

set -e

VERSION=$(grep '^AC_INIT' configure.ac | cut -d'[' -f 3 | cut -d']' -f1)
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/packaging
PKG_INDEX=$PKG_EXE/$PKG_INDEX_NAME
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
    die "unknown distribution"
fi

# Determine action
case $1 in
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
        die "usage: $0 [syncrepo|deb|rpm|bin]"
esac
