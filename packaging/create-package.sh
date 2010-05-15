#!/bin/sh

VERSION=
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/packaging
PKG_WEB_DIR=
PKG_SERVER_DIR=
DEBDIR=$PWD/debbuild
RPMDIR=$PWD/rpmbuild
RPMBUILD=/tmp/rpmbuild
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUBRPMDIRS="BUILD RPMS SOURCES SPECS SRPMS"
SUDO= # no sudo
ARCH=
DISTRO_RELEASE=
DISTRO=
DISTROBASE=
DISTRO_PKG_SUFFIX=
REPO_SERVER=hipl.infrahip.net
REPO_BASE=/var/www/packages/html
TARBALL=
RSYNC_OPTS=-uvr
REPO_USER=hipl
REPO_GROUP=hipl
SPECFILE_DIR=$(mktemp -d)
SPECFILE=$SPECFILE_DIR/hipl.spec
RELEASE_VERSION_FILE=$PKGROOT/release.version

inc_release_number()
{
    TMPFILE=$(mktemp)
    awk \
    '{ \
        if ($1 == "Release:") { \
            print $1 " " ($2 + 1) \
        } else {                  \
            print              \
        } \
    }' < $RELEASE_VERSION_FILE > $TMPFILE
    mv $TMPFILE $RELEASE_VERSION_FILE
    echo "Now type:"
    echo "bzr update"
    echo "bzr commit -m 'Increased release version number'"
}

die()
{
    echo $@
    exit 1
}

build_rpm()
{
    echo "Deleting old .rpmmacros"
    echo "%_topdir $RPMBUILD" > $HOME/.rpmmacros

    for SUBDIR in $SUBRPMDIRS; do
        if test ! -d $RPMBUILD/$SUBDIR; then
            $SUDO mkdir -p $RPMBUILD/$SUBDIR
        fi
    done

    # fix this hack -miika
    test -d $RPMBUILD/RPMS/i586 &&
        cp -a $RPMBUILD/RPMS/i586 $RPMBUILD/RPMS/i386

    $SUDO mv -f $TARBALL $RPMBUILD/SOURCES
    $SUDO rpmbuild -ba $SPECFILE

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
    test -d  /tmp/hipl-main/buildenv/RPMS/i586 &&
        cp -a /tmp/hipl-main/buildenv/RPMS/i586 /tmp/hipl-main/buildenv/RPMS/i386
    #$SUDO createrepo --update --outputdir=$PKG_INDEX_DIR $PKG_DIR
    $SUDO createrepo --outputdir=$PKG_INDEX_DIR $PKG_DIR
}

mkindex_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=$(echo $PKG_WEB_DIR | sed 's/\//\\\\\//g')
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
    test -e ~/.debmacros && echo "Warning: ~/.debmacros found, could be a problem"
    if test -e ~/debbuild; then
        echo "Warning: ~/debbuild found, could be a problem"
        echo "It should be a link to /usr/src/debian"
    fi

    if test ! -x /usr/bin/pax; then
        die "apt-get install pax"
    fi

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

cp $RELEASE_VERSION_FILE $SPECFILE

# Set architecture, distro and repo details
if test -r /etc/debian_version; then
    DISTROBASE=debian
    ARCH=$(dpkg --print-architecture)
    PKG_DIR=$DEBDIR/DEBS/$ARCH
    DISTRO_RELEASE=$(lsb_release -c | cut -f2)
    PKG_WEB_DIR=dists/$DISTRO_RELEASE/main/binary-${ARCH}
    PKG_SERVER_DIR=$REPO_BASE/$DISTRO/$PKG_WEB_DIR
    cat $PKGEXE/hipl-deb.spec >> $SPECFILE
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
elif test -r /etc/redhat-release; then
    DISTROBASE=redhat
    ARCH=$(uname -i)
    PKG_DIR=$RPMDIR/RPMS/$ARCH
    DISTRO_RELEASE=$(lsb_release -r | cut -f2)
    PKG_WEB_DIR=fedora/base/$DISTRO_RELEASE/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/$PKG_WEB_DIR
    cat $PKGEXE/hipl-rpm.spec >> $SPECFILE
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
else
    die "Unknown architecture"
fi

DISTRO=$(lsb_release -d | cut -f2 | tr '[:upper:]' '[:lower:]' | cut -d" " -f1)
PKG_INDEX_DIR=$PKGEXE
PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
VERSION=$(grep Version: $SPECFILE | cut -d" " -f2)

TARBALL=$PKGROOT/hipl-${VERSION}.tar.gz

# Determine action
if test x"$1" = x"syncrepo"; then
    syncrepo
    exit
elif test x"$1" = x"increl"; then
    inc_release_number
    exit
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

echo "*** Cleaning up ${DEBDIR} ***"
rm -rf ${DEBDIR}

if test x"$1" = x"rpm"; then
    build_rpm
elif test x"$1" = x"deb"; then
    build_deb
fi