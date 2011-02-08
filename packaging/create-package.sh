#!/bin/sh
#
# Copyright (c) 2010 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

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

    REPO_SERVER=hipl.hiit.fi
    REPO_USER=hipl

    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR

    # Delete old packages from the repo
    ssh  ${REPO_USER}@${REPO_SERVER} "rm -f ${PKG_SERVER_DIR}/*.${DISTRO_PKG_SUFFIX}"

    # Copy all packages and repo index to the repository
    rsync -uvr $PKG_DIR/hipl-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/
}

build_rpm()
{
    rm -rf $BUILDDIR
    for SUBDIR in BUILD SOURCES SPECS RPMS SRPMS; do
        mkdir -p $BUILDDIR/$SUBDIR
    done

    SPECFILE=$BUILDDIR/SPECS/hipl.spec
    RELEASE=$(grep VCS_REVISION $SRCDIR/version.h | cut -d\" -f2)

    echo "Version: $VERSION"  > $SPECFILE
    echo "Release: $RELEASE" >> $SPECFILE
    echo "%define _topdir $BUILDDIR" >> $SPECFILE
    cat $SRCDIR_PACKAGING/hipl-rpm.spec >> $SPECFILE

    make dist > /dev/null
    cp hipl-${VERSION}.tar.gz $BUILDDIR/SOURCES

    rpmbuild --target $ARCH -ba $SPECFILE
}

build_deb()
{
    dpkg-buildpackage -us -uc -I.bzr $BUILDPACKAGE_OPTS
}

############### Main program #####################

set -e

SRCDIR=$(echo $0 | sed s:/packaging/create-package.sh::)
VERSION=$(grep '^AC_INIT' $SRCDIR/configure.ac | cut -d'[' -f 3 | cut -d']' -f1)
SRCDIR_PACKAGING=$SRCDIR/packaging
REPO_BASE=/var/www/packages/html

# Set architecture, distro and repo details
if test -r /etc/debian_version; then
    ARCH=$(dpkg --print-architecture)
    PKG_DIR=..
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
    INDEXING_CMD=mkindex_deb
    PACKAGING_CMD=build_deb
    if test -r /etc/maemo_version; then
        export PATH=/usr/bin/dh7:/usr/bin:$PATH
        export SBOX_REDIRECT_IGNORE=/usr/bin/perl
        BUILDPACKAGE_OPTS="-d -rfakeroot"
    else
        DISTRO_RELEASE=$(lsb_release -c | cut -f2)
        PKG_SERVER_DIR=$REPO_BASE/ubuntu/dists/$DISTRO_RELEASE/main/binary-${ARCH}
        BUILDPACKAGE_OPTS=-j32
    fi
elif test -r /etc/redhat-release; then
    ARCH=$(uname -i)
    BUILDDIR=$PWD/rpmbuild
    PKG_DIR=$BUILDDIR/RPMS/$ARCH
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
    INDEXING_CMD=mkindex_rpm
    PACKAGING_CMD=build_rpm
    DISTRO_RELEASE=$(lsb_release -r | cut -f2)
    PKG_SERVER_DIR=$REPO_BASE/fedora/base/$DISTRO_RELEASE/$ARCH
    case $(lsb_release -d) in
        "Description:	CentOS release 5.5 (Final)")
            export CPPFLAGS=-U__STRICT_ANSI__;;
    esac
else
    die "unknown distribution"
fi

PKG_INDEX=$PKG_DIR/$PKG_INDEX_NAME

# Determine action
case $1 in
    syncrepo_deb)
        INDEXING_CMD=mkindex_deb syncrepo ;;
    syncrepo_rpm)
        INDEXING_CMD=mkindex_rpm syncrepo ;;
    syncrepo)
        syncrepo ;;
    deb)
        build_deb ;;
    rpm)
        build_rpm ;;
    bin)
        $PACKAGING_CMD ;;
    *)
        die "usage: $0 <syncrepo|syncrepo_deb|syncrepo_rpm|deb|rpm|bin>"
esac
