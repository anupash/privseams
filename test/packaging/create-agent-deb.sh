#!/bin/sh
# This script builds debian packages.

MAJOR=1
MINOR=0
VERSION="$MAJOR.$MINOR"
RELEASE=3
SUFFIX="-$VERSION-$RELEASE"
NAME=hipl-manager
DEBIAN=i386/DEBIAN-gconf
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}-${VERSION}-deb
PKGDIR_SRC=$PKGROOT/${NAME}-${VERSION}-deb-src
SRCDIR=${PKGDIR_SRC}/${NAME}-${VERSION}
ROOT=$PWD
PKGNAME="${NAME}-${VERSION}-${RELEASE}-i386.deb"

# Copy binary package files.
copy_binpkg_files()
{
	echo "** Copying binaries..."
	set -e

	mkdir -p "$PKGDIR/DEBIAN"
	for f in control changelog copyright postinst postrm; do
		cp $PKGROOT/$DEBIAN/$f "$PKGDIR/DEBIAN"
	done
	
	mkdir -p "$PKGDIR/usr"
	mkdir -p "$PKGDIR/usr/sbin"
	mkdir -p "$PKGDIR/usr/lib"
	mkdir -p "$PKGDIR/usr/share"
	mkdir -p "$PKGDIR/usr/share/hipl"
	mkdir -p "$PKGDIR/usr/share/hipl/libhipgui"
	mkdir -p "$PKGDIR/usr/share/menu"
	mkdir -p "$PKGDIR/usr/share/pixmaps"
	mkdir -p "$PKGDIR/usr/share/applications"
	mkdir -p "$PKGDIR/etc"
	mkdir -p "$PKGDIR/etc/xdg"
	mkdir -p "$PKGDIR/etc/xdg/autostart"
	
#	for suffix in a la so so.0 so.0.0.0; do
#		cp -d $ROOT/libhipgui/.libs/libstrvar.$suffix $PKGDIR/usr/lib/
#	done

	cp -d $ROOT/agent/hipagent $PKGDIR/usr/sbin/

#	cp -d $ROOT/libhipgui/hipmanager.desktop $PKGDIR/etc/xdg/autostart/hipmanager.desktop
#	cp -d $ROOT/libhipgui/hipmanager.app.desktop $PKGDIR/usr/share/applications/hipmanager.app.desktop
#	cp -d $ROOT/libhipgui/hipmanager.menu $PKGDIR/usr/share/menu/hipmanager
	cp -d $ROOT/libhipgui/hipmanager.png $PKGDIR/usr/share/pixmaps/hipmanager.png

	set +e
}


echo "** Creating debian package..."

#./configure
rm -rf $PKGDIR
rm -rf $PKGDIR_SRC

#if ! make clean all; then
#	echo "** Error while running make!"
#	exit 1
#fi
make

if ! copy_binpkg_files; then
	echo "** Error while copying files!"
	exit 1
fi

echo "** Creating binary package..."

cd $PKGROOT
if dpkg-deb -b "$PKGDIR" "$PKGNAME"; then
	echo "** Successfully finished building package."
else
	echo "** Error while building package!"
fi

