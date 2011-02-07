#! /bin/sh

# HIPL packaging depends on debhelper7
export PATH=/usr/bin/dh7:/usr/bin:$PATH
# ... which in turn depends on a newer version of perl
# than provided by the respective devkit
export SBOX_REDIRECT_IGNORE=/usr/bin/perl

# build the package and do not check for build dependencies
# -> the work-around above makes dpkg-buildpackage find the
#    wrong debhelper version
dpkg-buildpackage -rfakeroot -b -d
