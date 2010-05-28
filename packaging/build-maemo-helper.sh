#!/bin/sh

# HIPL requires Python >= 2.5, this is a workaround to use
# the installable python2.5 instead of the in-built 2.3.2
export SBOX_REDIRECT_IGNORE=$SBOX_REDIRECT_IGNORE:/usr/bin/python
export PATH=/usr/bin:$PATH
dpkg-buildpackage -rfakeroot -b
