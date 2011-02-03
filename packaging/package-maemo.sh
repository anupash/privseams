#! /bin/sh

# USAGE:
# 0. install Maemo SDK
# 1. check out hipl branch to build
# 2. modify paths below according to the checkouts
# 3. run this script
#
# NOTE: The script cleans source folder and updates the sources to allow
#       incremental builds.
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

SCRATCHBOX="/opt/scratchbox"
HIPL="$HOME/src/hipl/trunk"

### DON'T CHANGE BELOW THIS LINE ###

SCRATCHBOX_HOME=$SCRATCHBOX/users/$USER/home/$USER
VERSION=$(grep '^AC_INIT' ${HIPL}/configure.ac|cut -d'[' -f 3|cut -d']' -f1)

if [ ! -e $SCRATCHBOX ]; then
    echo "ERROR: There seems to be no ScratchBox installation at $SCRATCHBOX"
    exit 1
fi

if [ ! -e $SCRATCHBOX_HOME ]; then
    echo "ERROR: $SCRATCHBOX_HOME does not exist. Maybe you have not been added as a user!"
    exit 1
fi

# HIPL
if [ -e $HIPL ]; then
    echo "-> Preparing HIPL for MAEMO"
    cd $HIPL || exit 1
    rm -f hipl-*.tar.gz
    if [ -e Makefile ]; then
        make autotools-clean
    fi

    echo "    Updating HIPL..."
    bzr up
    echo "    Done."

    echo "    Making HIPL tarball..."
    autoreconf --install
    ./configure
    make dist
    echo "    Done."

    echo "-> Building HIPL"
    echo "    Unpacking tarball..."
    rm -rf $SCRATCHBOX_HOME/hipl*
    tar -xvzf $HIPL/hipl-${VERSION}.tar.gz -C $SCRATCHBOX_HOME
    echo "    Done."

    echo "    Compiling HIPL for Maemo..."
    $SCRATCHBOX/login -d hipl-${VERSION}/packaging ./build-maemo.sh
    echo "    Done."
else
    echo "ERROR: $HIPL does not exist."
    exit 1
fi

