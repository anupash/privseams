#! /bin/sh

# USAGE:
# 0. install Maemo SDK
# 1. check out hipl branch to build
# 2. modify paths below according to the checkouts
# 3. run this script
#
# NOTE: The script cleans source folder and updates the sources to allow
#       incremental builds.

SCRATCHBOX="/srv/power/scratchbox"
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
    tar -xvzf $HIPL/hipl-[0-9.]*.tar.gz -C $SCRATCHBOX_HOME
    echo "    Done."

    echo "    Compiling HIPL for Maemo..."
    $SCRATCHBOX/login -d hipl-${VERSION} packaging/build-maemo-helper.sh
    echo "    Done."
else
    echo "ERROR: $HIPL does not exist."
    exit 1
fi

