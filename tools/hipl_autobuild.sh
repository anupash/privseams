#!/bin/sh
# HIPL autobuild script for periodic compilation tests.
# The name of the branch to test needs to be passed as the first parameter.
#
# This script relies on the following directory layout:
# - $HOME/src/hipl/           - location for HIPL shared repository
# - $HOME/src/hipl/<branch>   - location for HIPL <branch> to be tested
# - $HOME/tmp/autobuild/hipl/ - temporary build directory
# - $HOME/tmp/autobuild/openwrt - working OpenWrt tree
# - /srv/power/scratchbox/users/${LOGNAME}${HOME]} - working scratchbox environment
#
# If the HIPL_NOTIFICATION_EMAIL environment variable is set to a suitable value
# for the user running this script, then email will be sent in case of failure.

if test "$1" = ""; then
    echo "usage: $0 <branch_name>"
    exit 1
fi

BRANCH_NAME=$1

AUTOBUILD_DIR=$HOME/tmp/autobuild
BUILD_DIR=$AUTOBUILD_DIR/hipl
OPENWRT_DIR=$AUTOBUILD_DIR/openwrt
SCRATCHBOX_DIR="/srv/power/scratchbox"
SCRATCHBOX_HOME=$SCRATCHBOX_DIR/users/${LOGNAME}${HOME}

BUILD_DIR=$HOME/tmp/autobuild/hipl
BRANCH_URL=$HOME/src/hipl/$BRANCH_NAME
CHECKOUT_DIR=$BUILD_DIR/$(date +"%Y-%m-%d-%H%M")_$BRANCH_NAME
BRANCH_REVISION=$(bzr revno -q $BRANCH_URL)
BRANCH_REVISION_FILE=$BUILD_DIR/HIPL_REVISION_$BRANCH_NAME
AUTOBUILD_REVISION=$(cat $BRANCH_REVISION_FILE)

# helper functions
run_program()
{
    $@ > log.txt 2>&1
    if [ $? -eq 0 ] ; then
        rm -f log.txt
        return 0
    else
        test $HIPL_NOTIFICATION_EMAIL && mail_notify "$1"
        cleanup 1
    fi
}

mail_notify()
{
    COMMAND="$1"
    cat > $CHECKOUT_DIR/msg.txt <<EOF
branch: $BRANCH_NAME
revision: $BRANCH_REVISION
configuration: $CONFIGURATION
command: $COMMAND
compiler output:

EOF
    cat log.txt >> $CHECKOUT_DIR/msg.txt
    SUBJECT="[autobuild] [$BRANCH_NAME] revision $BRANCH_REVISION"
    mailx -s "$SUBJECT" $HIPL_NOTIFICATION_EMAIL < $CHECKOUT_DIR/msg.txt
}

cleanup()
{
    # The build directory created by make distcheck is read-only.
    chmod -R u+rwX "$CHECKOUT_DIR"
    rm -rf "$CHECKOUT_DIR"
    echo $BRANCH_REVISION > $BRANCH_REVISION_FILE
    exit $1
}

# Make sure that 'make dist' is complete.
check_dist()
{
    find -L . | sed -e 1d -e 's:./::' -e '/\.bzr/d' -e '/autom4te.cache/d' -e '/file_list_checkout/d' |
        sort > file_list_checkout
    ./configure && make dist
    tar -tzf hipl-*.tar.gz |
        sed -e 1d -e 's:hipl-main/::' -e 's:/$::' -e '/file_list_checkout/d' -e '/version.h/d' |
        sort > file_list_tarball
    run_program diff -u file_list_checkout file_list_tarball
}

compile()
{
    CONFIGURATION="--prefix=$(pwd)/local_install $@"
    run_program "./configure" $CONFIGURATION &&
        run_program "make -j17" &&
        run_program "make -j17 checkheaders" &&
        run_program "make install"
}

test $BRANCH_REVISION = $AUTOBUILD_REVISION && exit 0

bzr checkout -q --lightweight $BRANCH_URL $CHECKOUT_DIR || cleanup 1

cd "$CHECKOUT_DIR" || cleanup 1

# Bootstrap the autotools build system.
run_program autoreconf --install

CONFIGURATION="distribution tarball completeness"
check_dist

# Compile HIPL in different configurations
# vanilla configuration
compile
run_program "make -j17 distcheck"

# PISA configuration
compile --enable-firewall --disable-rvs --disable-hipproxy --disable-opportunistic --disable-dht --disable-blind --disable-profiling --enable-debug --enable-midauth --disable-performance --disable-demo

# Alternative path to vanilla
compile --enable-firewall --disable-rvs --disable-hipproxy --disable-opportunistic --disable-dht --enable-blind --enable-profiling --disable-debug --enable-midauth --enable-performance --enable-demo

# Compile HIPL within an OpenWrt checkout
CONFIGURATION="OpenWrt ARM crosscompile"
run_program "cp hipl*tar.gz $OPENWRT_DIR/dl"
cd $OPENWRT_DIR || cleanup 1
run_program "rm -rf package/hipl"
run_program "cp -r $CHECKOUT_DIR/packaging/openwrt/package package/hipl"
run_program "make -j17 package/hipl-clean V=99"
run_program "make -j17 package/hipl-install V=99"


# Crosscompile HIPL in a scratchbox environment.

# scratchbox complains if USER is missing from the environment
export USER=$LOGNAME

CONFIGURATION="Scratchbox ARM crosscompile"
cd $SCRATCHBOX_HOME || cleanup 1
run_program "rm -rf hipl-main* hipl_*.changes hipl_*.deb"
run_program "tar -xzf $CHECKOUT_DIR/hipl-main.tar.gz"
run_program "$SCRATCHBOX_DIR/login -d hipl-main dpkg-buildpackage -rfakeroot -b"

cleanup 0
