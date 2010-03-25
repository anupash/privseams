#!/bin/sh
# HIPL autobuild script for periodic compilation tests.
# The name of the branch to test needs to be passed as the first parameter.
#
# This script relies on the following home directory layout:
# - $HOME/src/hipl/           - location for HIPL shared repository
# - $HOME/src/hipl/<branch>   - location for HIPL <branch> to be tested
# - $HOME/tmp/autobuild/hipl/ - temporary build directory
#
# If the HIPL_NOTIFICATION_EMAIL environment variable is set to a suitable value
# for the user running this script, then email will be sent in case of failure.

BRANCH_NAME=$1
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
    cat > msg.txt <<EOF
branch: $BRANCH_NAME
revision: $BRANCH_REVISION
configuration: $CONFIGURATION
command: $COMMAND
compiler output:

EOF
    cat log.txt >> msg.txt
    SUBJECT="[autobuild] [$BRANCH_NAME] revision $BRANCH_REVISION"
    mailx -s "$SUBJECT" $HIPL_NOTIFICATION_EMAIL < msg.txt
}

cleanup()
{
    chmod -R u+rwx "$CHECKOUT_DIR"
    rm -rf "$CHECKOUT_DIR"
    echo $BRANCH_REVISION > $BRANCH_REVISION_FILE
    exit $1
}

compile()
{
    run_program "./autogen.sh" &&
        run_program "./configure" --prefix=$(pwd)/local_install "$@" &&
        run_program "make -j17" &&
        run_program "make -j17 distcheck" &&
        run_program "make install"
}

test $BRANCH_REVISION = $AUTOBUILD_REVISION && exit 0

bzr checkout -q --lightweight $BRANCH_URL $CHECKOUT_DIR || cleanup 1

cd "$CHECKOUT_DIR" || cleanup 1

# Compile HIPL in different configurations
# vanilla configuration
compile

# PISA configuration
compile --enable-firewall --disable-agent --disable-pfkey --disable-rvs --disable-hipproxy --disable-altsep --enable-privsep --disable-i3 --disable-opportunistic --disable-dht --disable-blind --disable-profiling --enable-debug --enable-midauth --disable-performance --disable-demo

# Alternative path to vanilla
compile --enable-firewall --enable-agent --enable-pfkey --disable-rvs --disable-hipproxy --enable-openwrt --enable-altsep --disable-privsep --enable-i3 --disable-opportunistic --disable-dht --enable-blind --enable-profiling --disable-debug --enable-midauth --enable-performance --enable-demo


cleanup 0
