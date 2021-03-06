#!/bin/sh
# HIPL autobuild script for periodic compilation and quality tests.
# The name of the branch to test needs to be passed as the first parameter.
#
# The script is suitable to be run from cron in order to provide basic
# continuous integration. Errors encountered during operation are logged
# to a text file and sent off by email. To receive these notifications,
# set the HIPL_NOTIFICATION_EMAIL environment variable to a suitable value.
#
# No full checkout of HIPL sources is done. In order to greatly speed up
# testing multiple branches, lightweight checkouts are used. The shared
# repository from which the checkouts are extracted is expected to have
# been updated before this script is run.
#
# This script relies on the following home directory layout of the user
# running it:
# - $HOME/src/hipl/           - location for HIPL shared repository
# - $HOME/src/hipl/<branch>   - location for HIPL <branch> to be tested
# - $HOME/tmp/autobuild/hipl/ - temporary build directory
# - $HOME/tmp/autobuild/openwrt - working OpenWrt tree
# - /opt/scratchbox/users/${LOGNAME}${HOME]} - working scratchbox environment
#
# A typical crontab entry for the autobuilder looks the following way:
# m   h dom mon dow    command
# 30  *  *   *   *     bzr up -q $HOME/src/hipl/trunk && \
#                      sh -l $HOME/src/hipl/trunk/tools/hipl_autobuild.sh trunk
#
# TODO      Shortly describe the different stages (as in check-out, compare, ...)
#           of the autobuilder, especially when/why the autobuilder uses which
#           directory.
# RATIONALE I was not sure where the VERSION info added by Miika should have been
#           extracted from in the first place.
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

if test "$1" = ""; then
    echo "usage: $0 <branch_name>"
    exit 1
fi

BRANCH_NAME=$1

AUTOBUILD_DIR=$HOME/tmp/autobuild
BUILD_DIR=$AUTOBUILD_DIR/hipl
OPENWRT_DIR=$AUTOBUILD_DIR/openwrt
SCRATCHBOX_DIR="/opt/scratchbox"
SCRATCHBOX_HOME=$SCRATCHBOX_DIR/users/${LOGNAME}${HOME}

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

# Check if 'make dist' contains all files that are under version control.
check_dist_tarball()
{
    # Remove autogenerated, Bazaar-related and similar files from the list.
    find -L . | sed -e 1d -e 's:./::' -e '/\.bzr/d' -e '/autom4te.cache/d' -e '/file_list_checkout/d' |
        sort > file_list_checkout
    ./configure > /dev/null && make dist > /dev/null
    tar -tzf hipl-*.tar.gz |
        sed -e 1d -e "s:hipl-[0-9.]*/::" -e 's:/$::' -e '/file_list_checkout/d' -e '/version.h/d' |
        sort > file_list_tarball
    run_program diff -u file_list_checkout file_list_tarball
}

# There should be no Doxygen warnings.
check_doxygen()
{
    make doxygen > /dev/null 2> doxygen_stderr
    run_program diff -u /dev/null doxygen_stderr
}

compile()
{
    # Run compile and install tests for a certain configuration, in-tree.
    CONFIGURATION="--prefix=$(pwd)/local_install $@"
    run_program "./configure" $CONFIGURATION &&
        run_program "make -j"                &&
        run_program "make -j checkheaders"   &&
        run_program "make install"
}

# only run the autobuilder for newer revisions than the last one checked
test $BRANCH_REVISION = $AUTOBUILD_REVISION && exit 0

bzr checkout -q --lightweight $BRANCH_URL $CHECKOUT_DIR || cleanup 1

cd "$CHECKOUT_DIR" || cleanup 1

# Bootstrap the autotools build system.
run_program autoreconf --install

CONFIGURATION="distribution tarball completeness"
check_dist_tarball

CONFIGURATION="Doxygen documentation"
check_doxygen

# Compile HIPL in different configurations
# vanilla configuration
compile

# internal autoconf tests, bootstrap the dist tarball, build out-of-tree, etc
run_program "make -j distcheck"

# run unit tests (needs to run after HIPL has been configured)
run_program "make -j check"

# PISA configuration
compile --enable-firewall --disable-rvs --disable-profiling --enable-debug --enable-midauth --disable-performance

# Max compile coverage configuration
FEATURES_ALL="--enable-firewall --enable-rvs --enable-profiling --disable-debug --enable-midauth --enable-performance"
compile $FEATURES_ALL

# Max compile coverage configuration without optimization
compile $FEATURES_ALL CFLAGS="-O0"

# Max compile coverage configuration optimized for size
compile $FEATURES_ALL CFLAGS="-Os"

# Max compile coverage configuration with full optimization
# FIXME: Disabled until the tree compiles with this optimization level.
#compile $FEATURES_ALL CFLAGS="-O3"

# Without modules
compile --with-nomodules=heartbeat,update,heartbeat_update

# test binary distribution packages
# This is run as the last test because it can have sideeffects on the
# other standard configurations.
run_program "make -j bin"

# Compile HIPL within an OpenWrt checkout
CONFIGURATION="OpenWrt ARM crosscompile"
cd $OPENWRT_DIR || cleanup 1
run_program "cp $CHECKOUT_DIR/hipl*tar.gz dl/"
run_program "rm -rf package/hipl"
run_program "cp -r $CHECKOUT_DIR/packaging/openwrt/hipl package/"
run_program "make -j package/hipl/clean V=99"
run_program "make -j package/hipl/install V=99"


# Crosscompile HIPL in a scratchbox environment.

# scratchbox complains if USER is missing from the environment
export USER=$LOGNAME

CONFIGURATION="Scratchbox ARM crosscompile"
cd $SCRATCHBOX_HOME || cleanup 1
# clean-up previous run and get fresh sources for compilation (in host env)
run_program "rm -rf hipl-[0-9.]* hipl_*.changes hipl_*.deb"
run_program "tar -xzf $CHECKOUT_DIR/hipl-[0-9.]*.tar.gz"
# perform debian packaging (in maemo sdk env)
run_program "$SCRATCHBOX_DIR/login -d hipl-[0-9.]* ./configure"
run_program "$SCRATCHBOX_DIR/login -d hipl-[0-9.]* make deb"

cleanup 0
