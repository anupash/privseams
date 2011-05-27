#!/bin/sh
#
# This script allows to build HIPL on a remote host while editing the sources
# locally. The script can be used from a local shell. However, its main purpose
# is the integration into the build environment provided by Eclipse.
#
# Requirements:
# -------------
# 1.) Remote HIPL checkout/branch on build host
# 2.) Public key-based SSH access to build host from this host
# 3.) Mounted remote HIPL checkout/branch on this host
# 4.) Import of mounted folder as an Eclipse project
#     (File -> New -> C Project -> Location must refer to the local mount point)
#
# Installation:
# -------------
# 1.) Set Project -> Properties -> C/C++ Build -> Builder Setting -> Build command
#     to ${ProjDirPath}/tools/compile_remote.sh
#
# Setup:
# ------
# 1.) Adapt BUILD_HOST and BUILD_HOST_PATH in this file according to your needs
#
# Optionally, the following options can be enabled:
# 2.) Set Project -> Properties -> C/C++ Build -> Behavior -> Use parallel build
#     -> Use optimal job number
# 3.) Unset Project -> Properties -> C/C++ Build -> Behavior -> Stop on 1st error


BUILD_HOST="passion.comsys.rwth-aachen.de"
BUILD_HOST_PATH="~/src/hipl/trunk"


######### DON'T CHANGE BELOW THIS LINE #########

echo "Making $*..."
echo

ssh $BUILD_HOST "make -C $BUILD_HOST_PATH $*"

echo
echo "Done."
