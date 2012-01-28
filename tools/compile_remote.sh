#!/bin/sh
#
# This script allows to build HIPL on a remote host while editing the sources
# locally. The script can be used from a local shell. However, its main purpose
# is the integration into the build environment provided by Eclipse.
#
# Requirements:
# -------------
# 1.) Shared HIPL checkout/branch on editing and build hosts (e.g., smbfs, sshfs)
# 2.) Public key-based SSH access to build host from editing host
#
# Setup:
# ------
# 1.) Import project folder as an Eclipse project on editing host
#     (File -> New -> C Project -> Makefile Project -> Other Toolchain
#           -> Location must refer to the local project source code)
# 2.) Set Project -> Properties -> C/C++ Build -> Builder Setting -> Build command
#     to ${ProjDirPath}/tools/compile_remote.sh
# 3.) Add BUILD_HOST and BUILD_HOST_PATH to
#     Project -> Properties -> C/C++ Build Project -> Environment, e.g.,
#        * BUILD_HOST: passion.comsys.rwth-aachen.de
#        * BUILD_HOST_PATH: ~/src/hipl/trunk 
#
# Optionally, the following options can be enabled:
# a.) Set Project -> Properties -> C/C++ Build -> Behavior -> Use parallel build
#     -> Use optimal job number
# b.) Unset Project -> Properties -> C/C++ Build -> Behavior -> Stop on 1st error


######### DON'T CHANGE BELOW THIS LINE #########

echo "Calling 'make $*' on remote host..."
echo

if [ -z $BUILD_HOST ]; then
	echo "ERROR: BUILD_HOST not specified."
elif [ -z $BUILD_HOST_PATH ]; then
	echo "ERROR: BUILD_HOST_PATH not specified."
else
	ssh $BUILD_HOST "make -C $BUILD_HOST_PATH $*"
fi
