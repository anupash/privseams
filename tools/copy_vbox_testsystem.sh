#!/bin/sh
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

# Enter configuration parameters below:

# Need to be absolute paths
INPUT_DIR="/srv/archive/tinyhip/vms/testsystem/"
OUTPUT_DIR=""
SSH_PORT_alice=""
SSH_PORT_bob=""
SSH_PORT_middle1=""
SSH_PORT_middle2=""

# Functions
copy_vm() {
    VM_NAME=$1
    INPUT_DISK=$2
    OUTPUT_DISK=$3
    SSH_PORT=$4

    if [ ! -e "${INPUT_DISK}" ]; then
        echo "Input disk ${INPUT_DISK} does not exist! ...abort run!";
    exit;
    fi

    if [ ! -d "${OUTPUT_DIR}" ]; then
        echo "Directory ${OUTPUT_DIR} does not exist. Creating directory.";
        mkdir ${OUTPUT_DIR}
    fi

    cd ${OUTPUT_DIR}

    echo "cloning disk..."
    VBoxManage clonevdi ${INPUT_DISK} ${OUTPUT_DISK}

    echo "create vm..."
    VBoxManage createvm --name ${VM_NAME} --register --basefolder ${OUTPUT_DIR}

    echo "set ostype, memory size, audio, and boot order..."
    VBoxManage modifyvm ${VM_NAME} --ostype Ubuntu_64 > /dev/null
    VBoxManage modifyvm ${VM_NAME} --memory 384 > /dev/null
    VBoxManage modifyvm ${VM_NAME} --audio none > /dev/null
    VBoxManage modifyvm ${VM_NAME} --boot1 disk --boot2 dvd --boot3 none > /dev/null

    echo "add IDE controller and hd..."
    VBoxManage storagectl ${VM_NAME} --name "IDE Controller" --add ide > /dev/null
    VBoxManage modifyvm ${VM_NAME} --hda ${OUTPUT_DISK} > /dev/null

    echo "configure network..."
    VBoxManage modifyvm ${VM_NAME} --nic1 nat --cableconnected1 on > /dev/null

    echo "configure port forwarding..."
    VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/pcnet/0/LUN#0/Config/ssh/HostPort" ${!SSH_PORT} > /dev/null
    VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/pcnet/0/LUN#0/Config/ssh/GuestPort" 22 > /dev/null
    VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/pcnet/0/LUN#0/Config/ssh/Protocol" TCP > /dev/null

    #VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/e1000/0/LUN#0/Config/ssh/HostPort" ${!SSH_PORT}
    #VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/e1000/0/LUN#0/Config/ssh/GuestPort" 22
    #VBoxManage setextradata ${VM_NAME} "VBoxInternal/Devices/e1000/0/LUN#0/Config/ssh/Protocol" TCP
}

# Main program
if [ "$INPUT_DIR" = "" ]; then
    echo "Enter INPUT_DIR (You can statically set the value in this script):"
    read INPUT_DIR
fi

if [ "$OUTPUT_DIR" = "" ]; then
    echo "Enter OUTPUT_DIR (You can statically set the value in this script):"
    read OUTPUT_DIR
fi

if [ "$SSH_PORT_alice" = "" ]; then
    echo "Enter SSH_PORT_alice (You can statically set the value in this script):"
    read SSH_PORT_alice
fi
if [ "$SSH_PORT_bob" = "" ]; then
    echo "Enter SSH_PORT_bob (You can statically set the value in this script):"
    read SSH_PORT_bob
fi
if [ "$SSH_PORT_middle1" = "" ]; then
    echo "Enter SSH_PORT_middle1 (You can statically set the value in this script):"
    read SSH_PORT_middle1
fi
if [ "$SSH_PORT_middle2" = "" ]; then
    echo "Enter SSH_PORT_middle2 (You can statically set the value in this script):"
    read SSH_PORT_middle2
fi

for VM_NAME in "alice" "bob" "middle1" "middle2" do
    copy_vm ${VM_NAME} "${INPUT_DIR}/${VM_NAME}/${VM_NAME}.vdi" "${OUTPUT_DIR}/${VM_NAME}/${VM_NAME}.vdi" SSH_PORT_${VM_NAME}
done

# Create and configure additional network interfaces
VBoxManage modifyvm alice --nic2 intnet --intnet2 localscope --cableconnected2 on > /dev/null

VBoxManage modifyvm middle1 --nic2 intnet --intnet2 localscope --cableconnected2 on --macaddress2 080027ad5599 > /dev/null
VBoxManage modifyvm middle2 --nic2 intnet --intnet2 localscope --cableconnected2 on --macaddress2 080027d91634 > /dev/null

VBoxManage modifyvm middle1 --nic3 intnet --intnet3 globalscope --cableconnected3 on > /dev/null
VBoxManage modifyvm middle2 --nic3 intnet --intnet3 globalscope --cableconnected3 on > /dev/null

VBoxManage modifyvm bob --nic2 intnet --intnet2 globalscope --cableconnected2 on > /dev/null

