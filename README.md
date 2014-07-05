Priv-Seams: A Privacy-aware Signaling Layer for End-host-Assisted Middlebox Services
=========

On-path network elements, such as NATs and firewalls, are an accepted commonality in today’s networks. They are essential when extending network functionality and providing additional security. However, these so called middleboxes are not explicitly considered in the original TCP/IP-based network architecture. As a result, the protocols of the TCP/IP suite provide middleboxes with the same information about data flows as packet-forwarding routers. Yet, middleboxes typically perform complex functions within the network that require additional knowledge. Inferring this knowledge from observing the sparse information available in network packets requires these devices to base their decisions on ambiguous or forgeable data. Priv-Seams is designed to counter problems arising from such insufficient information and identify the resulting informational requirements of middleboxes. It is a signaling layer that enables end hosts to provide middleboxes with descriptive and verifiable data flow contexts in order to allow for more secure and richer middlebox functions in home and enterprise network scenarios than provided by today’s middleboxes. Furthermore, it provides extensions to the SEAMS signaling protocol that take privacy concerns of transmitting such descriptive and verifiable contexts on the signaling path into consideration. The evaluation of SEAMS and its extensions, shows that they can be a feasible addition to TCP/IP-based networks and that they support multiple on-path middleboxes.


HIPL dependencies
-----------------

HIPL places certain requirements on your kernel. Starting from Linux kernel
version 2.6.27, no changes are necessary. If you run an older version, look
at the patches/kernel directory to find patches for your Linux kernel version.
Alternatively, you can use userspace ipsec as provided by hipfw. If you want
to use the optional native programming interface, you need to patch your kernel
anyway.

In order to compile HIPL you need autotools (autoconf, automake, libtool), GNU
Make and gcc. openssl, iptables and libconfig are required complete with
development headers. For Perl Net::IP and Net::DNS modules are required.
You can optionally install xmlto to
build the HOWTO and doxygen to build the code documentation. Installing the
optional check library (http://check.sourceforge.net/) enables unit tests.
Some additional libraries are needed for building binary packages (fakeroot
and dpkg-dev on ubuntu).

On Ubuntu, the following command(s) should solve the dependencies:

  aptitude install autoconf automake libtool make gcc libssl-dev iptables-dev \
                   libconfig8-dev libnet-ip-perl libnet-dns-perl

  Optionally: aptitude install miredo bzr xmlto doxygen check fakeroot \
                       dpkg-dev debhelper devscripts

On Fedora, the following command(s) should solve the dependencies:

  yum install autoconf automake libtool make gcc openssl-devel \
              iptables-devel libconfig-devel perl-Net-IP perl-Net-DNS

  Optionally: yum install miredo bzr xmlto doxygen check-devel rpm-build \
                          redhat-lsb

Priv-Seams dependencies
-----------------
On Ubuntu, the following command should install net-tools
  apt-get install net-tools


How to build HIPL
-----------------

If you are working with a Bazaar checkout, you will have to bootstrap the
autotools build system with

  autoreconf --install

before running configure. On subsequent times, you don't have give the
install option.

From the trunk directory in the HIPL sources, run the following command to
build HIPL:

  ./configure && make

./configure --help will display the multitude of configuration options
available for HIPL.

To keep the developers sharp and honest HIPL is built with -Werror in CFLAGS.
gcc will just error out when issuing a warning. If you experience compilation
failures and just need to get HIPL to build on a combination of platform and
compiler that does produce warnings, you can override -Werror as follows:

  CFLAGS=-Wno-error ./configure

Then run make as usual.

Please note that the HIP configuration files are located in
/usr/local/etc/hip with the default configure flags. If you want to
change the location to /etc/hip, you have to pass --sysconfdir=/etc to
configure (or create a symbolic link).

Priv-Seams build options
-----------------
You can optionally enable ECDH (Elliptic-Curve Diffie-Hellman) instead of regular
Diffie-Hellman (DH) for the HIP Base Exchange (HIP BEX). This is recommended for 
hardware with low-end configurations.

  ./configure --enable-ecdh                           Enable ECDH (default is NO)

