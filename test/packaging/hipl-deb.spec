Name: hipl
Summary: HIP IPsec key management and mobility daemon.
# Note: Version and Release are read automatically from topdir release.version
# To check that this file is in correct format, type
# ./debbuild --showpkgs hipl-deb.spec
URL: http://infrahip.hiit.fi
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: miika@iki.fi
Vendor: InfraHIP
License: GPLv2
Group: System Environment/Kernel
BuildRequires: automake, autoconf, libtool, gcc, g++, libgtk2.0-dev, libssl-dev, libxml2-dev, xmlto, doxygen, iptables-dev, libcap-dev, libsqlite3-dev, libuuid1
ExclusiveOS: linux
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: /usr
%description

Host Identity Protocol (HIP) provides cryptographic authentication to
between hosts and secure communications using IPsec. HIP protocol
extensions support also mobility and multihoming, and traversal of NATs.

HIP for Linux (HIPL) is an implementation of a HIP implementation that
consists of the key and mobility management daemon. It includes also
other related tools and test software.
%prep
%setup

# Note: in subsequent releases me may want to use --disable-debugging
%build
./autogen.sh --prefix=/usr
%configure --prefix=/usr --enable-libinet6
make -C doc
make -j 4 all

# Note:
# This debbuild script is fragile and does not tolerate comments well.
# Keep all comments and notes here.
#
# Note:
#
# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#define _unpackaged_files_terminate_build 0
#define _missing_doc_files_terminate_build 0
#define python_sitelib __python -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')
#
# Note:
# we are not distributing everything from test directory, just essentials
#
# create subpackage
# list of files with the name of subpackage
#
# Note: earlier the contents of "all" and "minimal" was just "."
# It doesn't work anymore with Rene's changes to the update version of
# debbuild. Currently they include some files to get the binaries compiled.
# Fix this workaround.
#
# Note:
# - 64-bit binaries should go to lib64
#
# Note: the post rules used to be like this (does not work anymore)
# - update-rc.d hipfw start 20 S . stop 80 0 6 .
# - invoke-rc.d --quiet hipdnsproxy start


%package all
Summary: HIPL software bundle: HIP for Linux libraries, daemons and documentation
Group: System Environment/Kernel
Requires: hipl-lib, hipl-firewall, hipl-daemon, hipl-agent, hipl-tools, hipl-test, hipl-doc, hipl-dnsproxy
%description all

%package minimal
Summary: Minimal HIPL software bundle for servers. This virtual package is suitable for e.g. servers.
Group: System Environment/Kernel
Requires: hipl-lib hipl-daemon hipl-tools
%description minimal

%package lib
Summary: HIP for Linux libraries
Group: System Environment/Kernel
Requires: openssl, libxml2, libgtk2.0-0, iptables, libcap2, libsqlite3-0
%description lib

%package daemon
Requires: hipl-lib, iproute, libnet-ip-perl, libnet-dns-perl, libsocket6-perl, libio-socket-inet6-perl
Summary: HIP for Linux IPsec key management and mobility daemon
Group: System Environment/Kernel
%description daemon

%package tools
Requires: hipl-lib, hipl-daemon
Summary: Command line tools to control hipd from command line
Group: System Environment/Kernel
%description tools

%package firewall
Requires: hipl-lib
Summary: HIPL multi-purpose firewall daemon. Public-key/HIT-based access control, Local Scope Identifier support, userspace BEET-mode IPsec (for kernels below < 2.6.27) and system-based opportunistic mode for HIP.
Group: System Environment/Kernel
%description firewall

%package test
Requires: hipl-daemon
Summary: netcat-like command line tools with built-in HIP support for developers 
Group: System Environment/Kernel
%description test

%package doc
Summary: documentation for HIP for Linux
Group: System Environment/Kernel
%description doc

%package dnsproxy
Requires: python, hipl-lib
Summary: Name look-up proxy for HIP for Linux. Intercepts DNS look-ups and returns HIT or LSIs when corresponding entries are found in DNS, DHT or hosts files
Group: System Environment/Kernel
%description dnsproxy

%package agent
Requires: hipl-lib, hipl-daemon
Summary: Graphical user interface for HIP for Linux. Provides user-friendly access control "buddy" lists for HIP.
Group: System Environment/Kernel
%description agent

%install
rm -rf %{buildroot}

install -d %{buildroot}/usr/share/pixmaps
install -m 644 lib/gui/hipmanager.png %{buildroot}/usr/share/pixmaps
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/sbin
install -d %{buildroot}/usr/lib
install -d %{buildroot}/etc/init.d
install -d %{buildroot}/doc
make DESTDIR=%{buildroot} install
install -m 755 test/packaging/debian-init.d-hipfw %{buildroot}/etc/init.d/hipfw
install -m 755 test/packaging/debian-init.d-hipd %{buildroot}/etc/init.d/hipd
install -m 755 test/packaging/debian-init.d-dnsproxy %{buildroot}/etc/init.d/hipdnsproxy
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -d %{buildroot}/usr/lib/python2.6/dist-packages/DNS
install -t %{buildroot}/usr/lib/python2.6/dist-packages/DNS tools/DNS/*py*
install -d %{buildroot}/usr/lib/python2.6/dist-packages/hipdnsproxy
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnsproxy tools/dnsproxy.py*
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnsproxy tools/pyip6.py*
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnsproxy tools/hosts.py*
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnsproxy tools/util.py*
install -d %{buildroot}/usr/lib/python2.6/dist-packages/hipdnskeyparse
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnskeyparse tools/parse-key-3.py*
install -t %{buildroot}/usr/lib/python2.6/dist-packages/hipdnskeyparse tools/myasn.py*
install -m 755 tools/hipdnskeyparse %{buildroot}/usr/sbin/hipdnskeyparse
install -m 755 tools/hipdnsproxy %{buildroot}/usr/sbin/hipdnsproxy
install -m 755 agent/hipagent %{buildroot}/usr/sbin/hipagent

%post lib
/sbin/ldconfig 

%post daemon
update-rc.d hipd defaults 21

%post firewall
update-rc.d hipfw defaults 20

%post dnsproxy
update-rc.d hipdnsproxy defaults 22

%preun daemon
invoke-rc.d --quiet hipd status >/dev/null && invoke-rc.d --force --quiet hipd stop
update-rc.d -f hipd remove

%preun firewall
invoke-rc.d --quiet hipfw status >/dev/null && invoke-rc.d --force --quiet hipfw stop
update-rc.d -f hipfw remove

%preun dnsproxy
invoke-rc.d --quiet hipdnsproxy status >/dev/null && invoke-rc.d --force --quiet hipdnsproxy stop
update-rc.d -f hipdnsproxy remove

%clean
rm -rf %{buildroot}

%files lib
%{_libdir}

%files daemon
/usr/sbin/hipd
/usr/bin/hipsetup
%config /etc/init.d/hipd

%files agent
/usr/share/pixmaps/hipmanager.png
/usr/sbin/hipagent

%files dnsproxy
/usr/sbin/hipdnsproxy
/usr/sbin/hipdnskeyparse
%defattr(755,root,root)
%config /etc/init.d/hipdnsproxy


%files tools
/usr/sbin/hipconf
/usr/sbin/nsupdate.pl
%defattr(755,root,root)

%files test
/usr/bin/conntest-client-opp
/usr/bin/conntest-client-hip
/usr/bin/conntest-client-native
/usr/bin/conntest-client-native-user-key
/usr/bin/conntest-server
/usr/bin/conntest-server-native

%files firewall
/usr/sbin/hipfw
%config /etc/init.d/hipfw

%files doc
%doc doc/HOWTO.txt doc/howto-html

%files all
%doc doc/COPYING

%files minimal
%doc doc/HACKING

%changelog
* Fri Nov 20 2009 Miika Komu <miika@iki.fi>
- Loads of new stuff, including enhanced mobility
* Wed Dec 31 2008 Miika Komu <miika@iki.fi>
- Packaging improvements and lots of testing
* Wed Aug 20 2008 Miika Komu <miika@iki.fi>
- Dnsproxy separated into a separate package. Python packaging improvements.
* Mon Jul 21 2008 Miika Komu <miika@iki.fi>
- Rpmbuild fixes for Fedora 8 build
* Thu Jul 17 2008 Johnny Hughes <johnny@centos.org>
- added two perl searches and installed one directory in the spec file
- added libtool, libcap-devel and xmlto to BuildRequires 
* Thu May 29 2008 Juha Jylhakoski <juha.jylhakoski@hiit.fi>
- Split hipl.spec was split to different packages
* Tue May 9 2006 Miika Komu <miika@iki.fi>
- init.d script, buildroot
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog

