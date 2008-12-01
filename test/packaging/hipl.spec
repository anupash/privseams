Name: hipl
Version: 1.0.4
Release: 1
Summary: HIP IPsec key management and mobility daemon.
URL: http://infrahip.hiit.fi/hipl/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: hipl-dev@freelists.org
Vendor: InfraHIP
License: GPL
Group: System Environment/Kernel
Requires: openssl gtk2 libxml2 glib2 iptables-devel
BuildRequires: openssl-devel gtk2-devel libxml2-devel glib2-devel iptables-devel xmlto libtool libcap-devel 
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

#added by CentOS
%ifarch x86_64 ppc64 sparc64 ia64
%{__perl} -p -i -e 's,/usr/lib/libipq.a,/usr/lib64/libipq.a,g' firewall/Makefile.in
%endif

%{__perl} -p -i -e 's,/usr/share/pixmaps,\$(DESTDIR)/usr/share/pixmaps,g' libhipgui/Makefile.in
#end CentOS changes

# Note: in subsequent releases me may want to use --disable-debugging
# TBD: The pjproject needs to glued in better (convert it to automake).
#      That way we can get rid of the double configure (the second one is
#      currently required for bug id 524)
%build
./autogen.sh --target=hipl --prefix=/usr
%configure
make -C doc all

# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0
%define python_sitelib %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

%package lib
Summary: hip library files
Group: System Environment/Kernel
%description lib

%package daemon
Requires: hipl-lib
Summary: hip daemon files
Group: System Environment/Kernel
%description daemon

%package agent
Requires: hipl-lib, hipl-daemon
Summary: hip agent files
Group: System Environment/Kernel
%description agent

%package tools
Requires: hipl-lib, hipl-daemon
Summary: hip tools files
Group: System Environment/Kernel
%description tools

%package firewall
Summary: hip firewall files
Group: System Environment/Kernel
%description firewall

%package test
Requires: hipl-lib, hipl-daemon
Summary: hip test files
Group: System Environment/Kernel
%description test

%package doc
Summary: hip doc files
Group: System Environment/Kernel
%description doc

%package dnsproxy
Summary: dns proxy for hip
Group: System Environment/Kernel
%description dnsproxy

%install
rm -rf %{buildroot}

#added by CentOS
install -d %{buildroot}%{prefix}/share/pixmaps
#end CentOS add

# XX FIXME: add more python stuff from tools directory

install -d %{buildroot}%{prefix}/bin
install -d %{buildroot}%{prefix}/sbin
install -d %{buildroot}%{prefix}/lib
install -d %{buildroot}/etc/rc.d/init.d
install -d %{buildroot}/doc
make DESTDIR=%{buildroot} install
install -m 700 test/packaging/rh-init.d-hipfw %{buildroot}/etc/rc.d/init.d/hipfw
install -m 700 test/packaging/rh-init.d-hipd %{buildroot}/etc/rc.d/init.d/hipd
install -m 700 test/packaging/rh-init.d-dnsproxy %{buildroot}/etc/rc.d/init.d/dnshipproxy
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -d %{buildroot}%{python_sitelib}/DNS
install -t %{buildroot}%{python_sitelib}/DNS tools/DNS/*py*
install -d %{buildroot}%{python_sitelib}/dnshipproxy
install -t %{buildroot}%{python_sitelib}/dnshipproxy tools/dnsproxy.py*
install -t %{buildroot}%{python_sitelib}/dnshipproxy tools/pyip6.py*
install -t %{buildroot}%{python_sitelib}/dnshipproxy tools/hosts.py*
install -t %{buildroot}%{python_sitelib}/dnshipproxy tools/util.py*
install -d %{buildroot}%{python_sitelib}/parsehipkey
install -t %{buildroot}%{python_sitelib}/parsehipkey tools/parse-key-3.py*
install -t %{buildroot}%{python_sitelib}/parsehipkey tools/myasn.py*
# required in CentOS release 5.2
install -m 700 tools/parsehipkey %{buildroot}%{prefix}/sbin/parsehipkey
install -m 700 tools/dnshipproxy %{buildroot}%{prefix}/sbin/dnshipproxy

%post lib
/sbin/ldconfig 

%post daemon
/sbin/chkconfig --add hipd
/sbin/chkconfig --level 2 hipd on
/sbin/service hipd start

#%post
#/sbin/chkconfig --add hipfw
#/sbin/chkconfig --level 2 hipfw on
#/sbin/service hipfw start
#`/usr/sbin/hipfw -bk`

%post firewall
/sbin/chkconfig --add hipfw
/sbin/chkconfig --level 2 hipfw on
/sbin/service hipfw start
#/etc/rc.d/init.d/hipfw start
#/usr/sbin/hipfw -bk`

%post dnsproxy
/sbin/chkconfig --add dnshipproxy
/sbin/chkconfig --level 2 dnshipproxy on
/sbin/service dnshipproxy start
/bin/netstat -lanu|/bin/awk '$4 ~ /:53$/ {print $4}'|/bin/grep -q 53 && \
/bin/echo "*** Warning: DNS software detected running on port 53" && \
/bin/echo "*** Warning: HIP DNS proxy overrides system default DNS server" && \
/bin/echo "*** Warning: Check HIPL manual on DNS proxy for further info"

%preun daemon
/sbin/service hipd stop
/sbin/chkconfig --del hipd

%preun firewall
/sbin/service hipfw stop
/sbin/chkconfig --del hipfw
#/etc/rc.d/init.d/hipfw stop

%preun dnsproxy
/sbin/service dnshipproxy stop
/sbin/chkconfig --del dnshipproxy

%clean
rm -rf %{buildroot}

%files lib
%{_libdir}

%files daemon
%{prefix}/sbin/hipd
%{prefix}/bin/hipsetup
%config /etc/rc.d/init.d/hipd

%files agent
%{prefix}/bin/hipagent

%files dnsproxy
%{prefix}/sbin/dnshipproxy
%{prefix}/sbin/parsehipkey
%{python_sitelib}/dnshipproxy
%{python_sitelib}/parsehipkey
%{python_sitelib}/DNS
%defattr(755,root,root)
%config /etc/rc.d/init.d/dnshipproxy

%files tools
%{prefix}/sbin/hipconf
%{prefix}/sbin/nsupdate.pl
%defattr(755,root,root)

%files test
%{prefix}/bin/conntest-client-opp
%{prefix}/bin/conntest-client-hip
%{prefix}/bin/conntest-client-native
%{prefix}/bin/conntest-client-native-user-key
%{prefix}/bin/conntest-server
%{prefix}/bin/conntest-server-native

%files firewall
%{prefix}/sbin/hipfw
%config /etc/rc.d/init.d/hipfw

%files doc
%doc doc/HOWTO.txt doc/howto-html

%changelog
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

